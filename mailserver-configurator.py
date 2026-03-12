import os
import argparse
import logging
import docker
import time
import json

from sys import exit
from typing import Any, Dict, List, Optional, Tuple
from logging.handlers import RotatingFileHandler


# Logging setup

LOG_PATH = os.path.join(os.path.expanduser('~'), ".config", "mailserver-configurator")
os.makedirs(LOG_PATH, exist_ok=True)

format_str = "%(asctime)s [PID %(process)d] - %(funcName)s - %(levelname)s - %(message)s"
class LevelBasedFormatter(logging.Formatter):
    """Custom formatter to change format based on log level."""
    def format(self, record):
        if record.levelno == logging.INFO:
            fmt = "%(message)s"
        else:
            fmt = "%(levelname)s - %(message)s"
        formatter = logging.Formatter(fmt)
        return formatter.format(record)


formatter = logging.Formatter(format_str)
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

console_handler = logging.StreamHandler()
logger.addHandler(console_handler)

file_handler = RotatingFileHandler(
    os.path.join(os.path.expanduser(LOG_PATH), 'mailserver-configurator.log'),
    maxBytes=1024*1024, 
    backupCount=3
)
file_handler.setFormatter(formatter)
logger.addHandler(file_handler)


# Setup mailserver

def split_email_pass(email_pass: str) -> Optional[Tuple[str, str]]:
    """Splits an email:password string into its components."""
    try:
        email, password = email_pass.split(":", 1)
        if "@" not in email:
            raise ValueError("Email must contain a domain part.")
        return email, password
    except ValueError as e:
        logger.error(f"Error parsing email:password '{email_pass}': {e}")


def normalize_image_name(image: str) -> str:
    """
    Normalize a Docker image name by:
    - Removing tag (after last :)
    - Removing digest (after @)
    - Removing registry (docker.io, localhost:5000, IP:port, etc.)
    """
    # Remove digest if present
    image = image.split("@", 1)[0]

    # Remove tag (only the LAST colon)
    if ":" in image:
        image = image.rsplit(":", 1)[0]

    parts = image.split("/")

    # Detect registry
    if (
        len(parts) > 1
        and (
            "." in parts[0]
            or ":" in parts[0]
            or parts[0] == "localhost"
        )
    ):
        parts = parts[1:]

    return "/".join(parts)


def detect_existing_containers(
    client: docker.DockerClient,
    image: str,
    only_running: bool = False
) -> Optional[List[docker.models.containers.Container]]:
    """
    Detect containers whose image matches the given image name
    (ignoring registry and tag).
    Optionally, if the are only running containers.
    """
    target = normalize_image_name(image)

    containers = client.containers.list(all=not only_running)

    matched = []

    for container in containers:
        for tag in container.image.tags or []:
            normalized = normalize_image_name(tag)
            if normalized == target:
                matched.append(container)
                break

    if matched:
        names = [(c.name, c.short_id) for c in matched]
        logger.debug(
            f"Found containers matching image '{image}' "
            f"(normalized='{target}'): {names}"
        )
        return matched

    logger.debug(
        f"No container found matching image '{image}' "
        f"(normalized='{target}')."
    )
    return None


def detect_stopped_containers(
    client: docker.DockerClient,
    image: str
) -> Optional[List[docker.models.containers.Container]]:
    """Detect containers with the given image that are stopped (exited)."""

    target = normalize_image_name(image)

    containers = client.containers.list(all=True)

    matched = []

    for container in containers:
        if container.status != "exited":
            continue

        for tag in container.image.tags or []:
            normalized = normalize_image_name(tag)
            if normalized == target:
                matched.append(container)
                break

    if matched:
        names = [(c.name, c.short_id) for c in matched]
        logger.debug(
            f"Found stopped containers matching image '{image}' "
            f"(normalized='{target}'): {names}"
        )
        return matched

    logger.debug(
        f"No stopped container found matching image '{image}' "
        f"(normalized='{target}')."
    )
    return None


def get_container_args(container: docker.models.containers.Container) -> Tuple[Optional[str], Optional[Dict[str, int]], Optional[str]]:
    """Extracts relevant arguments from a running container."""
    try:
        name = container.name
        port_bindings = container.attrs["HostConfig"]["PortBindings"]
        ports = {k: int(v[0]['HostPort']) for k, v in port_bindings.items()}
        image = (
            container.image.tags[0]
            if container.image.tags
            else container.image.id
        )

        # hostname = container.attrs['Config']['Hostname']
        # domainname = container.attrs['Config']['Domainname']
        # ports = container.attrs['NetworkSettings']['Ports']
        # environment = container.attrs['Config']['Env']
        # env_dict = {}
        # for env in environment:
        #     key, _, value = env.partition("=")
        #     env_dict[key] = value
        # logger.info(f"Extracted args from container '{name}': hostname={hostname}, domainname={domainname}, ports={ports}, environment={env_dict}.")
        return name, ports, image
    except Exception as e:
        logger.error(f"Error extracting args from container '{container.name}': {e}")
        return None, None, None
    

def resolve_local_image(
    client: docker.DockerClient,
    image: str
) -> Optional[str]:
    """
    Find a local Docker image matching the normalized name.
    Returns the full image tag if found.
    """

    target = normalize_image_name(image)

    for img in client.images.list():
        for tag in img.tags or []:
            if normalize_image_name(tag) == target:
                logger.debug(
                    f"Resolved local image '{tag}' for requested image '{image}'"
                )
                return tag

    logger.debug(
        f"No local image found matching '{image}' (normalized='{target}')."
    )
    return None



def setup_mailserver(
        client: docker.DockerClient,
        image: str,
        name: str,
        ports: Dict[str, int],
        hostname: str,
        domainname: str,
        postmaster: Tuple[str, str],
        users: List[Tuple[str, str]],
        environment: Dict[str, Any],
        ssl_path: Optional[str] = None
    ) -> docker.models.containers.Container:
    """Sets up and runs the mailserver Docker container."""
    logger.info("Starting Docker Mailserver container...")

    # Create necessary directories
    abs_dirs = [
        os.path.abspath("./data/mail"), 
        os.path.abspath("./data/state"), 
        os.path.abspath("./config")
    ]
    volumes = {
        abs_dirs[0]: {"bind": "/var/mail"},  #, "mode": "rw"},
        abs_dirs[1]: {"bind": "/var/mail-state"},  # , "mode": "rw"},
        abs_dirs[2]: {"bind": "/tmp/docker-mailserver"},  # , "mode": "rw"},
        "/etc/localtime": {"bind": "/etc/localtime", "mode": "ro"},  # Sync time with host
    }

    if ssl_path:
        if environment.get("SSL_TYPE", None) == 'manual':
            cert_path = environment.get("SSL_CERT_PATH", "")
            dir_cert_path = os.path.dirname(cert_path) if cert_path else None
            if dir_cert_path:
                volumes[os.path.abspath(ssl_path)] = {"bind": dir_cert_path}  # , "mode": "ro"}
        elif environment.get("SSL_TYPE", None) == 'self-signed':
            volumes[os.path.abspath(ssl_path)] = {"bind": "/tmp/docker-mailserver/ssl/"}  # , "mode": "ro"}
        else:
            logger.warning("SSL_PATH provided but SSL_TYPE is not set to 'manual' or 'self-signed'. SSL will not be used.")

    for host_dir, bind in volumes.items():
        logger.debug(f"Volume directory: {host_dir} -> {bind}.")
        # os.makedirs(dir_name, exist_ok=True)

    try:
        # Run container
        container = client.containers.run(
            image,
            name=name,
            hostname=hostname,
            domainname=domainname,
            detach=True,
            ports=ports,
            cap_add=["NET_ADMIN", "SYS_PTRACE"],
            environment=environment,
            volumes=volumes,
            restart_policy={"Name": "unless-stopped"},
        )

        logger.info(f"Container '{container.name}' started (id: {container.short_id}).")

        # Wait until it's running
        for _ in range(20):
            container.reload()
            if container.status == "running":
                logger.info("Mailserver is now running.")
                break
            time.sleep(1)
        else:
            raise RuntimeError("Mailserver container failed to start within the expected time.")
        time.sleep(5)  # Wait a bit more for the mailserver to be fully ready

        # Create postmaster account
        logger.info("Creating postmaster account...")
        postmaster_email, postmaster_pass = postmaster
        exit_code, output = container.exec_run(
            ["setup", "email", "add", postmaster_email, postmaster_pass]
        )

        if exit_code == 0:
            logger.info(f"Postmaster account {postmaster_email} created successfully.")
        else:
            if "already exists" in output.decode('utf-8'):
                logger.warning(f"Postmaster {postmaster_email} already exists. Skipping creation.")
            else:
                raise RuntimeError(f"Failed to create postmaster account {postmaster_email}: {output.decode('utf-8')}")

        # Create additional users
        logger.info("Creating additional user accounts...")
        for user_email, user_pass in users:
            logger.debug(f"Creating user account {user_email}...")
            exit_code, output = container.exec_run(
                ["setup", "email", "add", user_email, user_pass]
            )

            if exit_code == 0:
                logger.debug(f"User account {user_email} created successfully.")
            else:
                if "already exists" in output.decode('utf-8'):
                    logger.warning(f"User {user_email} already exists. Skipping creation.")
                else:
                    logger.error(f"Failed to create user {user_email}: {output.decode('utf-8')}")

        # Check user list
        time.sleep(10)  # Wait a bit for the user to be created
        exit_code, output = container.exec_run(["setup", "email", "list"])
        if exit_code == 0:
            logger.debug(f"Current email users:\n{output.decode('utf-8')}")
        else:
            logger.error(f"Failed to list users: {output.decode('utf-8')}")

        # Check user list with doveadm
        exit_code, output = container.exec_run(["doveadm", "user", "*", "list"])
        if exit_code == 0:
            logger.debug(f"Dovecot users:\n{output.decode('utf-8')}")
        else:
            logger.error(f"Failed to list dovecot users: {output.decode('utf-8')}")

        logger.info("Mailserver setup complete.")
        return container
    except docker.errors.DockerException as e:
        logger.error(f"Docker error: {e}")
        exit(1)
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        exit(1)


def setup_api_server(host: str, port: int, debug: bool = False):
    """Sets up and runs the FastAPI server."""
    import uvicorn
    from api_server import app
    logger.info(f"Setting up FastAPI server on {host}:{port}...")
    uvicorn.run("api_server:app", host=host, port=port)


# Start/stop mailserver

def stop_mailserver(client: docker.DockerClient, image: str):
    """Stops and removes all running containers with the specified image."""
    containers = detect_existing_containers(client, image, only_running=True)
    if containers:
        logger.info("Stopping existing containers...")
        for container in containers:
            logger.debug(f"Stopping existing container '{container.name}' (id: {container.short_id})...")
            container.stop()
            logger.debug(f"Container '{container.name}' stopped and removed.")
        logger.info("All existing containers stopped.")
    else:
        logger.info(f"No running containers found with image '{image}'. Nothing to stop.")


def start_mailserver(client: docker.DockerClient, image: str):
    """Starts a mailserver container with default settings."""
    logger.info("Starting mailserver with default settings...")
    containers = detect_stopped_containers(client, image)
    if containers:
        for container in containers:
            logger.debug(f"Starting stopped container '{container.name}' (id: {container.short_id})...")
            container.start()
            logger.debug(f"Container '{container.name}' started.")
        logger.info("All stopped containers started.")
    else:
        logger.info(f"No stopped containers found with image '{image}'. Nothing to start.")


# Parser auxiliary functions

def parse_json_arg(value):
    """Transforms a JSON string into a dictionary."""
    try:
        return json.loads(value)
    except json.JSONDecodeError as e:
        raise argparse.ArgumentTypeError(f"Invalid JSON format: {e}")

def parse_list_arg(value):
    """Transforms a comma-separated string into a list."""
    try:
        return [item.strip() for item in value.split(",") if item.strip()]
    except Exception as e:
        raise argparse.ArgumentTypeError(f"Invalid list format: {e}")


# Main

def main():
    parser = argparse.ArgumentParser(
        prog="mailserver-configurator",
        description="A tool to configure, start or stop a mail server. Primarily for Docker Mailserver. If an argument starts with [DC], it is related to Docker container configuration. If it starts with [MS], it is related to mail server configuration.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Subcommands
    init_parser = subparsers.add_parser("init", help="Initializes and starts the mail server with the specified configuration. If a container with the specified image is already running, it will be stopped and removed before starting a new one.")
    init_parser.add_argument("--postmaster", type=str, required=True, help="Postmaster email and password in the format '<email>:<password>'. <email> must include the domain.")
    init_parser.add_argument("--hostname", type=str, default="mail", help="[DC] Hostname for the mail server.")
    init_parser.add_argument("--domainname", type=str, default="example.local", help="[DC] Domain name for the mail server.")
    init_parser.add_argument("--user", action="append", help="A user in the format '<email>:<password>'. <email> must include the domain. If a user already exists, it will be skipped. You can specify this argument as many times as needed.")
    init_parser.add_argument("--envs", type=parse_json_arg, default={}, help="[MS] Additional arguments to pass to the Docker container as environment variables. This should be a dictionary of key-value pairs in the format: '{\"KEY1\": \"string_value\", \"KEY2\": numeric_or_boolean_value}'. Not compatible with --env.")
    init_parser.add_argument("--env", action="append", type=str, help="[MS] Additional arguments to pass to the Docker container as environment variables. This should be in the format 'KEY=VALUE'. You can specify this argument as many times as needed. Not compatible with --envs.")
    init_parser.add_argument("--image", type=str, default="mailserver/docker-mailserver", help="[DC] Docker image to use for the mail server. If any container with this image is already running, it will be stopped and removed before starting a new one. It ignores the registry and tag.")
    init_parser.add_argument("--get-container-args", action="store_true", help="If set, it gets the argument such as the container name and ports from any running container with the specified image and uses them to start the new container. If no such container is found, it uses default values.", default=True)
    init_parser.add_argument("--no-get-container-args", action="store_false", dest="get_container_args", help="Disables the --get-container-args option.")
    init_parser.add_argument("--ssl-path", type=str, help="[MS] Path to the SSL directory containing the SSL certificate and key files to use for the mail server. If not provided, no SSL will be used.", default=None)
    init_parser.add_argument("--add-common-features", "-F", action="store_true", help="[MS] If set, it adds some common features like setting the postmaster address automatically, enabling IMAP, and disabling POP3, ClamAV, Amavis, Fail2Ban and spoof protection, setting unlimited size messages and disabling update checks. If any of these features are already set in --env, they will not be overridden.", default=False)
    # init_parser.add_argument("--ssl-key", type=str, help="[MS] Path to the SSL key file to use for the mail server. If not provided, no SSL will be used.")
    init_parser.add_argument("--api", action="store_true", help="If set, it starts the FastAPI server to manage the mail server via API calls.", default=False)
    init_parser.add_argument("--api-host", type=str, default="0.0.0.0", help="Host for the FastAPI server. Only used if --api is set (default: 0.0.0.0).")
    init_parser.add_argument("--api-port", type=int, default=24421, help="Port for the FastAPI server. Only used if --api is set (default: 24421).")
    init_parser.add_argument("--debug", action="store_true", help="Enable debug logging.", default=False)

    start_parser = subparsers.add_parser("start", help="Starts any mail server.")
    start_parser.add_argument("--image", type=str, default="mailserver/docker-mailserver", help="[DC] Docker image used for the mail server. All containers with this image will be stopped and removed. It ignores the registry and tag.")
    start_parser.add_argument("--api", action="store_true", help="If set, it starts the FastAPI server to manage the mail server via API calls.", default=False)
    start_parser.add_argument("--api-host", type=str, default="0.0.0.0", help="Host for the FastAPI server. Only used if --api is set (default: 0.0.0.0).")
    start_parser.add_argument("--api-port", type=int, default=24421, help="Port for the FastAPI server. Only used if --api is set (default: 24421).")
    start_parser.add_argument("--debug", action="store_true", help="Enable debug logging.", default=False)

    stop_parser = subparsers.add_parser("stop", help="Stops any running mail server.")
    stop_parser.add_argument("--image", type=str, default="mailserver/docker-mailserver", help="[DC] Docker image used for the mail server. All containers with this image will be stopped and removed. It ignores the registry and tag.")
    stop_parser.add_argument("--debug", action="store_true", help="Enable debug logging.", default=False)


    args, unknown = parser.parse_known_args()

    if args.debug:
        console_handler.setFormatter(formatter)
    else:
        console_handler.setFormatter(LevelBasedFormatter())
        console_handler.setLevel(logging.INFO)

    logger.info("Starting mailserver-configurator.")
    if unknown:
        logger.warning(f"Unknown arguments ignored: {unknown}.")

    # Check if both --env and --envs are used
    if args.env and args.envs:
        logger.error("Both --env and --envs cannot be used at the same time. Please use only one of them. Exiting.")
        exit(1)
    
    if args.env:
        # Convert list of KEY=VALUE strings to dictionary
        envs = {}
        for env_var in args.env:
            if "=" not in env_var:
                logger.error(f"Invalid environment variable format: '{env_var}'. It must be in the format 'KEY=VALUE'. Exiting.")
                exit(1)
            key, value = env_var.split("=", 1)
            envs[key] = value
    else:
        envs = args.envs

    client = docker.from_env()

    if args.command == "stop":
        stop_mailserver(client, args.image)
        logger.info("Finishing mailserver-configurator.")
        exit(0)
    elif args.command == "start":
        start_mailserver(client, args.image)
        logger.info("Finishing mailserver-configurator.")
        if args.api:
            setup_api_server(host=args.api_host, port=args.api_port, debug=args.debug)
        exit(0)

    processed_postmaster = split_email_pass(args.postmaster)
    if not processed_postmaster:
        logger.error("Invalid postmaster argument. Exiting.")
        exit(1)
    
    processed_users = [split_email_pass(user) for user in args.user]
    if None in processed_users:
        logger.error("One or more invalid user arguments. Exiting.")
        exit(1)

    logger.debug(f"Input arguments: {args}")

    if "POSTMASTER_ADDRESS" in envs:
        logger.warning("POSTMASTER_ADDRESS found in args. It will be overridden by the --postmaster argument.")
        del envs["POSTMASTER_ADDRESS"]

    if args.ssl_path:
        args.ssl_path = os.path.abspath(os.path.expanduser(args.ssl_path))

    if args.ssl_path and "SSL_CERT_PATH" in envs and "SSL_KEY_PATH" in envs and envs.get("SSL_TYPE", "").lower() == "manual":
        # Command to generate self-signed certificate for testing purposes
        # openssl req -x509 -nodes -newkey rsa:2048 \
        #   -days 365 \
        #   -keyout ./certs/mail.key \
        #   -out ./certs/mail.crt \
        #   -subj "/CN=mail.cobra.org"

        # Check the paths share the same directory
        cert_path = os.path.dirname(envs["SSL_CERT_PATH"])
        key_path = os.path.dirname(envs["SSL_KEY_PATH"])
        if cert_path != key_path:
            logger.error("SSL_CERT_PATH and SSL_KEY_PATH must be in the same directory inside the container. Exiting.")
            exit(1)
        # Check the path ssl_path exists in the host
        if not os.path.isdir(os.path.abspath(args.ssl_path)):
            logger.error(f"SSL path '{args.ssl_path}' does not exist in the host. Exiting.")
            exit(1)
        logger.info("SSL_CERT_PATH and SSL_KEY_PATH found in args with SSL_TYPE set to 'manual'. SSL will be enabled with the provided paths.")
    
    if args.ssl_path and envs.get("SSL_TYPE", "").lower() == "self-signed":
        # Follow the instructions at https://docker-mailserver.github.io/docker-mailserver/latest/config/security/ssl/#self-signed-certificates
        
        # Check the path ssl_path exists in the host
        if not os.path.isdir(os.path.abspath(args.ssl_path)):
            logger.error(f"SSL path '{args.ssl_path}' does not exist in the host. Exiting.")
            exit(1)
        else:
            # Check the directory contains <FQDN>-key.pem, <FQDN>-cert.pem and demoCA/cacert.pem
            fqdn = f"{args.hostname}.{args.domainname}"
            key_file = os.path.join(os.path.abspath(args.ssl_path), f"{fqdn}-key.pem")
            cert_file = os.path.join(os.path.abspath(args.ssl_path), f"{fqdn}-cert.pem")
            cacert_file = os.path.join(os.path.abspath(args.ssl_path), "demoCA", "cacert.pem")
            if not (os.path.isfile(key_file) and os.path.isfile(cert_file) and os.path.isfile(cacert_file)):
                logger.error(f"SSL path '{args.ssl_path}' does not contain the required files: '{key_file}', '{cert_file}' and '{cacert_file}'. Exiting.")
                exit(1)
            logger.info("SSL_TYPE set to 'self-signed' and SSL paths found in the provided directory. SSL will be enabled with the provided paths.")

    if "mailserver/docker-mailserver" in args.image and args.add_common_features:
        current_env = envs.copy()
        envs = {
            "ENABLE_IMAP": "1",
            "ENABLE_POP3": "0",
            "ENABLE_CLAMAV": "0",
            "ENABLE_AMAVIS": "0",
            "ENABLE_SPAMASSASSIN": "0",
            "ENABLE_POSTGREY": "0",
            "ENABLE_FAIL2BAN": "0",
            "SPOOF_PROTECTION": "0",
            "POSTMASTER_ADDRESS": processed_postmaster[0],
            "POSTFIX_MESSAGE_SIZE_LIMIT": 0,
            "ENABLE_UPDATE_CHECK": "0",
        }
        envs.update(current_env)  # Do not override any existing setting
        logger.info("Added some common features to args: enabling IMAP, disabling POP3, ClamAV, Amavis, SpamAssassin, Postgrey and Fail2Ban, disabling spoof protection, setting unlimited size messages and setting the postmaster address automatically.")
    elif "POSTMASTER_ADDRESS" not in envs:
        envs["POSTMASTER_ADDRESS"] = processed_postmaster[0]
        logger.debug(f"Setting POSTMASTER_ADDRESS in args to {processed_postmaster[0]}.")

    # Check for existing containers, get name and ports, and remove them
    containers = detect_existing_containers(client, args.image)
    name, port_bindings, resolved_image = None, None, None
    if containers:
        if args.get_container_args:
            name, port_bindings, resolved_image = get_container_args(containers[0])
            logger.info(f"Using args from existing container '{name}': name={name}, port_bindings={port_bindings}, image={resolved_image}.")

        logger.info("Removing existing containers...")
        for container in containers:
            logger.debug(f"Stopping and removing existing container '{container.name}' (id: {container.short_id})...")
            container.remove(v=True, force=True)
            logger.debug(f"Container '{container.name}' stopped and removed.")
    else:
        logger.debug("No existing containers to remove.")
    
    if not name:
        name = "mailserver-python"
        logger.warning(f"No container name found or --get-container-args disabled. Using default name: {name}.")
    
    if not port_bindings:
        port_bindings = {
            "25/tcp": 25,  # SMTP  (explicit TLS => STARTTLS)
            "110/tcp": 110,  # POP3
            "143/tcp": 143,  # IMAP4 (explicit TLS => STARTTLS)
            "465/tcp": 465,  # ESMTP (implicit TLS)
            "587/tcp": 587,  # ESMTP (explicit TLS => STARTTLS)
            "993/tcp": 993,  # IMAP4 (implicit TLS)
            "995/tcp": 995,  # POP3 (with TLS)
        }
        logger.warning(f"No port bindings found or --get-container-args disabled. Using default port bindings: {port_bindings}.")

    final_image = None
    if resolved_image:
        final_image = resolved_image
    else:
        local_image = resolve_local_image(client, args.image)
        final_image = local_image if local_image else args.image
    
    logger.debug(f"Requested Docker image for mailserver: {args.image}.")
    logger.debug(f"Resolved Docker image for mailserver: {final_image}.")

    logger.debug(f"Processed environment variables for container: {envs}.")
    container = setup_mailserver(
        client=client,
        image=final_image,
        name=name,
        ports=port_bindings,
        hostname=args.hostname,
        domainname=args.domainname,
        postmaster=processed_postmaster,
        users=processed_users,
        environment=envs,
        ssl_path=args.ssl_path
    )

    # # Wait 30 seconds before stopping
    # logger.info("Mailserver will run for 30 seconds before stopping...")
    # time.sleep(30)
    # logger.info("Stopping mailserver container...")
    # container.remove(v=True, force=True)
    # logger.info("Mailserver container stopped and removed.")

    logger.info("Finishing mailserver-configurator.")
    
    if args.api:
        os.environ["MAILSERVER_CONTAINER"] = container.name
        setup_api_server(host=args.api_host, port=args.api_port, debug=args.debug)


if __name__ == "__main__":
    main()
