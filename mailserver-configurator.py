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


def detect_existing_containers(client: docker.DockerClient, image: str, only_running: bool = False) -> Optional[List[docker.models.containers.Container]]:
    """Detects if containers with the specified image already exists (optionally, if they are running too)."""
    if only_running:
        containers = client.containers.list(filters={"ancestor": image})
    else:
        containers = client.containers.list(all=True, filters={"ancestor": image})

    if containers:
        names = [container.name for container in containers]
        short_ids = [container.short_id for container in containers]
        tuples = list(zip(names, short_ids))
        logger.debug(f"Found running containers with image '{image}': {tuples}.")
        return containers
    else:
        logger.debug(f"No running container found with image '{image}'.")
        return None
    

def detect_stopped_containers(client: docker.DockerClient, image: str) -> Optional[List[docker.models.containers.Container]]:
    """Detects if containers with the specified image are stopped."""
    containers = client.containers.list(all=True, filters={"ancestor": image, "status": "exited"})

    if containers:
        names = [container.name for container in containers]
        short_ids = [container.short_id for container in containers]
        tuples = list(zip(names, short_ids))
        logger.debug(f"Found stopped containers with image '{image}': {tuples}.")
        return containers
    else:
        logger.debug(f"No stopped container found with image '{image}'.")
        return None
    

def get_container_args(container: docker.models.containers.Container):
    """Extracts relevant arguments from a running container."""
    try:
        name = container.name
        port_bindings = container.attrs["HostConfig"]["PortBindings"]
        ports = {k: int(v[0]['HostPort']) for k, v in port_bindings.items()}
        # hostname = container.attrs['Config']['Hostname']
        # domainname = container.attrs['Config']['Domainname']
        # ports = container.attrs['NetworkSettings']['Ports']
        # environment = container.attrs['Config']['Env']
        # env_dict = {}
        # for env in environment:
        #     key, _, value = env.partition("=")
        #     env_dict[key] = value
        # logger.info(f"Extracted args from container '{name}': hostname={hostname}, domainname={domainname}, ports={ports}, environment={env_dict}.")
        return name, ports
    except Exception as e:
        logger.error(f"Error extracting args from container '{container.name}': {e}")
        return None, None


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
    init_parser.add_argument("--users", type=parse_list_arg, default=[], help="List of user emails to create like 'user1@domain:pass1,user2@domain:pass2'. Each entry should be in the format '<email>:<password>'. <email> must include the domain. If a user already exists, it will be skipped.")
    init_parser.add_argument("--env", type=parse_json_arg, default={}, help="[MS] Additional arguments to pass to the Docker container as environment variables. This should be a dictionary of key-value pairs in the format: '{\"KEY1\": \"string_value\", \"KEY2\": numeric_or_boolean_value}'.")
    init_parser.add_argument("--image", type=str, default="docker.io/mailserver/docker-mailserver:latest", help="[DC] Docker image to use for the mail server. If any container with this image is already running, it will be stopped and removed before starting a new one.")
    init_parser.add_argument("--get-container-args", action="store_true", help="If set, it gets the argument such as the container name and ports from any running container with the specified image and uses them to start the new container. If no such container is found, it uses default values.", default=True)
    init_parser.add_argument("--no-get-container-args", action="store_false", dest="get_container_args", help="Disables the --get-container-args option.")
    init_parser.add_argument("--ssl-path", type=str, help="[MS] Path to the SSL directory containing the SSL certificate and key files to use for the mail server. If not provided, no SSL will be used.", default=None)
    init_parser.add_argument("--add-common-features", "-F", action="store_true", help="[MS] If set, it adds some common features like setting the postmaster address automatically, enabling IMAP, and disabling POP3, ClamAV, Amavis, Fail2Ban and spoof protection, and setting unlimited size messages. If any of these features are already set in --env, they will not be overridden.", default=False)
    # init_parser.add_argument("--ssl-key", type=str, help="[MS] Path to the SSL key file to use for the mail server. If not provided, no SSL will be used.")
    init_parser.add_argument("--api", action="store_true", help="If set, it starts the FastAPI server to manage the mail server via API calls.", default=False)
    init_parser.add_argument("--api-host", type=str, default="0.0.0.0", help="Host for the FastAPI server. Only used if --api is set (default: 0.0.0.0).")
    init_parser.add_argument("--api-port", type=int, default=9999, help="Port for the FastAPI server. Only used if --api is set (default: 9999).")
    init_parser.add_argument("--debug", action="store_true", help="Enable debug logging.", default=False)

    start_parser = subparsers.add_parser("start", help="Starts any mail server.")
    start_parser.add_argument("--image", type=str, default="docker.io/mailserver/docker-mailserver:latest", help="[DC] Docker image used for the mail server. All containers with this image will be stopped and removed.")
    start_parser.add_argument("--api", action="store_true", help="If set, it starts the FastAPI server to manage the mail server via API calls.", default=False)
    start_parser.add_argument("--api-host", type=str, default="0.0.0.0", help="Host for the FastAPI server. Only used if --api is set (default: 0.0.0.0).")
    start_parser.add_argument("--api-port", type=int, default=9999, help="Port for the FastAPI server. Only used if --api is set (default: 9999).")
    start_parser.add_argument("--debug", action="store_true", help="Enable debug logging.", default=False)

    stop_parser = subparsers.add_parser("stop", help="Stops any running mail server.")
    stop_parser.add_argument("--image", type=str, default="docker.io/mailserver/docker-mailserver:latest", help="[DC] Docker image used for the mail server. All containers with this image will be stopped and removed.")
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
    
    processed_users = [split_email_pass(user) for user in args.users]
    if None in processed_users:
        logger.error("One or more invalid user arguments. Exiting.")
        exit(1)

    logger.debug(f"Input arguments: {args}")

    if "POSTMASTER_ADDRESS" in args.env:
        logger.warning("POSTMASTER_ADDRESS found in args. It will be overridden by the --postmaster argument.")
        del args.env["POSTMASTER_ADDRESS"]

    if args.ssl_path and "SSL_CERT_PATH" in args.env and "SSL_KEY_PATH" in args.env and args.env.get("SSL_TYPE").lower() == "manual":
        # Command to generate self-signed certificate for testing purposes
        # openssl req -x509 -nodes -newkey rsa:2048 \
        #   -days 365 \
        #   -keyout ./certs/mail.key \
        #   -out ./certs/mail.crt \
        #   -subj "/CN=mail.cobra.org"

        # Check the paths share the same directory
        cert_path = os.path.dirname(args.env["SSL_CERT_PATH"])
        key_path = os.path.dirname(args.env["SSL_KEY_PATH"])
        if cert_path != key_path:
            logger.error("SSL_CERT_PATH and SSL_KEY_PATH must be in the same directory inside the container. Exiting.")
            exit(1)
        # Check the path ssl_path exists in the host
        if not os.path.isdir(os.path.abspath(args.ssl_path)):
            logger.error(f"SSL path '{args.ssl_path}' does not exist in the host. Exiting.")
            exit(1)
        logger.info("SSL_CERT_PATH and SSL_KEY_PATH found in args with SSL_TYPE set to 'manual'. SSL will be enabled with the provided paths.")
    
    if args.ssl_path and args.env.get("SSL_TYPE").lower() == "self-signed":
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

    if args.image == "docker.io/mailserver/docker-mailserver:latest" and args.add_common_features:
        current_env = args.env.copy()
        args.env = {
            "ENABLE_IMAP": "1",
            "ENABLE_POP3": "0",
            "ENABLE_CLAMAV": "0",
            "ENABLE_AMAVIS": "0",
            "ENABLE_SPAMASSASSIN": "0",
            "ENABLE_POSTGREY": "0",
            "ENABLE_FAIL2BAN": "0",
            "SPOOF_PROTECTION": "0",
            "POSTMASTER_ADDRESS": processed_postmaster[0],
            "POSTFIX_MESSAGE_SIZE_LIMIT": 0
        }
        args.env.update(current_env)  # Do not override any existing setting
        logger.info("Added some common features to args: enabling IMAP, disabling POP3, ClamAV, Amavis, SpamAssassin, Postgrey and Fail2Ban, disabling spoof protection, setting unlimited size messages and setting the postmaster address automatically.")
    elif "POSTMASTER_ADDRESS" not in args.env:
        args.env["POSTMASTER_ADDRESS"] = processed_postmaster[0]
        logger.debug(f"Setting POSTMASTER_ADDRESS in args to {processed_postmaster[0]}.")

    # Check for existing containers, get name and ports, and remove them
    containers = detect_existing_containers(client, args.image)
    name, port_bindings = None, None
    if containers:
        if args.get_container_args:
            name, port_bindings = get_container_args(containers[0])
            logger.info(f"Using args from existing container '{name}': name={name}, port_bindings={port_bindings}.")

        logger.info("Removing existing containers...")
        for container in containers:
            logger.debug(f"Stopping and removing existing container '{container.name}' (id: {container.short_id})...")
            container.remove(v=True, force=True)
            logger.debug(f"Container '{container.name}' stopped and removed.")
    else:
        logger.debug("No existing containers to remove.")
    
    if not name:
        name = "mailserver-python"
        logger.warning(f"No existing container found or --get-container-args disabled. Using default name: {name}.")
    
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
        logger.warning(f"No existing container found or --get-container-args disabled. Using default port bindings: {port_bindings}.")

    logger.debug(f"Processed environment variables for container: {args.env}.")
    container = setup_mailserver(
        client=client,
        image=args.image,
        name=name,
        ports=port_bindings,
        hostname=args.hostname,
        domainname=args.domainname,
        postmaster=processed_postmaster,
        users=processed_users,
        environment=args.env,
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
        setup_api_server(host=args.api_host, port=args.api_port, debug=args.debug)


if __name__ == "__main__":
    main()
