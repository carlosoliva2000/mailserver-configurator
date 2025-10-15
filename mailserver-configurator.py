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


def detect_running_containers(client: docker.DockerClient, image: str) -> Optional[List[docker.models.containers.Container]]:
    """Detects if containers with the specified image are already running."""
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
        environment: Dict[str, Any]
    ) -> docker.models.containers.Container:
    """Sets up and runs the mailserver Docker container."""
    logger.info("Starting Docker Mailserver container...")

    # Create necessary directories
    abs_dirs = [
        os.path.abspath("./data/mail"), 
        os.path.abspath("./data/state"), 
        os.path.abspath("./config")
    ]
    for dir_name in abs_dirs:
        logger.debug(f"Volume directory: {dir_name}")
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
            volumes={
                abs_dirs[0]: {"bind": "/var/mail"},  #, "mode": "rw"},
                abs_dirs[1]: {"bind": "/var/mail-state"},  # , "mode": "rw"},
                abs_dirs[2]: {"bind": "/tmp/docker-mailserver"}  # , "mode": "rw"},
            },
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

        # Create postmaster account
        logger.info("Creating postmaster account...")
        postmaster_email, postmaster_pass = postmaster
        exit_code, output = container.exec_run(
            ["setup", "email", "add", postmaster_email, postmaster_pass]
        )

        if exit_code == 0:
            logger.info(f"Postmaster account {postmaster_email} created successfully.")
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
        time.sleep(3)  # Wait a bit for the user to be created
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
    parser.add_argument("--postmaster", type=str, required=True, help="Postmaster email and password in the format '<email>:<password>'. <email> must include the domain.")
    parser.add_argument("--hostname", type=str, default="mail", help="[DC] Hostname for the mail server.")
    parser.add_argument("--domain", type=str, default="example.local", help="[DC] Domain name for the mail server.")
    parser.add_argument("--users", type=parse_list_arg, default=[], help="List of user emails to create like 'user1@domain:pass1,user2@domain:pass2'. Each entry should be in the format '<email>:<password>'. <email> must include the domain. If a user already exists, it will be skipped.")
    parser.add_argument("--args", type=parse_json_arg, default={}, help="[MS] Additional arguments to pass to the Docker container as environment variables. This should be a dictionary of key-value pairs in the format: '{\"KEY1\": \"string_value\", \"KEY2\": numeric_or_boolean_value}'.")
    parser.add_argument("--image", type=str, default="docker.io/mailserver/docker-mailserver:latest", help="[DC] Docker image to use for the mail server. If any container with this image is already running, it will be stopped and removed before starting a new one.")
    parser.add_argument("--get-container-args", action="store_true", help="If set, it gets the argument such as the container name and ports from any running container with the specified image and uses them to start the new container. If no such container is found, it uses default values.", default=True)
    parser.add_argument("--no-get-container-args", action="store_false", dest="get_container_args", help="Disables the --get-container-args option.")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging.", default=False)

    args, unknown = parser.parse_known_args()

    if args.debug:
        console_handler.setFormatter(formatter)
    else:
        console_handler.setFormatter(LevelBasedFormatter())
        console_handler.setLevel(logging.INFO)

    logger.info("Starting mailserver-configurator.")
    if unknown:
        logger.warning(f"Unknown arguments ignored: {unknown}.")

    processed_postmaster = split_email_pass(args.postmaster)
    if not processed_postmaster:
        logger.error("Invalid postmaster argument. Exiting.")
        exit(1)
    
    processed_users = [split_email_pass(user) for user in args.users]
    if None in processed_users:
        logger.error("One or more invalid user arguments. Exiting.")
        exit(1)

    logger.debug(f"Input arguments: {args}")

    if "POSTMASTER_ADDRESS" in args.args:
        logger.warning("POSTMASTER_ADDRESS found in args. It will be overridden by the --postmaster argument.")
        del args.args["POSTMASTER_ADDRESS"]

    if args.image == "docker.io/mailserver/docker-mailserver:latest" and not args.args:
        args.args = {
            "ENABLE_CLAMAV": "0",
            "ENABLE_SPAMASSASSIN": "0",
            "ENABLE_POSTGREY": "0",
            "ENABLE_FAIL2BAN": "0",
            "DMS_DEBUG": "0",
            "POSTMASTER_ADDRESS": processed_postmaster[0],
        }
        logger.warning(f"Using default image and no additional args. Enabling some common features: {args.args}.")
    elif "POSTMASTER_ADDRESS" not in args.args:
        args.args["POSTMASTER_ADDRESS"] = processed_postmaster[0]
        logger.debug(f"Setting POSTMASTER_ADDRESS in args to {processed_postmaster[0]}.")
    
    client = docker.from_env()

    # Check for existing containers, get name and ports, and remove them
    containers = detect_running_containers(client, args.image)
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
            "25/tcp": 25,
            "110/tcp": 110,
            "143/tcp": 143,
            "587/tcp": 587,
            "993/tcp": 993
        }
        logger.warning(f"No existing container found or --get-container-args disabled. Using default port bindings: {port_bindings}.")

    logger.debug(f"Processed environment variables for container: {args.args}.")
    container = setup_mailserver(
        client=client,
        image=args.image,
        name=name,
        ports=port_bindings,
        hostname=args.hostname,
        domainname=args.domain,
        postmaster=processed_postmaster,
        users=processed_users,
        environment=args.args
    )

    # # Wait 30 seconds before stopping
    # logger.info("Mailserver will run for 30 seconds before stopping...")
    # time.sleep(30)
    # logger.info("Stopping mailserver container...")
    # container.remove(v=True, force=True)
    # logger.info("Mailserver container stopped and removed.")

    logger.info("Finishing mailserver-configurator.")


if __name__ == "__main__":
    main()
