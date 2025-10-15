import os
import argparse
import logging
import docker
import time

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

def setup_mailserver(client: docker.DockerClient):
    logger.info("Starting Docker Mailserver container...")

    # Create necessary directories
    abs_dirs = [
        os.path.abspath("./data/mail"), 
        os.path.abspath("./data/state"), 
        os.path.abspath("./config")
    ]
    for dir_name in abs_dirs:
        logger.info(f"Volume directory: {dir_name}")
        # os.makedirs(dir_name, exist_ok=True)

    # Run container
    container = client.containers.run(
        "docker.io/mailserver/docker-mailserver:latest",
        name="mailserver-python",
        hostname="mail",
        domainname="cobra.org",
        detach=True,
        ports={
            "25/tcp": 25,
            "587/tcp": 587,
            "110/tcp": 110,
            "143/tcp": 143,
            "993/tcp": 993,
        },
        cap_add=["NET_ADMIN", "SYS_PTRACE"],
        environment={
            "ENABLE_CLAMAV": "0",
            "ENABLE_SPAMASSASSIN": "0",
            "ENABLE_POSTGREY": "0",
            "ENABLE_FAIL2BAN": "0",
            "DMS_DEBUG": "0",
            "POSTMASTER_ADDRESS": "postmaster@cobra.org",
        },
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
        logger.error("Mailserver failed to start.")
        return

    # Create postmaster account
    logger.info("Creating postmaster account...")
    exit_code, output = container.exec_run(
        ["setup", "email", "add", "postmaster@cobra.org", "Admin1234!"]
    )

    if exit_code == 0:
        logger.info("Postmaster account created successfully.")
    else:
        logger.error(f"Failed to create postmaster: {output.decode('utf-8')}")

    # Check user list
    time.sleep(3)  # Wait a bit for the user to be created
    exit_code, output = container.exec_run(["setup", "email", "list"])
    if exit_code == 0:
        logger.info(f"Current email users:\n{output.decode('utf-8')}")
    else:
        logger.error(f"Failed to list users: {output.decode('utf-8')}")

    # Check user list with doveadm
    exit_code, output = container.exec_run(["doveadm", "user", "*", "list"])
    if exit_code == 0:
        logger.info(f"Dovecot users:\n{output.decode('utf-8')}")
    else:
        logger.error(f"Failed to list dovecot users: {output.decode('utf-8')}")

    # Wait 30 seconds before stopping
    logger.info("Mailserver will run for 30 seconds before stopping...")
    time.sleep(30)
    logger.info("Stopping mailserver container...")

    container.stop()
    container.remove(v=True, force=True)
    logger.info("Mailserver container stopped and removed.")

    logger.info("Mailserver setup complete.")

# Main

def main():
    parser = argparse.ArgumentParser(
        prog="mailserver-configurator",
        description="A tool to configure, start or stop a mail server. Primarily for Docker Mailserver.",
    )

    parser.add_argument("--debug", action="store_true", help="Enable debug logging")

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
    setup_mailserver(client)

    logger.info("Finishing mailserver-configurator.")


if __name__ == "__main__":
    main()
