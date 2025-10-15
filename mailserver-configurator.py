import os
import argparse
import logging

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
    
    # Placeholder for actual mail server configuration logic
    logger.info("Mail server configuration logic would go here.")

    logger.info("Finishing mailserver-configurator.")


if __name__ == "__main__":
    main()
