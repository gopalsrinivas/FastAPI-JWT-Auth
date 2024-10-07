import os
import logging
from logging.config import dictConfig

# Set your desired log directory path
log_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "../logger")

# Ensure the logger directory exists
os.makedirs(log_dir, exist_ok=True)

# Define the log file path inside the logger directory
log_file_path = os.path.join(log_dir, "logger_app.log")

LOGGING_CONFIG = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "default": {
            "format": "{levelname} {asctime} {name} {message}",
            "style": "{",
            "datefmt": "%Y-%m-%d %H:%M:%S",
        },
        "error_formatter": {
            "format": "{levelname} {asctime} {name} {message}",
            "style": "{",
            "datefmt": "%Y-%m-%d %H:%M:%S",
        },
    },
    "handlers": {
        "file": {
            "level": "DEBUG",
            "class": "logging.FileHandler",
            "filename": log_file_path,
            "formatter": "default",
        },
        "error_file": {
            "level": "ERROR",
            "class": "logging.FileHandler",
            "filename": os.path.join(log_dir, "error_app.log"),
            "formatter": "error_formatter",
        },
    },
    "root": {
        "handlers": ["file", "error_file"],
        "level": "DEBUG",
    },
}

# Apply the logging configuration
dictConfig(LOGGING_CONFIG)
logger = logging.getLogger(__name__)

# Example usage
logger.debug("This is a debug message")
logger.error("This is an error message")
