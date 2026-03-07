"""
Logger configuration for VulnSpectra
"""
import logging
import logging.handlers
import os
from datetime import datetime
import colorlog


def setup_logger(log_level=logging.INFO, log_file=None):
    """
    Setup structured logging with colors and file output

    Args:
        log_level: Logging level
        log_file: Path to log file (optional)
    """
    # Create logs directory
    os.makedirs('logs', exist_ok=True)

    # Generate log filename if not provided
    if log_file is None:
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        log_file = f'logs/vulnspectra_{timestamp}.log'

    # Root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(log_level)

    # Remove existing handlers
    root_logger.handlers = []

    # Console handler with colors
    console_handler = colorlog.StreamHandler()
    console_handler.setLevel(log_level)

    console_format = colorlog.ColoredFormatter(
        '%(log_color)s%(asctime)s [%(levelname)s] %(name)s: %(message)s%(reset)s',
        datefmt='%Y-%m-%d %H:%M:%S',
        log_colors={
            'DEBUG': 'cyan',
            'INFO': 'green',
            'WARNING': 'yellow',
            'ERROR': 'red',
            'CRITICAL': 'red,bg_white',
        }
    )
    console_handler.setFormatter(console_format)
    root_logger.addHandler(console_handler)

    # File handler
    file_handler = logging.handlers.RotatingFileHandler(
        log_file,
        maxBytes=10 * 1024 * 1024,  # 10MB
        backupCount=5
    )
    file_handler.setLevel(log_level)

    file_format = logging.Formatter(
        '%(asctime)s [%(levelname)s] %(name)s: %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    file_handler.setFormatter(file_format)
    root_logger.addHandler(file_handler)

    # Log startup
    logging.info(f"Logger initialized - Log file: {log_file}")

    return root_logger

