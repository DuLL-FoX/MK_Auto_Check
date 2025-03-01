import logging
import os
import sys
from logging.handlers import RotatingFileHandler
from typing import Optional, Dict, Any


class CustomFormatter(logging.Formatter):
    COLORS = {
        'DEBUG': '\033[36m',
        'INFO': '\033[32m',
        'WARNING': '\033[33m',
        'ERROR': '\033[31m',
        'CRITICAL': '\033[41m',
        'RESET': '\033[0m'
    }

    def __init__(self, fmt: str, datefmt: str, use_colors: bool = True):
        super().__init__(fmt, datefmt)
        self.use_colors = use_colors and sys.stdout.isatty()

    def format(self, record):
        original_msg = record.msg
        original_levelname = record.levelname
        if self.use_colors:
            color = self.COLORS.get(record.levelname, self.COLORS['RESET'])
            record.levelname = f"{color}{record.levelname}{self.COLORS['RESET']}"
        if isinstance(record.msg, str) and ('=' * 10) in record.msg:
            if record.msg.strip() == ('=' * 50) or record.msg.strip() == ('=' * 60):
                record.msg = '-' * 30
        result = super().format(record)
        record.msg = original_msg
        record.levelname = original_levelname
        return result


class ContextFilter(logging.Filter):
    def __init__(self, context: Optional[Dict[str, Any]] = None):
        super().__init__()
        self.context = context or {}

    def filter(self, record):
        for key, value in self.context.items():
            setattr(record, key, value)
        return True


def setup_logging(
        log_file: Optional[str] = None,
        level: int = logging.INFO,
        max_bytes: int = 10 * 1024 * 1024,
        backup_count: int = 5,
        use_colors: bool = True,
        log_dir: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None
) -> logging.Logger:
    if log_dir and not os.path.exists(log_dir):
        os.makedirs(log_dir)
    if log_file and log_dir:
        log_file = os.path.join(log_dir, log_file)
    root_logger = logging.getLogger()
    root_logger.setLevel(level)
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)
    log_format = "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s"
    if context:
        context_format = " | ".join(f"{k}=%(${k})s" for k in context.keys())
        log_format = f"{log_format} | {context_format}"
    date_format = "%Y-%m-%d %H:%M:%S"
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(CustomFormatter(log_format, date_format, use_colors))
    root_logger.addHandler(console_handler)
    if log_file:
        try:
            file_handler = RotatingFileHandler(
                log_file, maxBytes=max_bytes, backupCount=backup_count
            )
            file_handler.setFormatter(logging.Formatter(log_format, date_format))
            root_logger.addHandler(file_handler)
        except (IOError, PermissionError) as e:
            logging.error(f"Failed to create log file {log_file}: {e}")
    if context:
        context_filter = ContextFilter(context)
        for handler in root_logger.handlers:
            handler.addFilter(context_filter)
    logging.getLogger("discord").setLevel(logging.WARNING)
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("requests").setLevel(logging.WARNING)
    logging.getLogger("asyncio").setLevel(logging.WARNING)
    logging.info("Logging configured successfully")
    return root_logger


def get_logger(name: str, level: Optional[int] = None) -> logging.Logger:
    logger = logging.getLogger(name)
    if level is not None:
        logger.setLevel(level)
    return logger
