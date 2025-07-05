"""Logging configuration for WTF CodeBot."""

import logging
import logging.handlers
import sys
from pathlib import Path
from typing import Optional

import structlog
from rich.console import Console
from rich.logging import RichHandler

from .config import Config, LoggingConfig


class ColoredFormatter(logging.Formatter):
    """Custom formatter with color support for console output."""
    
    COLORS = {
        'DEBUG': '\033[36m',    # Cyan
        'INFO': '\033[32m',     # Green
        'WARNING': '\033[33m',  # Yellow
        'ERROR': '\033[31m',    # Red
        'CRITICAL': '\033[35m', # Magenta
    }
    RESET = '\033[0m'
    
    def format(self, record: logging.LogRecord) -> str:
        """Format log record with colors."""
        if record.levelname in self.COLORS:
            record.levelname = f"{self.COLORS[record.levelname]}{record.levelname}{self.RESET}"
        return super().format(record)


def setup_logging(config: Optional[Config] = None) -> None:
    """Setup logging configuration.
    
    Args:
        config: Optional configuration object
    """
    if config is None:
        from .config import get_config
        config = get_config()
    
    logging_config = config.logging
    
    # Clear existing handlers
    root_logger = logging.getLogger()
    root_logger.handlers.clear()
    
    # Set log level
    log_level = getattr(logging, logging_config.level.upper(), logging.INFO)
    root_logger.setLevel(log_level)
    
    # Console handler with Rich formatting
    console_handler = RichHandler(
        console=Console(stderr=True),
        show_time=True,
        show_path=True,
        markup=True,
        rich_tracebacks=True,
        tracebacks_show_locals=config.verbose
    )
    console_handler.setLevel(log_level)
    
    # Use custom formatter for console if Rich is not available
    if not sys.stderr.isatty():
        console_handler = logging.StreamHandler(sys.stderr)
        console_handler.setLevel(log_level)
        formatter = ColoredFormatter(logging_config.format)
        console_handler.setFormatter(formatter)
    
    root_logger.addHandler(console_handler)
    
    # File handler if specified
    if logging_config.file_path:
        file_path = Path(logging_config.file_path)
        file_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Use rotating file handler to prevent large log files
        file_handler = logging.handlers.RotatingFileHandler(
            file_path,
            maxBytes=10 * 1024 * 1024,  # 10MB
            backupCount=5
        )
        file_handler.setLevel(log_level)
        
        # Use standard formatter for file output
        file_formatter = logging.Formatter(logging_config.format)
        file_handler.setFormatter(file_formatter)
        
        root_logger.addHandler(file_handler)
    
    # Configure structlog
    structlog.configure(
        processors=[
            structlog.stdlib.filter_by_level,
            structlog.stdlib.add_logger_name,
            structlog.stdlib.add_log_level,
            structlog.stdlib.PositionalArgumentsFormatter(),
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            structlog.processors.UnicodeDecoder(),
            structlog.processors.JSONRenderer() if logging_config.file_path else structlog.dev.ConsoleRenderer(),
        ],
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )


def get_logger(name: str) -> structlog.stdlib.BoundLogger:
    """Get a configured logger instance.
    
    Args:
        name: Logger name
        
    Returns:
        Configured logger instance
    """
    return structlog.get_logger(name)


class LoggerMixin:
    """Mixin class that provides logging functionality."""
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.logger = get_logger(self.__class__.__name__)
    
    def log_debug(self, message: str, **kwargs) -> None:
        """Log debug message."""
        self.logger.debug(message, **kwargs)
    
    def log_info(self, message: str, **kwargs) -> None:
        """Log info message."""
        self.logger.info(message, **kwargs)
    
    def log_warning(self, message: str, **kwargs) -> None:
        """Log warning message."""
        self.logger.warning(message, **kwargs)
    
    def log_error(self, message: str, **kwargs) -> None:
        """Log error message."""
        self.logger.error(message, **kwargs)
    
    def log_critical(self, message: str, **kwargs) -> None:
        """Log critical message."""
        self.logger.critical(message, **kwargs)
    
    def log_exception(self, message: str, **kwargs) -> None:
        """Log exception with traceback."""
        self.logger.exception(message, **kwargs)
