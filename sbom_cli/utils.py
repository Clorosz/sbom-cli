"""Utility functions for SBOM CLI."""

import logging
import sys


def setup_logging(verbosity: int = 0) -> logging.Logger:
    """Set up logging with appropriate verbosity level.

    Args:
        verbosity: Verbosity level (0=warning, 1=info, 2=debug)

    Returns:
        Configured logger instance.
    """
    logger = logging.getLogger("sbom_cli")

    # Clear existing handlers
    logger.handlers = []

    # Set level based on verbosity
    if verbosity >= 2:
        level = logging.DEBUG
    elif verbosity >= 1:
        level = logging.INFO
    else:
        level = logging.WARNING

    logger.setLevel(level)

    # Create console handler
    handler = logging.StreamHandler(sys.stderr)
    handler.setLevel(level)

    # Create formatter
    formatter = logging.Formatter(
        "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    handler.setFormatter(formatter)

    logger.addHandler(handler)

    return logger


def get_logger(name: str = "sbom_cli") -> logging.Logger:
    """Get a logger instance.

    Args:
        name: Logger name.

    Returns:
        Logger instance.
    """
    return logging.getLogger(name)


def format_json_output(data: dict, indent: int = 2) -> str:
    """Format data as JSON string.

    Args:
        data: Dictionary to format.
        indent: Number of spaces for indentation.

    Returns:
        JSON formatted string.
    """
    import json

    return json.dumps(data, indent=indent, default=str)


def truncate_string(s: str, max_length: int = 50, suffix: str = "...") -> str:
    """Truncate a string to maximum length.

    Args:
        s: String to truncate.
        max_length: Maximum length.
        suffix: Suffix to add if truncated.

    Returns:
        Truncated string.
    """
    if not s or len(s) <= max_length:
        return s
    return s[: max_length - len(suffix)] + suffix


def parse_wildcard_pattern(pattern: str) -> str:
    """Convert user wildcard pattern to SQL LIKE pattern.

    Args:
        pattern: User input pattern with '*' wildcards.

    Returns:
        SQL pattern with '*' converted to '%'.
    """
    return pattern.replace("*", "%")


def validate_file_path(path: str, must_exist: bool = True) -> bool:
    """Validate a file path.

    Args:
        path: Path to validate.
        must_exist: Whether file must exist.

    Returns:
        True if valid.

    Raises:
        FileNotFoundError: If file doesn't exist and must_exist is True.
    """
    from pathlib import Path

    p = Path(path)

    if must_exist and not p.exists():
        raise FileNotFoundError(f"File not found: {path}")

    return True
