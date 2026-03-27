"""Configuration management for SBOM CLI.

Supports:
- CLI arguments
- Environment variables
- Config files

Precedence: CLI > Environment > Config file
"""

import os
from pathlib import Path
from typing import Any, Dict, Optional

import json

DEFAULT_CONFIG = {
    "db_path": "sbom.db",
    "output_format": "text",
    "quiet": False,
    "verbose": 0,
}


def get_config_file_path() -> Optional[Path]:
    """Get the path to the config file.

    Checks in order:
    1. SBOM_CONFIG_PATH environment variable
    2. ~/.sbom-cli/config.json
    3. ./.sbom-cli/config.json

    Returns:
        Path to config file if found, None otherwise.
    """
    # Check environment variable first
    env_path = os.environ.get("SBOM_CONFIG_PATH")
    if env_path:
        path = Path(env_path)
        if path.exists():
            return path

    # Check user home directory
    home_config = Path.home() / ".sbom-cli" / "config.json"
    if home_config.exists():
        return home_config

    # Check current directory
    local_config = Path(".sbom-cli") / "config.json"
    if local_config.exists():
        return local_config

    return None


def load_config_file(config_path: Optional[Path] = None) -> Dict[str, Any]:
    """Load configuration from file.

    Args:
        config_path: Optional path to config file. If None, uses default search.

    Returns:
        Dictionary with configuration values.
    """
    if config_path is None:
        config_path = get_config_file_path()

    if config_path is None or not config_path.exists():
        return {}

    try:
        with open(config_path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, IOError):
        return {}


def get_config(
    cli_args: Optional[Dict[str, Any]] = None,
    config_file: Optional[Path] = None,
) -> Dict[str, Any]:
    """Get merged configuration with proper precedence.

    Precedence: CLI > Environment > Config file > Defaults

    Args:
        cli_args: Dictionary of CLI argument values.
        config_file: Optional path to config file.

    Returns:
        Merged configuration dictionary.
    """
    # Start with defaults
    config = DEFAULT_CONFIG.copy()

    # Load config file
    file_config = load_config_file(config_file)
    config.update(file_config)

    # Override with environment variables
    env_mapping = {
        "SBOM_DB_PATH": "db_path",
        "SBOM_OUTPUT_FORMAT": "output_format",
        "SBOM_QUIET": "quiet",
        "SBOM_VERBOSE": "verbose",
    }

    for env_var, config_key in env_mapping.items():
        env_value = os.environ.get(env_var)
        if env_value is not None:
            # Convert to appropriate type
            if config_key == "verbose":
                config[config_key] = int(env_value)
            elif config_key == "quiet":
                config[config_key] = env_value.lower() in ("true", "1", "yes")
            else:
                config[config_key] = env_value

    # Override with CLI arguments
    if cli_args:
        for key, value in cli_args.items():
            if value is not None:
                config[key] = value

    return config


def get_db_path(cli_path: Optional[str] = None) -> str:
    """Get database path with proper precedence.

    Args:
        cli_path: Optional path from CLI argument.

    Returns:
        Database path string.
    """
    # CLI argument takes precedence
    if cli_path:
        return cli_path

    # Environment variable
    env_path = os.environ.get("SBOM_DB_PATH")
    if env_path:
        return env_path

    # Config file
    config = load_config_file()
    if "db_path" in config:
        return config["db_path"]

    # Default
    return DEFAULT_CONFIG["db_path"]
