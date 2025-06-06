"""
Configuration utility module for loading and managing project settings.
"""

import os
from typing import Dict, Any
import yaml
from dotenv import load_dotenv

def load_config(config_path: str) -> Dict[str, Any]:
    """
    Load configuration from YAML file and environment variables.
    
    Args:
        config_path: Path to the YAML configuration file
        
    Returns:
        Dict containing the merged configuration
    """
    # Load environment variables
    load_dotenv()
    
    # Load YAML configuration
    with open(config_path, 'r') as f:
        config = yaml.safe_load(f)
    
    # Replace environment variables in configuration
    _replace_env_vars(config)
    
    return config

def _replace_env_vars(config: Dict[str, Any]) -> None:
    """
    Recursively replace environment variable placeholders in configuration.
    
    Args:
        config: Configuration dictionary to process
    """
    for key, value in config.items():
        if isinstance(value, dict):
            _replace_env_vars(value)
        elif isinstance(value, str) and value.startswith('${') and value.endswith('}'):
            env_var = value[2:-1]
            config[key] = os.getenv(env_var)
            if config[key] is None:
                raise ValueError(f"Environment variable {env_var} not set") 