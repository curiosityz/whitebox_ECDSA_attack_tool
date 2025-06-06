"""
Logging utility module for consistent logging configuration.
"""

import logging
import os
from typing import Dict, Any

def setup_logging(config: Dict[str, Any] = None) -> None:
    """
    Set up logging configuration for the application.
    
    Args:
        config: Optional configuration dictionary. If not provided,
               will use default configuration.
    """
    if config is None:
        config = {
            "level": "INFO",
            "format": "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
            "file": "logs/llh.log"
        }
    
    # Create logs directory if it doesn't exist
    log_dir = os.path.dirname(config["file"])
    if log_dir and not os.path.exists(log_dir):
        os.makedirs(log_dir)
    
    # Configure root logger
    logging.basicConfig(
        level=getattr(logging, config["level"]),
        format=config["format"],
        handlers=[
            logging.FileHandler(config["file"]),
            logging.StreamHandler()
        ]
    )
    
    # Set specific logger levels
    logging.getLogger("web3").setLevel(logging.WARNING)
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("aiohttp").setLevel(logging.WARNING) 