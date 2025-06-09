"""
Checkpoint management for the blockchain crawler.
Ensures the crawler can resume from where it left off if interrupted.
"""

import os
import logging
from typing import Optional

logger = logging.getLogger(__name__)

CHECKPOINT_DIR = "data/checkpoints"
CHECKPOINT_FILE = f"{CHECKPOINT_DIR}/crawler_checkpoint.txt"

def ensure_checkpoint_dir():
    """Ensure the checkpoint directory exists."""
    os.makedirs(CHECKPOINT_DIR, exist_ok=True)

def save_checkpoint(block_number: int) -> bool:
    """
    Save the current block number as a checkpoint.
    
    Args:
        block_number: The block number to save
        
    Returns:
        bool: True if successful, False otherwise
    """
    try:
        ensure_checkpoint_dir()
        with open(CHECKPOINT_FILE, 'w') as f:
            f.write(str(block_number))
        logger.info(f"Checkpoint saved: Block {block_number}")
        return True
    except Exception as e:
        logger.error(f"Failed to save checkpoint: {e}")
        return False

def load_checkpoint() -> Optional[int]:
    """
    Load the last processed block number from checkpoint.
    
    Returns:
        int: The last processed block number, or None if no checkpoint exists
    """
    try:
        if not os.path.exists(CHECKPOINT_FILE):
            logger.info("No checkpoint found, starting from genesis block")
            return 1  # Start from the genesis block
            
        with open(CHECKPOINT_FILE, 'r') as f:
            checkpoint = int(f.read().strip())
            
        logger.info(f"Loaded checkpoint: Block {checkpoint}")
        return checkpoint
    except Exception as e:
        logger.error(f"Failed to load checkpoint: {e}")
        # If there's an error reading the checkpoint, start from the beginning
        return 1