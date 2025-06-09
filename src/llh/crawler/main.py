"""
Main crawler module for the Ledger Lattice Hunter.
Handles blockchain data collection and signature extraction.
"""

import asyncio
import logging
import os
from typing import Dict, List, Optional, Any
from datetime import datetime
from decimal import Decimal

import time

import bitcoin.rpc
from bitcoin.core import CTransaction, x, b2lx, CTxOut
from bitcoin.core.script import CScript

from ..utils.config import load_config
from ..utils.logging import setup_logging
from ..database.connection import DatabaseConnection
from ..database.models import PubkeyMetadata, Signature
from .transaction_parser import TransactionParser
from .checkpoint import load_checkpoint, save_checkpoint

logger = logging.getLogger(__name__)

class BlockchainCrawler:
    """Main crawler class for collecting blockchain data."""
    

    def __init__(self, config: Dict[str, Any]):
        """Initialize the crawler with configuration."""
        self.config = config
        self._rpc_conf = self.config["bitcoin_rpc"]
        self.db = DatabaseConnection(self.config)
        self.parser = TransactionParser()
        # Rate limiter: 20 API calls per second
        self._rate_limit = 15  # max requests per second
        self._min_interval = 1.0 / self._rate_limit
        self._last_call_time = 0.0
        self._rate_lock = asyncio.Lock()

    def _make_rpc(self) -> bitcoin.rpc.Proxy:
        """Create a new Bitcoin RPC connection (not thread-safe to share)."""
        rpc_conf = self._rpc_conf
        rpc_url = rpc_conf["url"]
        rpc_user = rpc_conf["user"]
        rpc_pass = rpc_conf["password"]
        if "://" in rpc_url:
            rpc_url = rpc_url.split("://")[1]
        service_url = f"http://{rpc_user}:{rpc_pass}@{rpc_url}"
        return bitcoin.rpc.Proxy(service_url=service_url, timeout=self.config["crawler"]["timeout"])

    async def _acquire_rate_limit(self):
        async with self._rate_lock:
            now = time.monotonic()
            elapsed = now - self._last_call_time
            if elapsed < self._min_interval:
                await asyncio.sleep(self._min_interval - elapsed)
            self._last_call_time = time.monotonic()

    async def _rate_limited_rpc(self, func, *args, **kwargs):
        await self._acquire_rate_limit()
        return await asyncio.to_thread(func, *args, **kwargs)
        
    def _setup_rpc(self) -> bitcoin.rpc.Proxy:
        """Set up Bitcoin RPC connection."""
        rpc_conf = self.config["bitcoin_rpc"]
        rpc_url = rpc_conf["url"]
        rpc_user = rpc_conf["user"]
        rpc_pass = rpc_conf["password"]
        
        # The URL should be in the format: http://user:password@host:port
        # python-bitcoinlib will parse this.
        # We need to strip the protocol if present in the rpc_url from config
        if "://" in rpc_url:
            rpc_url = rpc_url.split("://")[1]

        service_url = f"http://{rpc_user}:{rpc_pass}@{rpc_url}"
        
        return bitcoin.rpc.Proxy(service_url=service_url, timeout=self.config["crawler"]["timeout"])
    
    async def start(self):
        """Start the crawler and begin data collection."""
        try:
            logger.info("Initializing blockchain crawler")
            logger.info(f"RPC URL: {self.config['bitcoin_rpc']['url']}")
            logger.info(f"RPC User: {self.config['bitcoin_rpc']['user']}")
            
            # Test RPC connection before proceeding
            try:
                rpc = self._make_rpc()
                test_connection = await self._rate_limited_rpc(rpc.getblockcount)
                logger.info(f"RPC connection successful. Block height: {test_connection}")
            except Exception as e:
                logger.error(f"RPC connection test failed: {e}", exc_info=True)
                raise RuntimeError(f"Failed to connect to Bitcoin RPC: {str(e)}")
            await self.db.connect()
            logger.info("Database connection established")
            await self._crawl_blocks()
        except Exception as e:
            logger.critical(f"Fatal error in crawler: {e}", exc_info=True)
            raise
        finally:
            await self.db.close()
            logger.info("Crawler execution completed")
    
    async def _crawl_blocks(self):
        """Crawl blocks and extract transaction data."""
        current_block = await self._get_latest_block()
        batch_size = self.config["crawler"]["batch_size"]
        
        # Load the checkpoint to determine where to start
        start_block = load_checkpoint()
        logger.info(f"Starting crawler from block {start_block} to {current_block} (total: {current_block - start_block} blocks)")
        logger.info(f"RPC URL: {self.config['bitcoin_rpc']['url']}")
        logger.info(f"RPC User: {self.config['bitcoin_rpc']['user']}")
        logger.info(f"Batch size: {batch_size}")
        
        # Log more details about the process
        if current_block <= start_block:
            logger.warning(f"No new blocks to process. Current: {current_block}, Start: {start_block}")
            return
            
        block_count = 0
        
        for block_start in range(start_block, current_block, batch_size):
            block_end = min(block_start + batch_size -1, current_block)
            logger.info(f"Processing blocks {block_start} to {block_end}")
            
            try:
                await self._process_block_range(block_start, block_end)
                # Save a checkpoint after each batch is processed
                save_checkpoint(block_end + 1)
            except Exception as e:
                logger.error(f"Error processing block range {block_start}-{block_end}: {e}", exc_info=True)
                # Save checkpoint at the start of the failed batch so we can retry
                save_checkpoint(block_start)
                continue
                
            # Log progress
            block_count += (block_end - block_start + 1)
            progress_pct = (block_count / (current_block - start_block)) * 100
            logger.info(f"Progress: {block_count}/{current_block - start_block} blocks ({progress_pct:.2f}%)")
        
        # Log final parser statistics
        logger.info("="*60)
        logger.info("FINAL CRAWLER STATISTICS")
        logger.info("="*60)
        self.parser.log_stats()
    
    async def _get_latest_block(self) -> int:
        """Get the latest block number."""
        try:
            logger.debug("Attempting to get latest block height from RPC")
            rpc = self._make_rpc()
            block_count = await self._rate_limited_rpc(rpc.getblockcount)
            logger.info(f"Latest block height: {block_count}")
            return block_count
        except Exception as e:
            logger.error(f"Error getting latest block: {e}", exc_info=True)
            logger.warning("Using fallback value of 10 blocks for testing. This should NOT happen in production!")
            if os.environ.get('ENVIRONMENT') == 'production':
                raise
            return 10
    
    async def _process_block_range(self, start_block: int, end_block: int):
        """Process a range of blocks."""
        # Process blocks concurrently with rate limiting
        semaphore = asyncio.Semaphore(self.config["crawler"]["concurrent_requests"])

        async def process_with_semaphore(block_number):
            async with semaphore:
                return await self._process_block(block_number)

        tasks = [process_with_semaphore(block_number) for block_number in range(start_block, end_block + 1)]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Process results and update database
        total_signatures = 0
        for block_number, result in zip(range(start_block, end_block + 1), results):
            if isinstance(result, Exception):
                logger.error(f"Error processing block {block_number}: {result}", exc_info=True)
                continue
            
            signatures = result
            if signatures:
                count = len(signatures)
                total_signatures += count
                logger.info(f"Found {count} signatures in block {block_number}")
                await self._update_database(signatures)
        
        if total_signatures > 0:
            logger.info(f"Block range {start_block}-{end_block}: {total_signatures} total signatures extracted")
        
        # Log parser statistics periodically
        if (end_block - start_block) % 100 == 0 or end_block % 1000 == 0:
            self.parser.log_stats()
    
    async def _process_block(self, block_number: int) -> List[Signature]:
        """Process a single block and extract transaction data."""
        logger.info(f"Processing block {block_number}")
        try:
            rpc = self._make_rpc()
            logger.debug(f"Fetching block hash for block {block_number}")
            block_hash = await self._rate_limited_rpc(rpc.getblockhash, block_number)
            logger.debug(f"Block hash for block {block_number}: {block_hash}")

            logger.debug(f"Fetching full block data for block {block_number}")
            block = await self._rate_limited_rpc(rpc.getblock, block_hash)  # removed extra arg
            logger.debug(f"Block {block_number} retrieved successfully")

            # The rest of the code expects block['tx'], but bitcoin.rpc.Proxy.getblock returns a CBlock, not a dict.
            # If you need verbose tx data, you may need to fetch raw block and decode, or adjust logic here.
            # For now, keep the structure, but you may need to adapt downstream code if block['tx'] fails.
            if not hasattr(block, 'vtx'):
                logger.error(f"Block object does not have 'vtx' attribute. Adjust parsing logic as needed.")
                return []

            all_signatures = []
            for tx in block.vtx:
                # tx is a CTransaction already
                # For each input, we need the scriptPubKey from the output it is spending.
                # To get this, we must fetch the full previous transaction.
                prev_tx_tasks = []
                input_indices_with_prevout = []
                for i, txin in enumerate(tx.vin):
                    if txin.prevout.is_null(): # Skip coinbase
                        continue
                    input_indices_with_prevout.append(i)
                    prev_tx_hash_bytes = txin.prevout.hash
                    # Use getrawtransaction with verbose=1 to get dict
                    rpc_task = self._rate_limited_rpc(self._make_rpc().getrawtransaction, prev_tx_hash_bytes, 1)
                    prev_tx_tasks.append(rpc_task)
                if not prev_tx_tasks:
                    continue # only coinbase inputs in this tx

                results = await asyncio.gather(*prev_tx_tasks, return_exceptions=True)

                prev_tx_vouts = []
                valid_indices = []
                for i, res in enumerate(results):
                    original_index = input_indices_with_prevout[i]
                    txin = tx.vin[original_index]
                    if isinstance(res, Exception):
                        logger.warning(f"Could not fetch prev_tx for input {b2lx(txin.prevout.hash)}:{txin.prevout.n}. Error: {res}")
                        continue

                    prev_tx_dict = res
                    output_index = txin.prevout.n
                    if output_index < len(prev_tx_dict['tx'].vout):
                        vout = prev_tx_dict['tx'].vout[output_index]
                        # vout is already a CTxOut object, no need to reconstruct
                        prev_tx_vouts.append(vout)
                        valid_indices.append(original_index)
                    else:
                        logger.warning(f"Output index {output_index} out of range for tx {b2lx(txin.prevout.hash)}")

                if not prev_tx_vouts:
                    continue

                signatures = self.parser.process_transaction(tx, valid_indices, prev_tx_vouts, block_number)
                all_signatures.extend(signatures)

            return all_signatures

        except Exception as e:
            logger.error(f"Error processing block {block_number}: {e}", exc_info=True)
            return []

    async def _update_database(self, signatures: List[Signature]):
        """Update database with new signatures and pubkey metadata."""
        pubkey_counts = {}
        
        for signature in signatures:
            # Insert signature
            await self.db.insert_signature(signature)
            
            # Update pubkey count
            pubkey = signature.pubkey
            pubkey_counts[pubkey] = pubkey_counts.get(pubkey, 0) + 1
        
        # Update pubkey metadata
        for pubkey, count in pubkey_counts.items():
            metadata = PubkeyMetadata(
                pubkey=pubkey,
                signature_count=count,
                last_seen=datetime.utcnow()
            )
            await self.db.update_pubkey_metadata(metadata)


async def main():
    """Main entry point for the crawler."""
    # Setup logging
    log_level = os.environ.get('LOG_LEVEL', 'INFO')
    logging_config = {
        "level": log_level,
        "format": "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        "file": "logs/llh.log"
    }
    setup_logging(logging_config)
    
    try:
        # Log startup information
        logger.info("="*80)
        logger.info("Starting blockchain crawler")
        logger.info("="*80)
        
        # Load configuration
        config_path = os.environ.get('CONFIG_PATH', 'config/config.yaml')
        logger.info(f"Loading configuration from {config_path}")
        config = load_config(config_path)
        
        # Create and start crawler
        crawler = BlockchainCrawler(config)
        logger.info("Crawler initialized, starting blockchain processing")
        await crawler.start()
        
        logger.info("Crawler completed successfully")
        return 0
    except Exception as e:
        logger.critical(f"Critical error in crawler main: {e}", exc_info=True)
        return 1


if __name__ == "__main__":
    # Run the main async function
    import sys
    result = asyncio.run(main())
    sys.exit(result)