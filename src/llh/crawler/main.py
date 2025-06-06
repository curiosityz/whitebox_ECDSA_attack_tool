"""
Main crawler module for the Ledger Lattice Hunter.
Handles blockchain data collection and signature extraction.
"""

import asyncio
import logging
from typing import Dict, List, Optional, Any
from datetime import datetime
from decimal import Decimal

import bitcoin.rpc
from bitcoin.core import CTransaction, x, b2lx, CTxOut
from bitcoin.core.script import CScript

from ..utils.config import load_config
from ..utils.logging import setup_logging
from ..database.connection import DatabaseConnection
from ..database.models import PubkeyMetadata, Signature
from .transaction_parser import TransactionParser

logger = logging.getLogger(__name__)

class BlockchainCrawler:
    """Main crawler class for collecting blockchain data."""
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize the crawler with configuration."""
        self.config = config
        self.rpc = self._setup_rpc()
        self.db = DatabaseConnection(self.config)
        self.parser = TransactionParser()
        
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
            await self.db.connect()
            await self._crawl_blocks()
        finally:
            await self.db.close()
    
    async def _crawl_blocks(self):
        """Crawl blocks and extract transaction data."""
        current_block = await self._get_latest_block()
        batch_size = self.config["crawler"]["batch_size"]
        
        # Start from the first block
        start_block = 1
        
        for block_start in range(start_block, current_block, batch_size):
            block_end = min(block_start + batch_size -1, current_block)
            logger.info(f"Processing blocks {block_start} to {block_end}")
            
            try:
                await self._process_block_range(block_start, block_end)
            except Exception as e:
                logger.error(f"Error processing block range {block_start}-{block_end}: {e}", exc_info=True)
                continue
    
    async def _get_latest_block(self) -> int:
        """Get the latest block number."""
        return await asyncio.to_thread(self.rpc.getblockcount)
    
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
        for block_number, result in zip(range(start_block, end_block + 1), results):
            if isinstance(result, Exception):
                logger.error(f"Error processing block {block_number}: {result}", exc_info=True)
                continue
            
            signatures = result
            if signatures:
                await self._update_database(signatures)
    
    async def _process_block(self, block_number: int) -> List[Signature]:
        """Process a single block and extract transaction data."""
        logger.debug(f"Processing block {block_number}")
        try:
            block_hash = await asyncio.to_thread(self.rpc.getblockhash, block_number)
            block = await asyncio.to_thread(self.rpc.getblock, block_hash, 2)

            if not block or not block.get('tx'):
                return []

            all_signatures = []
            for tx_data in block['tx']:
                tx = CTransaction.deserialize(x(tx_data['hex']))

                # For each input, we need the scriptPubKey from the output it is spending.
                # To get this, we must fetch the full previous transaction.
                
                # Prepare to fetch previous transactions concurrently
                prev_tx_tasks = []
                input_indices_with_prevout = []
                for i, txin in enumerate(tx.vin):
                    if txin.prevout.is_null(): # Skip coinbase
                        continue
                    input_indices_with_prevout.append(i)
                    prev_tx_hash_str = b2lx(txin.prevout.hash)
                    # Use getrawtransaction with verbose=1 to get dict
                    prev_tx_tasks.append(
                        asyncio.to_thread(self.rpc.getrawtransaction, prev_tx_hash_str, 1)
                    )
                
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
                    if output_index < len(prev_tx_dict['vout']):
                        vout_dict = prev_tx_dict['vout'][output_index]
                        script_pub_key_hex = vout_dict['scriptPubKey']['hex']
                        # Convert value from BTC (Decimal) to satoshis (int)
                        vout_val = int(Decimal(str(vout_dict['value'])) * 10**8)
                        prev_tx_vouts.append(CTxOut(vout_val, CScript(x(script_pub_key_hex))))
                        valid_indices.append(original_index)
                    else:
                        logger.warning(f"Output index {output_index} out of range for tx {b2lx(txin.prevout.hash)}")

                if not prev_tx_vouts:
                    continue

                # Pass the CTransaction object, the vouts of inputs, and the indices of those inputs
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