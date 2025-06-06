"""
Integration tests for the BlockchainCrawler.

These tests are designed to run against a live Bitcoin RPC node and a running database.
They require a valid configuration in `config/config.yaml` and a populated `.env` file.
"""

import pytest
from llh.crawler.main import BlockchainCrawler
from llh.database.connection import DatabaseConnection
from llh.utils.config import load_config
from dotenv import load_dotenv

load_dotenv()

@pytest.fixture(scope="module")
def crawler():
    """Fixture to initialize the BlockchainCrawler."""
    config = load_config("config/config.yaml")
    return BlockchainCrawler(config)

@pytest.fixture(scope="module")
async def db_connection(crawler: BlockchainCrawler):
    """Fixture to manage the database connection."""
    db = crawler.db
    await db.connect()
    yield db
    await db.close()

@pytest.mark.asyncio
async def test_rpc_connection(crawler: BlockchainCrawler):
    """Test that a connection to the Bitcoin RPC node can be established."""
    latest_block = await crawler._get_latest_block()
    assert isinstance(latest_block, int)
    assert latest_block > 0
    print(f"Successfully connected to RPC. Latest block: {latest_block}")

@pytest.mark.asyncio
async def test_process_block_range(crawler: BlockchainCrawler, db_connection: DatabaseConnection):
    """
    Test processing a small range of blocks to ensure the pipeline runs.
    This test will process 2 blocks. A small number is used to keep test duration reasonable.
    """
    latest_block = await crawler._get_latest_block()
    start_block = latest_block - 1000  # Process a recent block
    end_block = start_block + 1
    
    print(f"Testing block processing for range: {start_block} - {end_block}")
    
    await crawler._process_block_range(start_block, end_block)
    
    print("Block range processed successfully.")

    assert True 