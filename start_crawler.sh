#!/bin/bash

# Script to ensure the crawler processes the entire blockchain from the beginning
set -x  # Enable debugging output

echo "Starting blockchain crawler from genesis block..."

# Make sure data directory exists
mkdir -p /app/data/checkpoints

# For debugging, list contents
ls -la /app
ls -la /app/src
ls -la /app/src/llh
ls -la /app/src/llh/crawler

# Only create initial checkpoint if none exists
if [ ! -f /app/data/checkpoints/crawler_checkpoint.txt ]; then
    echo "1" > /app/data/checkpoints/crawler_checkpoint.txt
    echo "Starting from block 1 (no existing checkpoint)"
else
    EXISTING_CHECKPOINT=$(cat /app/data/checkpoints/crawler_checkpoint.txt)
    echo "Found existing checkpoint: $EXISTING_CHECKPOINT"
fi 

# Print environment variables for debugging (redact passwords)
echo "CHAINSTACK_BTC_RPC_URL: ${CHAINSTACK_BTC_RPC_URL}"
echo "CHAINSTACK_BTC_RPC_USER: ${CHAINSTACK_BTC_RPC_USER}"
echo "MONGODB_URI: ${MONGODB_URI}"

while true; do
  echo "Running crawler..."
  
  # Create logs directory if it doesn't exist
  mkdir -p /app/logs
  
  # Set time for this run
  TIMESTAMP=$(date +"%Y-%m-%d_%H-%M-%S")
  LOG_FILE="/app/logs/crawler_${TIMESTAMP}.log"
  
  echo "Starting crawler run at $(date), logging to ${LOG_FILE}"
  
  # Run the crawler with detailed output and logging level set to DEBUG
  # Tee output to both console and log file
  PYTHONPATH=/app LOG_LEVEL=DEBUG sage -python -m src.llh.crawler.main 2>&1 | tee -a ${LOG_FILE}
  
  # Check exit code (note: using PIPESTATUS to get exit code of python not tee)
  EXIT_CODE=${PIPESTATUS[0]}
  echo "Crawler exited with code: $EXIT_CODE"
  
  # Check if checkpoint file exists and show its content
  echo "Current checkpoint:"
  cat /app/data/checkpoints/crawler_checkpoint.txt 2>/dev/null || echo "No checkpoint file found"
  
  # Print MongoDB status for debugging
  echo "MongoDB status:"
  mongo --eval "db.serverStatus()" mongodb:27017/llh_db || echo "Failed to connect to MongoDB"
  
  # Direct test of Bitcoin RPC connection
  echo "Testing Bitcoin RPC connection:"
  # Simple test script to check RPC connection
  sage -python -c "
import asyncio, bitcoin.rpc
async def test_rpc():
  try:
    rpc_url='${CHAINSTACK_BTC_RPC_URL}'
    rpc_user='${CHAINSTACK_BTC_RPC_USER}'
    rpc_pass='${CHAINSTACK_BTC_RPC_PASSWORD}'
    if '://' in rpc_url:
        rpc_url = rpc_url.split('://')[1]
    service_url = f'http://{rpc_user}:{rpc_pass}@{rpc_url}'
    print(f'Connecting to {service_url}')
    proxy = bitcoin.rpc.Proxy(service_url=service_url)
    block_count = proxy.getblockcount()
    print(f'Connection successful! Latest block: {block_count}')
  except Exception as e:
    print(f'RPC connection failed: {e}')
asyncio.run(test_rpc())
" || echo "RPC test script failed to execute"
  
  if [ $EXIT_CODE -eq 0 ]; then
    echo "Crawler completed processing all available blocks."
    # Use shorter sleep during development for faster feedback
    echo "Sleeping for 5 minutes before checking for new blocks..."
    sleep 300  # Sleep for 5 minutes instead of 30
  else
    echo "Crawler exited with an error. Retrying in 60 seconds..."
    sleep 60  # Shorter retry time on errors
  fi
done