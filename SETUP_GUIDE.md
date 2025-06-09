# Setup Guide for Ledger Lattice Hunter

This guide will help you resolve the SageMath and g6k compatibility issues and get the application running successfully.

## Changes Made

### 1. **Dockerfile Updates**
- Upgraded from SageMath 9.7 to SageMath 10.1 for better compatibility
- Fixed g6k installation process
- Added proper dependency versions
- Improved build process

### 2. **Docker Compose Updates**
- Upgraded MongoDB from 4.4 to 6.0
- Added `netcat-traditional` for wait-for-it script compatibility
- Improved health checks
- Added proper Python environment setup

### 3. **Requirements Updates**
- Pinned all package versions for reproducibility
- Added fpylll==0.5.9 for lattice operations
- Ensured numpy version compatibility (1.24.4)

### 4. **Lattice Solver Improvements**
- Enhanced error handling
- Added g6k parameter configuration
- Improved vector extraction from g6k database
- Added progressive sieving with pump-and-jump BKZ

### 5. **Configuration Updates**
- Added g6k_params section for sieving configuration
- Added pump_params for BKZ tours
- Set appropriate default values

## Setup Instructions

### Step 1: Ensure Prerequisites
```bash
# Check Docker is installed and running
docker --version
docker-compose --version

# Ensure you have sufficient disk space (at least 10GB)
df -h
```

### Step 2: Configure Environment
```bash
# If you haven't already, copy the example environment file
cp .env.example .env

# Edit .env with your Bitcoin RPC credentials
nano .env
```

### Step 3: Build and Run Services

#### Option A: Using the Helper Script (Recommended)
```bash
# Make the script executable (already done)
chmod +x run.sh

# Run the setup script
./run.sh

# Select option 1 to build and start all services
```

#### Option B: Manual Docker Compose Commands
```bash
# Build all services from scratch
docker-compose build --no-cache

# Start all services
docker-compose up -d

# View logs
docker-compose logs -f
```

### Step 4: Verify Services are Running
```bash
# Check service status
docker-compose ps

# Check MongoDB connection
docker exec -it llh_mongodb mongosh --eval "db.adminCommand('ping')"

# Check individual service logs
docker-compose logs crawler
docker-compose logs attack
docker-compose logs analysis
```

## Troubleshooting

### Issue: g6k Import Errors
If you see errors related to g6k imports:
1. Rebuild the analysis service: `docker-compose build --no-cache analysis`
2. Check the Dockerfile build logs for any errors during g6k installation

### Issue: MongoDB Connection Failed
If services can't connect to MongoDB:
1. Ensure MongoDB is healthy: `docker-compose ps`
2. Check MongoDB logs: `docker-compose logs mongodb`
3. Restart MongoDB: `docker-compose restart mongodb`

### Issue: SageMath Compatibility
If you encounter SageMath-related errors:
1. The Dockerfile now uses SageMath 10.1 which has better compatibility
2. Ensure the analysis service is using the custom Dockerfile, not the Python image

### Issue: Memory Issues
If services are running out of memory:
1. Increase Docker memory allocation in Docker Desktop settings
2. Reduce the number of threads in config.yaml under g6k_params

### Issue: Build Failures
If the build fails:
1. Clean up Docker resources: `docker system prune -a`
2. Remove volumes: `docker volume prune`
3. Try building again with: `docker-compose build --no-cache`

## Monitoring and Logs

### Real-time Monitoring
```bash
# Monitor all services
docker-compose logs -f

# Monitor specific service
docker-compose logs -f analysis

# Check resource usage
docker stats
```

### Log Files
Logs are also written to files as configured in config.yaml:
- Location: `logs/llh.log`
- Level: INFO (can be changed in config.yaml)

## Performance Tuning

### G6K Parameters
Edit `config/config.yaml` to tune g6k performance:
```yaml
g6k_params:
  threads: 4  # Adjust based on CPU cores
  default_sieve: "bgj1"  # Options: "gauss", "bgj1", "hk3"
```

### MongoDB Performance
For better performance with large datasets:
1. Ensure MongoDB has sufficient memory
2. Add indexes as needed (handled automatically by the application)

## Next Steps

Once all services are running:
1. The crawler will begin ingesting blockchain data
2. The attack service will process signatures
3. The analysis service will identify patterns
4. Check `docker-compose logs -f` to monitor progress

For development and testing:
1. Run tests: `docker-compose run --rm analysis pytest`
2. Access MongoDB: `docker exec -it llh_mongodb mongosh llh_db`

## Support

If you continue to experience issues:
1. Check the logs carefully for specific error messages
2. Ensure all environment variables are set correctly
3. Verify network connectivity for blockchain RPC access
4. Consider running services individually to isolate issues