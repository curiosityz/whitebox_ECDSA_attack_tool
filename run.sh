#!/bin/bash

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}Ledger Lattice Hunter - Setup and Run Script${NC}"
echo "=============================================="

# Check if .env file exists
if [ ! -f .env ]; then
    echo -e "${YELLOW}Warning: .env file not found. Creating from .env.example...${NC}"
    cp .env.example .env
    echo -e "${RED}Please edit .env file with your credentials before continuing.${NC}"
    exit 1
fi

# Check if wait-for-it.sh is executable
if [ ! -x wait-for-it.sh ]; then
    echo -e "${YELLOW}Making wait-for-it.sh executable...${NC}"
    chmod +x wait-for-it.sh
fi

# Function to check if Docker is running
check_docker() {
    if ! docker info > /dev/null 2>&1; then
        echo -e "${RED}Docker is not running. Please start Docker and try again.${NC}"
        exit 1
    fi
}

# Function to clean up old containers and images
cleanup() {
    echo -e "${YELLOW}Cleaning up old containers and volumes...${NC}"
    docker-compose down -v
    docker system prune -f
}

# Main menu
echo ""
echo "Select an option:"
echo "1) Build and start all services (fresh start)"
echo "2) Start services (using existing build)"
echo "3) Stop all services"
echo "4) View logs (all services)"
echo "5) View logs (specific service)"
echo "6) Rebuild specific service"
echo "7) Clean up (remove containers and volumes)"
echo "8) Exit"
echo ""
read -p "Enter option (1-8): " option

check_docker

case $option in
    1)
        echo -e "${GREEN}Building and starting all services...${NC}"
        docker-compose build --no-cache
        docker-compose up -d
        echo -e "${GREEN}Services started. Use 'docker-compose logs -f' to view logs.${NC}"
        ;;
    2)
        echo -e "${GREEN}Starting services...${NC}"
        docker-compose up -d
        echo -e "${GREEN}Services started. Use 'docker-compose logs -f' to view logs.${NC}"
        ;;
    3)
        echo -e "${YELLOW}Stopping all services...${NC}"
        docker-compose down
        echo -e "${GREEN}Services stopped.${NC}"
        ;;
    4)
        echo -e "${GREEN}Showing logs for all services (Ctrl+C to exit)...${NC}"
        docker-compose logs -f
        ;;
    5)
        echo "Available services: crawler, attack, analysis, mongodb"
        read -p "Enter service name: " service
        echo -e "${GREEN}Showing logs for $service (Ctrl+C to exit)...${NC}"
        docker-compose logs -f $service
        ;;
    6)
        echo "Available services: crawler, attack, analysis"
        read -p "Enter service name to rebuild: " service
        echo -e "${YELLOW}Rebuilding $service...${NC}"
        docker-compose build --no-cache $service
        docker-compose up -d $service
        echo -e "${GREEN}$service rebuilt and restarted.${NC}"
        ;;
    7)
        read -p "This will remove all containers and volumes. Are you sure? (y/N): " confirm
        if [[ $confirm == [yY] ]]; then
            cleanup
            echo -e "${GREEN}Cleanup complete.${NC}"
        else
            echo -e "${YELLOW}Cleanup cancelled.${NC}"
        fi
        ;;
    8)
        echo -e "${GREEN}Exiting...${NC}"
        exit 0
        ;;
    *)
        echo -e "${RED}Invalid option. Please try again.${NC}"
        exit 1
        ;;
esac

# Show service status
echo ""
echo -e "${GREEN}Service Status:${NC}"
docker-compose ps