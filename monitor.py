#!/usr/bin/env python3
import docker
import time
import logging
import requests
from datetime import datetime
import os
from dotenv import load_dotenv

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('monitor.log'),
        logging.StreamHandler()
    ]
)

# Load environment variables
load_dotenv()

class SystemMonitor:
    def __init__(self):
        self.client = docker.from_env()
        self.services = ['llh_crawler', 'llh_attack', 'llh_analysis', 'llh_mongodb']
        self.health_endpoints = {
            'llh_crawler': 'http://localhost:8080/health',
            'llh_attack': 'http://localhost:8081/health',
            'llh_analysis': 'http://localhost:8082/health'
        }

    def check_container_health(self, container_name):
        try:
            container = self.client.containers.get(container_name)
            status = container.status
            health = container.attrs.get('State', {}).get('Health', {}).get('Status', 'unknown')
            
            if container_name in self.health_endpoints:
                try:
                    response = requests.get(self.health_endpoints[container_name], timeout=5)
                    api_health = response.status_code == 200
                except:
                    api_health = False
            else:
                api_health = True

            return {
                'status': status,
                'health': health,
                'api_health': api_health,
                'running': status == 'running' and health == 'healthy' and api_health
            }
        except Exception as e:
            logging.error(f"Error checking {container_name}: {str(e)}")
            return {'status': 'error', 'health': 'error', 'api_health': False, 'running': False}

    def check_mongodb_connection(self):
        try:
            response = requests.get('http://localhost:27017', timeout=5)
            return response.status_code == 200
        except:
            return False

    def monitor(self):
        while True:
            logging.info("=== System Health Check ===")
            all_healthy = True

            for service in self.services:
                health_info = self.check_container_health(service)
                status = "✅" if health_info['running'] else "❌"
                logging.info(f"{status} {service}:")
                logging.info(f"  Status: {health_info['status']}")
                logging.info(f"  Health: {health_info['health']}")
                if service in self.health_endpoints:
                    logging.info(f"  API Health: {'✅' if health_info['api_health'] else '❌'}")
                
                if not health_info['running']:
                    all_healthy = False
                    logging.warning(f"Service {service} is not healthy!")

            if not all_healthy:
                logging.warning("System is not fully healthy!")
            else:
                logging.info("All systems operational!")

            time.sleep(60)  # Check every minute

if __name__ == "__main__":
    monitor = SystemMonitor()
    monitor.monitor() 