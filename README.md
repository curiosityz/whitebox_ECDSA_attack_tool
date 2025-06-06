# Ledger Lattice Hunter (LLH)

An autonomous agent designed to identify and exploit nonce leakage vulnerabilities in ECDSA signatures across public ledgers.

## Features

- Distributed blockchain data crawling
- Advanced lattice-based attack implementation
- Intelligent vulnerability fingerprinting
- Scalable worker architecture
- Real-time vulnerability detection

## Prerequisites

- Python 3.8+
- Docker & Docker Compose
- MongoDB
- A Bitcoin RPC node (e.g., via ChainStack)

## Getting Started

### 1. Environment Setup

First, clone the repository and create an environment file from the example:

```bash
git clone https://github.com/yourusername/ledger-lattice-hunter.git
cd ledger-lattice-hunter
cp .env.example .env
```

Next, open the `.env` file and fill in the required credentials for your Bitcoin RPC node and any other custom settings.

### 2. Build and Run with Docker

This project is designed to be run with Docker Compose, which orchestrates the necessary services.

To build the Docker images and start the services, run:

```bash
docker-compose up --build
```

This command will start three main services:
-   `mongodb`: The database instance for storing signatures and results.
-   `crawler`: The service that connects to the Bitcoin blockchain, ingests transactions, and stores signatures in the database.
-   `attack`: The service that continuously queries the database for attackable public keys and runs the lattice attack against them.

### 3. Monitoring the System

You can monitor the logs of each service to see their progress:

-   **Crawler Logs**: `docker-compose logs -f crawler`
-   **Attack Logs**: `docker-compose logs -f attack`

### 4. Stopping the System

To stop all running services, press `Ctrl+C` in the terminal where `docker-compose up` is running, or run the following command from another terminal:

```bash
docker-compose down
```

## Configuration

The project uses a YAML configuration file located at `config/config.yaml`. Key configuration sections include:

- ChainStack API settings
- Database connection details
- Crawler parameters
- Lattice attack configuration
- Worker deployment settings

## Usage

1. Start the crawler:
```bash
python -m llh.crawler.main
```

2. Launch the lattice attack workers:
```bash
python -m llh.lattice.worker
```

3. Monitor results:
```bash
python -m llh.analysis.monitor
```

## Project Structure

```
llh/
├── crawler/         # Blockchain data crawling
├── database/        # Database models and operations
├── lattice/         # Lattice attack implementation
├── analysis/        # Vulnerability analysis
└── utils/           # Shared utilities
```

## Testing

Run the test suite:
```bash
pytest
```

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Contributing

1. Fork the repository
2. Create your feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request 