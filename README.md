# Ledger Lattice Hunter (LLH)

An autonomous agent designed to identify and exploit nonce leakage vulnerabilities in ECDSA signatures across public ledgers.

## Features

- Distributed blockchain data crawling
- Advanced lattice-based attack implementation
- Intelligent vulnerability fingerprinting
- Scalable worker architecture
- Real-time vulnerability detection
- **Intelligent Attack Prioritization**: Uses meta-analysis of past vulnerabilities to prioritize new attack targets, creating a feedback loop that makes the hunt more efficient over time.

## Prerequisites

- Python 3.10+
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
-   `analysis`: A service that runs periodically to analyze found vulnerabilities and update the list of high-priority attack targets.

### 3. Monitoring the System

You can monitor the logs of each service to see their progress:

-   **Crawler Logs**: `docker-compose logs -f crawler`
-   **Attack Logs**: `docker-compose logs -f attack`
-   **Analysis Logs**: `docker-compose logs -f analysis`

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
- **Analysis and Prioritization**: Configure the feedback loop, including the criteria for what makes a target "high-priority" (e.g., key age, signature count).

## Usage

Once the services are running with `docker-compose up`, the crawler and attack manager will run automatically.

To run a one-off analysis and generate a report, you can execute the analysis service directly:

```bash
docker-compose run --rm analysis
```

This will connect to the database, perform the analysis, print a report to the console, and update the priority queue for the attack manager.

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