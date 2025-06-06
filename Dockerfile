# Use a base image that has SageMath, fplll, and G6K pre-installed.
FROM fplll/sagemath-g6k:latest

# Set the working directory inside the container
WORKDIR /app

# Copy the entire project structure into the container
COPY . .

# Install Python dependencies from pyproject.toml
# The sage-env script sets up the environment to use Sage's Python and packages.
# We install with the [test] option to include testing libraries.
RUN . "/sage/local/bin/sage-env" && \
    pip install --no-cache-dir .[test]

# Set the default command to run when the container starts.
# This will be overridden in docker-compose.yml for specific services,
# but provides a useful default for interacting with the container.
CMD ["/bin/bash"] 