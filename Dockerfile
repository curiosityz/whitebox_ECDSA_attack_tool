FROM fplll/sagemath-g6k:latest as builder

WORKDIR /app

# Copy all files needed for building the package
COPY pyproject.toml .
COPY README.md .
COPY src/ src/

# Install dependencies
RUN pip install --no-cache-dir .[test]

# Final stage
FROM fplll/sagemath-g6k:latest

WORKDIR /app

# Copy only the necessary files from the builder stage
COPY --from=builder /usr/local/lib/python3.*/site-packages/ /usr/local/lib/python3.*/site-packages/
COPY --from=builder /usr/local/bin/ /usr/local/bin/

# Copy the rest of the application
COPY . .

# Set the default command
CMD ["/bin/bash"] 