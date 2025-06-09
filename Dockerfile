FROM sagemath/sagemath:10.1

USER root

# Install system dependencies
RUN apt-get update && \
    apt-get install -y build-essential git python3-dev libgmp-dev libmpfr-dev libmpc-dev automake autoconf libtool m4 perl netcat-traditional && \
    rm -rf /var/lib/apt/lists/*

# Install Python dependencies (let Sage 10.x handle fpylll/g6k)
RUN sage -pip install --no-cache-dir numpy==1.24.4 Cython==0.29.36 cysignals && \
    sage -pip install --no-cache-dir wheel setuptools python-bitcoinlib ecdsa

WORKDIR /app
COPY . /app/

# Install project dependencies
RUN sage -pip install --no-cache-dir -r requirements.txt

# Set Python path to include the current directory
ENV PYTHONPATH="/app:$PYTHONPATH"

CMD ["sage", "-python", "-m", "src.llh.analysis.main"]