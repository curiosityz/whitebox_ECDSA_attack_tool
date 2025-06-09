FROM sagemath/sagemath:10.1

USER root

# Install system dependencies for G6K
RUN apt-get update && \
    apt-get install -y build-essential git python3-dev libgmp-dev libmpfr-dev libmpc-dev \
    automake autoconf libtool m4 perl netcat-traditional pkg-config libfplll-dev \
    libqd-dev && \
    rm -rf /var/lib/apt/lists/*

# Install Python dependencies (let Sage 10.x handle fpylll)
RUN sage -pip install --no-cache-dir numpy==1.24.4 Cython==0.29.36 cysignals && \
    sage -pip install --no-cache-dir wheel setuptools python-bitcoinlib ecdsa

# Install G6K from source
RUN cd /tmp && \
    git clone https://github.com/fplll/g6k.git && \
    cd g6k && \
    git submodule update --init --recursive && \
    sage -pip install -r requirements.txt && \
    sage -python setup.py build_ext --inplace && \
    sage -pip install -e .

WORKDIR /app
COPY . /app/

# Install project dependencies
RUN sage -pip install --no-cache-dir -r requirements.txt

# Set Python path to include the current directory
ENV PYTHONPATH="/app:$PYTHONPATH"

CMD ["sage", "-python", "-m", "src.llh.analysis.main"]