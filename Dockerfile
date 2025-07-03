# =================================================================
# WebMer v5.0 - Project Prometheus Docker Image
# Advanced Defense Evasion Engine Container
# =================================================================

FROM python:3.9-slim-bullseye

# Metadata
LABEL maintainer="Anas Erami <anaserami17@gmail.com>"
LABEL version="5.0"
LABEL description="WebMer - Advanced Defense Evasion Engine"
LABEL project="Project Prometheus"

# Environment variables
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1
ENV WEBMER_HOME=/opt/webmer
ENV PATH="$WEBMER_HOME/venv/bin:$PATH"

# Create non-root user for security
RUN groupadd -r webmer && useradd -r -g webmer -d $WEBMER_HOME -s /bin/bash webmer

# Install system dependencies
RUN apt-get update && apt-get install -y \
    # Build dependencies
    build-essential \
    gcc \
    g++ \
    make \
    cmake \
    # Network libraries
    libpcap-dev \
    libffi-dev \
    libssl-dev \
    # XML processing
    libxml2-dev \
    libxslt1-dev \
    # Image processing
    libjpeg-dev \
    zlib1g-dev \
    # Security tools
    nmap \
    masscan \
    nikto \
    sqlmap \
    # Network utilities
    curl \
    wget \
    netcat \
    dnsutils \
    whois \
    # Version control
    git \
    # Text processing
    jq \
    # Development tools
    vim \
    nano \
    # Clean up
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* \
    && rm -rf /tmp/* \
    && rm -rf /var/tmp/*

# Create application directory
RUN mkdir -p $WEBMER_HOME && chown -R webmer:webmer $WEBMER_HOME

# Switch to webmer user
USER webmer
WORKDIR $WEBMER_HOME

# Create virtual environment
RUN python3 -m venv venv

# Copy requirements first for better caching
COPY --chown=webmer:webmer requirements.txt .

# Install Python dependencies
RUN venv/bin/pip install --upgrade pip && \
    venv/bin/pip install wheel setuptools && \
    venv/bin/pip install -r requirements.txt

# Copy application files
COPY --chown=webmer:webmer . .

# Install WebMer
RUN venv/bin/pip install -e .

# Create necessary directories
RUN mkdir -p sessions logs reports tools

# Set permissions
RUN chmod +x webmer.py

# Download security wordlists (optional)
RUN mkdir -p tools/wordlists && \
    cd tools/wordlists && \
    wget -q https://github.com/danielmiessler/SecLists/archive/master.zip && \
    unzip -q master.zip && \
    mv SecLists-master SecLists && \
    rm master.zip || true

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD venv/bin/python -c "import webmer; print('WebMer is healthy')" || exit 1

# Default command
CMD ["venv/bin/webmer", "--help"]

# =================================================================
# Build and Run Instructions:
# 
# Build: docker build -t webmer:latest .
# Run:   docker run -it --rm webmer:latest
# Scan:  docker run -it --rm webmer:latest webmer --url https://example.com
# Shell: docker run -it --rm webmer:latest bash
# =================================================================
