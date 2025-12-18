# ============================================
# Dockerfile untuk Attacker Container
# Kali-like environment dengan tools penetration testing
# ============================================

FROM python:3.10-slim

LABEL maintainer="Forensic Lab"
LABEL description="Attacker container for digital forensics simulation"

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    wget \
    nmap \
    netcat-openbsd \
    dnsutils \
    iputils-ping \
    net-tools \
    tcpdump \
    git \
    vim \
    nano \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
RUN pip install --no-cache-dir \
    requests \
    beautifulsoup4 \
    colorama \
    tabulate \
    mysql-connector-python \
    python-dateutil

# Create working directories
RUN mkdir -p /attack_scripts /loot /results

# Set working directory
WORKDIR /attack_scripts

# Keep container running
CMD ["tail", "-f", "/dev/null"]
