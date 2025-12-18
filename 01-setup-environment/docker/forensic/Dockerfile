# ============================================
# Dockerfile untuk Forensic Workstation
# Container untuk analisis forensik digital
# ============================================

FROM python:3.10-slim

LABEL maintainer="Forensic Lab"
LABEL description="Forensic workstation for digital forensics simulation"

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    wget \
    file \
    xxd \
    hexedit \
    binwalk \
    foremost \
    sleuthkit \
    dc3dd \
    exiftool \
    vim \
    nano \
    jq \
    tree \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
RUN pip install --no-cache-dir \
    pandas \
    matplotlib \
    requests \
    beautifulsoup4 \
    colorama \
    tabulate \
    rich \
    python-dateutil \
    jinja2 \
    plotly

# Create working directories
RUN mkdir -p /forensic /evidence /reports

# Set working directory
WORKDIR /forensic

# Keep container running
CMD ["tail", "-f", "/dev/null"]
