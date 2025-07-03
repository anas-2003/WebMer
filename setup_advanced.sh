#!/bin/bash

# ================================================
# WebMer Advanced Setup Script
# Developed by Anas Erami
# ================================================

set -e

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}================================================${NC}"
echo -e "${YELLOW}  WebMer Advanced Security Platform Setup${NC}"
echo -e "${BLUE}================================================${NC}"

# Check if running as root
if [[ $EUID -eq 0 ]]; then
   echo -e "${RED}This script should not be run as root${NC}"
   echo -e "${YELLOW}Please run as regular user (will ask for sudo when needed)${NC}"
   exit 1
fi

echo -e "${YELLOW}[*] Updating system packages...${NC}"
sudo apt-get update

echo -e "${YELLOW}[*] Installing system dependencies...${NC}"
sudo apt-get install -y \
    python3 \
    python3-pip \
    python3-venv \
    python3-dev \
    build-essential \
    libpcap-dev \
    libffi-dev \
    libssl-dev \
    libxml2-dev \
    libxslt-dev \
    libjpeg-dev \
    zlib1g-dev \
    git \
    nmap \
    whois \
    dnsutils \
    curl \
    wget \
    tcpdump \
    aircrack-ng \
    john \
    hashcat \
    sqlmap

echo -e "${YELLOW}[*] Creating virtual environment...${NC}"
python3 -m venv venv

echo -e "${YELLOW}[*] Activating virtual environment...${NC}"
source venv/bin/activate

echo -e "${YELLOW}[*] Upgrading pip...${NC}"
pip install --upgrade pip setuptools wheel

echo -e "${YELLOW}[*] Installing Python requirements...${NC}"
echo -e "${BLUE}This may take a while depending on your internet connection...${NC}"

# Install requirements in stages to handle potential failures
echo -e "${YELLOW}[*] Stage 1: Core libraries...${NC}"
pip install aiohttp aiofiles httpx requests urllib3 beautifulsoup4 lxml colorama PyYAML

echo -e "${YELLOW}[*] Stage 2: Security libraries...${NC}"
pip install cryptography pycryptodome pyopenssl certifi bcrypt

echo -e "${YELLOW}[*] Stage 3: Network libraries...${NC}"
pip install dnspython netaddr paramiko

echo -e "${YELLOW}[*] Stage 4: Advanced libraries...${NC}"
pip install numpy scipy pandas matplotlib

echo -e "${YELLOW}[*] Stage 5: Security tools...${NC}"
pip install shodan wafw00f sslyze

echo -e "${YELLOW}[*] Stage 6: Optional advanced tools (may fail on some systems)...${NC}"
pip install scapy || echo -e "${YELLOW}Warning: scapy installation failed${NC}"
pip install pwntools || echo -e "${YELLOW}Warning: pwntools installation failed${NC}"
pip install mitmproxy || echo -e "${YELLOW}Warning: mitmproxy installation failed${NC}"

echo -e "${YELLOW}[*] Installing remaining requirements...${NC}"
pip install -r requirements.txt || echo -e "${YELLOW}Some packages may have failed to install${NC}"

echo -e "${YELLOW}[*] Creating necessary directories...${NC}"
mkdir -p modules advanced_modules payloads sessions logs wordlists reports

echo -e "${YELLOW}[*] Setting up configuration files...${NC}"
if [ ! -f config.yaml ]; then
    cp config.yaml.example config.yaml 2>/dev/null || echo -e "${YELLOW}config.yaml.example not found${NC}"
fi

echo -e "${YELLOW}[*] Setting executable permissions...${NC}"
chmod +x webmer.py
chmod +x run.sh

echo -e "${YELLOW}[*] Creating symlink for global access...${NC}"
sudo ln -sf "$(pwd)/webmer.py" /usr/local/bin/webmer 2>/dev/null || echo -e "${YELLOW}Warning: Could not create global symlink${NC}"

echo -e "${YELLOW}[*] Testing installation...${NC}"
python webmer.py --help || echo -e "${RED}Error: WebMer test failed${NC}"

echo -e "${GREEN}================================================${NC}"
echo -e "${GREEN}     WEBMER SETUP COMPLETED SUCCESSFULLY!${NC}"
echo -e "${GREEN}================================================${NC}"
echo -e "${YELLOW}Usage Examples:${NC}"
echo -e "${BLUE}  Basic scan:${NC} python webmer.py --url https://example.com"
echo -e "${BLUE}  Advanced scan:${NC} python webmer.py --url https://example.com --ddos --tls-audit --network-scan --vuln-scan"
echo -e "${BLUE}  Global usage:${NC} webmer --url https://example.com"
echo ""
echo -e "${YELLOW}Activate environment:${NC} source venv/bin/activate"
echo -e "${YELLOW}Configuration:${NC} Edit config.yaml file"
echo ""
echo -e "${RED}⚠️  WARNING: Use only on authorized targets!${NC}"
echo -e "${GREEN}================================================${NC}"
