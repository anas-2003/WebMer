#!/bin/bash

# ================================================
# WebMer System Tools Installation Script
# Install all required system tools for real attacks
# ================================================

echo "=========================================="
echo "  WebMer Real Attack Tools Installation"
echo "=========================================="
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Check if running as root
if [[ $EUID -eq 0 ]]; then
   echo -e "${RED}[!] This script should not be run as root${NC}"
   echo -e "${YELLOW}[*] Please run as normal user (sudo will be used when needed)${NC}"
   exit 1
fi

# Function to print status
print_status() {
    echo -e "${BLUE}[*] $1${NC}"
}

print_success() {
    echo -e "${GREEN}[+] $1${NC}"
}

print_error() {
    echo -e "${RED}[!] $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}[*] $1${NC}"
}

# Check internet connection
print_status "Checking internet connection..."
if ping -c 1 google.com &> /dev/null; then
    print_success "Internet connection verified"
else
    print_error "No internet connection available"
    exit 1
fi

# Update system packages
print_status "Updating system packages..."
sudo apt-get update -qq
if [ $? -eq 0 ]; then
    print_success "System packages updated"
else
    print_error "Failed to update system packages"
    exit 1
fi

# Install basic development tools
print_status "Installing basic development tools..."
sudo apt-get install -y \
    build-essential \
    git \
    curl \
    wget \
    unzip \
    software-properties-common \
    apt-transport-https \
    ca-certificates \
    gnupg \
    lsb-release \
    python3-dev \
    python3-pip \
    python3-venv

print_success "Basic development tools installed"

# Install network and security libraries
print_status "Installing network and security libraries..."
sudo apt-get install -y \
    libpcap-dev \
    libffi-dev \
    libssl-dev \
    libxml2-dev \
    libxslt1-dev \
    libjpeg-dev \
    zlib1g-dev \
    libncurses5-dev \
    libreadline-dev \
    libbz2-dev \
    libsqlite3-dev \
    libgdbm-dev \
    libdb-dev \
    libexpat1-dev \
    liblzma-dev \
    tk-dev

print_success "Network and security libraries installed"

# Install Aircrack-ng suite for WiFi attacks
print_status "Installing Aircrack-ng suite..."
sudo apt-get install -y aircrack-ng
if command -v aircrack-ng &> /dev/null; then
    print_success "Aircrack-ng suite installed successfully"
else
    print_error "Failed to install Aircrack-ng suite"
fi

# Install hashcat for GPU cracking
print_status "Installing hashcat..."
sudo apt-get install -y hashcat
if command -v hashcat &> /dev/null; then
    print_success "Hashcat installed successfully"
else
    print_warning "Hashcat installation may have failed - trying alternative method..."
    # Try installing from snapcraft
    sudo snap install hashcat
fi

# Install hcxtools for PMKID attacks
print_status "Installing hcxtools..."
sudo apt-get install -y hcxtools
if command -v hcxdumptool &> /dev/null; then
    print_success "hcxtools installed successfully"
else
    print_warning "hcxtools not available in repository - installing from source..."
    cd /tmp
    git clone https://github.com/ZerBea/hcxtools.git
    cd hcxtools
    make
    sudo make install
    cd ~
    rm -rf /tmp/hcxtools
fi

# Install nmap for network scanning
print_status "Installing nmap..."
sudo apt-get install -y nmap
if command -v nmap &> /dev/null; then
    print_success "Nmap installed successfully"
else
    print_error "Failed to install nmap"
fi

# Install masscan for fast port scanning
print_status "Installing masscan..."
sudo apt-get install -y masscan
if command -v masscan &> /dev/null; then
    print_success "Masscan installed successfully"
else
    print_warning "Masscan not available - installing from source..."
    cd /tmp
    git clone https://github.com/robertdavidgraham/masscan
    cd masscan
    make
    sudo make install
    cd ~
    rm -rf /tmp/masscan
fi

# Install john the ripper for password cracking
print_status "Installing John the Ripper..."
sudo apt-get install -y john
if command -v john &> /dev/null; then
    print_success "John the Ripper installed successfully"
else
    print_error "Failed to install John the Ripper"
fi

# Install hydra for brute force attacks
print_status "Installing Hydra..."
sudo apt-get install -y hydra
if command -v hydra &> /dev/null; then
    print_success "Hydra installed successfully"
else
    print_error "Failed to install Hydra"
fi

# Install sqlmap for SQL injection
print_status "Installing sqlmap..."
sudo apt-get install -y sqlmap
if command -v sqlmap &> /dev/null; then
    print_success "Sqlmap installed successfully"
else
    print_warning "Sqlmap not available in repository - installing from source..."
    cd /opt
    sudo git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git sqlmap-dev
    sudo ln -sf /opt/sqlmap-dev/sqlmap.py /usr/local/bin/sqlmap
    print_success "Sqlmap installed from source"
fi

# Install nikto for web vulnerability scanning
print_status "Installing Nikto..."
sudo apt-get install -y nikto
if command -v nikto &> /dev/null; then
    print_success "Nikto installed successfully"
else
    print_error "Failed to install Nikto"
fi

# Install dirb for directory brute forcing
print_status "Installing dirb..."
sudo apt-get install -y dirb
if command -v dirb &> /dev/null; then
    print_success "Dirb installed successfully"
else
    print_error "Failed to install dirb"
fi

# Install gobuster for directory/file brute forcing
print_status "Installing gobuster..."
sudo apt-get install -y gobuster
if command -v gobuster &> /dev/null; then
    print_success "Gobuster installed successfully"
else
    print_warning "Gobuster not available - installing from GitHub..."
    # Install Go first if not present
    if ! command -v go &> /dev/null; then
        sudo apt-get install -y golang-go
    fi
    go install github.com/OJ/gobuster/v3@latest
    sudo cp ~/go/bin/gobuster /usr/local/bin/
fi

# Install wfuzz for web application fuzzing
print_status "Installing wfuzz..."
sudo apt-get install -y wfuzz
if command -v wfuzz &> /dev/null; then
    print_success "Wfuzz installed successfully"
else
    print_error "Failed to install wfuzz"
fi

# Install sublist3r for subdomain enumeration
print_status "Installing Sublist3r..."
cd /opt
sudo git clone https://github.com/aboul3la/Sublist3r.git
cd Sublist3r
sudo pip3 install -r requirements.txt
sudo ln -sf /opt/Sublist3r/sublist3r.py /usr/local/bin/sublist3r
print_success "Sublist3r installed successfully"

# Install whatweb for web technology identification
print_status "Installing WhatWeb..."
sudo apt-get install -y whatweb
if command -v whatweb &> /dev/null; then
    print_success "WhatWeb installed successfully"
else
    print_error "Failed to install WhatWeb"
fi

# Install burpsuite community (optional)
print_status "Checking for Burp Suite Community..."
if ! command -v burpsuite &> /dev/null; then
    print_warning "Burp Suite not found - you may want to install it manually"
    print_warning "Download from: https://portswigger.net/burp/communitydownload"
fi

# Install metasploit framework (optional but powerful)
print_status "Checking for Metasploit Framework..."
if ! command -v msfconsole &> /dev/null; then
    print_warning "Metasploit not found"
    read -p "Do you want to install Metasploit Framework? (y/N): " install_msf
    if [[ $install_msf =~ ^[Yy]$ ]]; then
        print_status "Installing Metasploit Framework..."
        curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall
        chmod 755 msfinstall
        ./msfinstall
        rm msfinstall
        print_success "Metasploit Framework installed"
    fi
fi

# Create wordlists directory
print_status "Setting up wordlists..."
sudo mkdir -p /usr/share/wordlists
cd /usr/share/wordlists

# Download SecLists wordlists
if [ ! -d "SecLists" ]; then
    print_status "Downloading SecLists wordlists..."
    sudo git clone https://github.com/danielmiessler/SecLists.git
    print_success "SecLists wordlists downloaded"
fi

# Download rockyou.txt if not present
if [ ! -f "rockyou.txt" ]; then
    print_status "Downloading rockyou.txt wordlist..."
    sudo wget https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt
    print_success "Rockyou.txt wordlist downloaded"
fi

# Set permissions for wireless tools
print_status "Setting up wireless interface permissions..."
sudo usermod -a -G netdev $USER
print_warning "You may need to log out and back in for wireless permissions to take effect"

# Install wireshark for packet analysis (optional)
read -p "Do you want to install Wireshark for packet analysis? (y/N): " install_wireshark
if [[ $install_wireshark =~ ^[Yy]$ ]]; then
    print_status "Installing Wireshark..."
    sudo apt-get install -y wireshark
    sudo usermod -a -G wireshark $USER
    print_success "Wireshark installed"
    print_warning "You may need to log out and back in for Wireshark permissions to take effect"
fi

# Final system cleanup
print_status "Cleaning up..."
sudo apt-get autoremove -y
sudo apt-get autoclean

# Summary
echo ""
echo "=========================================="
echo "           INSTALLATION COMPLETE"
echo "=========================================="
echo ""
print_success "All required tools have been installed!"
print_warning "IMPORTANT NOTES:"
echo ""
echo "1. Some tools may require root privileges to run"
echo "2. Always ensure you have authorization before testing"
echo "3. Reboot or log out/in for group permissions to take effect"
echo "4. WiFi attacks require a compatible wireless adapter"
echo "5. GPU cracking requires compatible graphics drivers"
echo ""
print_warning "Installed Tools Summary:"
echo "• Aircrack-ng Suite (WiFi attacks)"
echo "• Hashcat (GPU password cracking)"
echo "• hcxtools (PMKID attacks)"
echo "• Nmap (Network scanning)"
echo "• Masscan (Fast port scanning)"
echo "• John the Ripper (Password cracking)"
echo "• Hydra (Brute force attacks)"
echo "• Sqlmap (SQL injection)"
echo "• Nikto (Web vulnerability scanning)"
echo "• Gobuster/Dirb (Directory brute forcing)"
echo "• Wfuzz (Web fuzzing)"
echo "• Sublist3r (Subdomain enumeration)"
echo "• WhatWeb (Technology identification)"
echo "• SecLists & Rockyou wordlists"
echo ""
print_success "WebMer is now ready for real penetration testing!"
print_error "USE ONLY WITH PROPER AUTHORIZATION!"
