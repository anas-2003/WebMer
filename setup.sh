#!/bin/bash

# WebMer - Advanced Web Security Platform Installer (v2.0)
# Developed by Anas Erami
# This script prepares the environment for web and API penetration testing.

# --- Configuration ---
VENV_DIR="venv"
REQUIREMENTS_FILE="requirements.txt"

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color


set -e

printf "${YELLOW}====================================================${NC}\n"
printf "${YELLOW}        Welcome to the WebMer Setup Script          ${NC}\n"
printf "${YELLOW}====================================================${NC}\n\n"

printf "This script will install system packages and set up a Python environment.\n"
read -p "Do you want to continue? (y/n) " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    printf "${RED}Setup cancelled by user.${NC}\n"
    exit 1
fi


printf "\n${YELLOW}[*] Step 1: Installing system-level dependencies (requires sudo)...${NC}\n"
sudo apt-get update
sudo apt-get install -y python3-pip python3-venv git
printf "${GREEN}[+] System dependencies installed successfully.${NC}\n"


printf "\n${YELLOW}[*] Step 2: Setting up Python virtual environment in './${VENV_DIR}'...${NC}\n"
if [ ! -d "$VENV_DIR" ]; then
    python3 -m venv $VENV_DIR
    printf "    Virtual environment created.${NC}\n"
else
    printf "    Virtual environment already exists.${NC}\n"
fi


source "${VENV_DIR}/bin/activate"
printf "${GREEN}[+] Virtual environment activated for setup.${NC}\n"


printf "\n${YELLOW}[*] Step 3: Installing Python libraries from '${REQUIREMENTS_FILE}'...${NC}\n"

# Upgrade pip
pip install --upgrade pip


if [ ! -f "$REQUIREMENTS_FILE" ]; then
    printf "${RED}[!] Error: '${REQUIREMENTS_FILE}' not found. Cannot continue.${NC}\n"
    deactivate
    exit 1
fi
pip install -r $REQUIREMENTS_FILE

printf "${GREEN}[+] All Python libraries installed successfully.${NC}\n"
deactivate # Deactivate after setup is done

# --- 4. Final Instructions ---
printf "\n${GREEN}====================================================${NC}\n"
printf "${GREEN}            SETUP COMPLETE! READY TO RUN.             ${NC}\n"
printf "${GREEN}====================================================${NC}\n\n"
printf "${YELLOW}To run WebMer, use the './run.sh' script.${NC}\n"
printf "${YELLOW}Example:${NC} ./run.sh -u https://example.com\n\n"
printf "Make sure to give it execution permissions first:\n"
printf "${CYAN}chmod +x run.sh${NC}\n\n"
