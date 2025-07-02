#!/bin/bash

# Project Prometheus (WebMer) - System-wide Installer (v1.0)
# Developed by Anas Erami
# This script installs WebMer as a global command.

# --- Configuration ---
INSTALL_DIR="/opt/webmer"
VENV_DIR_INSIDE_INSTALL="${INSTALL_DIR}/venv"
COMMAND_NAME="webmer"
SYMLINK_PATH="/usr/local/bin/${COMMAND_NAME}"

# --- Colors ---
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

# --- Stop on any error ---
set -e

printf "${YELLOW}====================================================${NC}\n"
printf "${YELLOW}  Welcome to the Project Prometheus System Installer  ${NC}\n"
printf "${YELLOW}====================================================${NC}\n\n"

# --- 1. Check for Root Privileges ---
if [ "$EUID" -ne 0 ]; then
  printf "${RED}[!] This script must be run with sudo.${NC}\n"
  exit 1
fi

# --- 2. Install System Dependencies ---
printf "${YELLOW}[*] Installing system dependencies...${NC}\n"
apt-get update
apt-get install -y python3-pip python3-venv git

# --- 3. Prepare Installation Directory ---
printf "${YELLOW}[*] Preparing installation directory at ${INSTALL_DIR}...${NC}\n"
# Remove old installation if it exists
if [ -d "$INSTALL_DIR" ]; then
    rm -rf "$INSTALL_DIR"
fi
mkdir -p "$INSTALL_DIR"
# Copy project files to the installation directory
cp -r ./* "$INSTALL_DIR/"

# --- 4. Install the Application using setuptools ---
printf "${YELLOW}[*] Creating virtual environment and installing WebMer...${NC}\n"
cd "$INSTALL_DIR"
python3 -m venv venv
source "${VENV_DIR_INSIDE_INSTALL}/bin/activate"
pip install --upgrade pip
# The '.' tells pip to look for setup.py in the current directory
pip install .
deactivate
printf "${GREEN}[+] WebMer installed successfully into its environment.${NC}\n"

# --- 5. Create System-wide Symlink ---
printf "${YELLOW}[*] Creating system-wide command '${COMMAND_NAME}'...${NC}\n"
# Remove old symlink if it exists
if [ -L "$SYMLINK_PATH" ]; then
    rm "$SYMLINK_PATH"
fi
# Create new symlink
ln -s "${VENV_DIR_INSIDE_INSTALL}/bin/${COMMAND_NAME}" "$SYMLINK_PATH"
chmod +x "$SYMLINK_PATH"

# --- 6. Final Instructions ---
printf "\n${GREEN}====================================================${NC}\n"
printf "${GREEN}           INSTALLATION COMPLETE!                   ${NC}\n"
printf "${GREEN}====================================================${NC}\n\n"
printf "${YELLOW}You can now run WebMer from anywhere by typing:${NC}\n"
printf "${CYAN}${COMMAND_NAME} -u https://example.com${NC}\n\n"
