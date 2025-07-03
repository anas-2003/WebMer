#!/bin/bash
set -e

INSTALL_DIR="/opt/webmer"
VENV_DIR="${INSTALL_DIR}/venv"
COMMAND_NAME="webmer"
SYMLINK_PATH="/usr/local/bin/${COMMAND_NAME}"

echo "Starting WebMer installation..."

# 1. Sudo check
if [ "$EUID" -ne 0 ]; then
  echo "This script must be run with sudo."
  exit 1
fi

# 2. System dependencies
echo "[*] Installing system dependencies..."
apt-get update
apt-get install -y python3-pip python3-venv git

# 3. Prepare installation directory
echo "[*] Preparing installation directory at ${INSTALL_DIR}..."
if [ -d "$INSTALL_DIR" ]; then
    rm -rf "$INSTALL_DIR"
fi
# Copy source code to the final location
mkdir -p "$INSTALL_DIR"
cp -r ./* "$INSTALL_DIR/"

# 4. Install using pip in editable mode inside the venv
echo "[*] Installing WebMer..."
cd "$INSTALL_DIR"
python3 -m venv venv

# IMPORTANT: Install requirements first, then the package
"${VENV_DIR}/bin/pip" install --upgrade pip
"${VENV_DIR}/bin/pip" install -r requirements.txt
# The '.' installs the package defined by setup.py in the current dir
"${VENV_DIR}/bin/pip" install .

# 5. Create symlink
echo "[*] Creating system-wide command..."
if [ -L "$SYMLINK_PATH" ]; then
    rm "$SYMLINK_PATH"
fi
ln -s "${VENV_DIR}/bin/${COMMAND_NAME}" "$SYMLINK_PATH"

echo "Installation complete!"
echo "You can now run WebMer by typing: webmer -u <URL>"
