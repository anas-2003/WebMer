#!/bin/bash

# WebMer - Runner Script
# Developed by Anas Erami
# Use this script to run the framework after setup.

# --- Configuration ---
VENV_DIR="venv"
PYTHON_SCRIPT="webmer.py" # The main Python file is now webmer.py


if [ ! -d "$VENV_DIR" ]; then
    echo "Virtual environment not found. Please run the 'setup.sh' script first."
    exit 1
fi

# --- Activate the virtual environment ---
source "${VENV_DIR}/bin/activate"

# --- Run the Python script ---
# The Python script will handle 'sudo' internally if ever needed for any command.
# "$@" passes all command-line arguments (like -u, -v, --proxy) to the Python script.
python "$PYTHON_SCRIPT" "$@"

# --- Deactivate on exit ---
deactivate
