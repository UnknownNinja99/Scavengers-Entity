#!/bin/bash
# Entity Launcher Script for Linux
# This script automatically activates the virtual environment and runs Entity

# Get the directory where this script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Check if virtual environment exists
if [ ! -d "entity-env" ]; then
    echo "🚨 Virtual environment not found!"
    echo "Please run the installation first:"
    echo "python3 -m venv entity-env"
    echo "source entity-env/bin/activate"
    echo "pip install requests rich phonenumbers python-whois pyfiglet"
    exit 1
fi

# Activate virtual environment
echo "🔄 Activating Entity virtual environment..."
source entity-env/bin/activate

# Check if packages are installed
if ! python -c "import requests, rich, phonenumbers, whois, pyfiglet" 2>/dev/null; then
    echo "🚨 Missing dependencies! Installing..."
    pip install requests rich phonenumbers python-whois pyfiglet
fi

# Run Entity
echo "🚀 Starting Entity..."
python main.py

# Deactivate when done
deactivate
