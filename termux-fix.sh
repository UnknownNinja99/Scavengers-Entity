#!/bin/bash
# Termux Entity Installation Script
# Run this in Termux terminal

echo "🚀 Installing Entity Cybersecurity Toolkit for Termux..."
echo "=============================================="

# Update Termux first
echo "📦 Updating Termux packages..."
pkg update -y
pkg upgrade -y

# Install system dependencies
echo "🔧 Installing system dependencies..."
pkg install python git -y

# Upgrade pip
echo "⬆️  Upgrading pip..."
pip install --upgrade pip

# Install Python packages one by one for better error handling
echo "🐍 Installing Python packages..."

packages=(
    "requests"
    "rich" 
    "python-dateutil"
    "urllib3"
    "phonenumbers"
    "python-whois"
    "pyfiglet"
)

for package in "${packages[@]}"; do
    echo "Installing $package..."
    pip install "$package"
    if [ $? -eq 0 ]; then
        echo "✅ $package installed successfully"
    else
        echo "❌ Failed to install $package - continuing anyway..."
    fi
done

echo ""
echo "🎯 Installation complete!"
echo "To run Entity, use: python main.py"
echo ""

# Test if main packages are available
echo "🧪 Testing imports..."
python -c "
try:
    import requests
    import rich
    print('✅ Core packages imported successfully!')
except ImportError as e:
    print(f'❌ Import error: {e}')
"
