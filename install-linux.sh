#!/bin/bash
# Linux Installation Script for Entity Cybersecurity Toolkit
# Compatible with Ubuntu, Debian, CentOS, Fedora, and other distributions

echo "🚀 Installing Entity Cybersecurity Toolkit for Linux..."
echo "=================================================="

# Detect the Linux distribution
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$NAME
    VER=$VERSION_ID
fi

echo "🔍 Detected OS: $OS"

# Update system packages
echo "📦 Updating system packages..."
if command -v apt-get &> /dev/null; then
    # Debian/Ubuntu
    sudo apt-get update
    sudo apt-get install -y python3 python3-pip git curl wget
elif command -v yum &> /dev/null; then
    # CentOS/RHEL
    sudo yum update -y
    sudo yum install -y python3 python3-pip git curl wget
elif command -v dnf &> /dev/null; then
    # Fedora
    sudo dnf update -y
    sudo dnf install -y python3 python3-pip git curl wget
elif command -v pacman &> /dev/null; then
    # Arch Linux
    sudo pacman -Syu --noconfirm
    sudo pacman -S --noconfirm python python-pip git curl wget
else
    echo "⚠️  Unknown package manager. Please install python3, pip, and git manually."
fi

# Upgrade pip
echo "⬆️  Upgrading pip..."
python3 -m pip install --upgrade pip

# Install Python packages
echo "🐍 Installing Python packages..."

packages=(
    "requests>=2.32.0"
    "rich>=14.0.0"
    "python-dateutil>=2.9.0"
    "urllib3>=2.2.0"
    "phonenumbers>=8.13.0"
    "python-whois>=0.9.0"
    "pyfiglet>=1.0.0"
)

for package in "${packages[@]}"; do
    echo "Installing $package..."
    python3 -m pip install "$package"
    if [ $? -eq 0 ]; then
        echo "✅ $package installed successfully"
    else
        echo "❌ Failed to install $package"
        # Try without version constraint
        base_package=$(echo "$package" | cut -d'>' -f1)
        echo "Trying $base_package without version constraint..."
        python3 -m pip install "$base_package"
    fi
done

echo ""
echo "🎯 Installation complete!"
echo ""

# Test imports
echo "🧪 Testing imports..."
python3 -c "
import sys
try:
    import requests
    import rich
    import phonenumbers
    import whois
    import pyfiglet
    print('✅ All core packages imported successfully!')
    print(f'Python version: {sys.version}')
except ImportError as e:
    print(f'❌ Import error: {e}')
    sys.exit(1)
"

if [ $? -eq 0 ]; then
    echo ""
    echo "🚀 Entity is ready to run!"
    echo "Use: python3 main.py"
    echo ""
else
    echo ""
    echo "❌ Some packages failed to import. Please check the installation."
    echo ""
fi
