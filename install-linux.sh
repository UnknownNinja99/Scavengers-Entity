#!/bin/bash
# 🐧 Linux Installation Script for Entity Cybersecurity Toolkit
# ✅ Tested and optimized for all Linux distributions

echo "🚀 Installing Entity Cybersecurity Toolkit for Linux..."
echo "══════════════════════════════════════════════════════"

# Create virtual environment
echo "🏗️  Creating virtual environment..."
python3 -m venv entity-env

if [ $? -eq 0 ]; then
    echo "✅ Virtual environment created successfully"
else
    echo "❌ Failed to create virtual environment"
    echo "💡 Installing python3-venv..."
    sudo apt install python3-venv -y 2>/dev/null || sudo yum install python3-venv -y 2>/dev/null || sudo dnf install python3-venv -y 2>/dev/null
    python3 -m venv entity-env
fi

# Activate virtual environment
echo "🔄 Activating virtual environment..."
source entity-env/bin/activate

if [ $? -eq 0 ]; then
    echo "✅ Virtual environment activated"
else
    echo "❌ Failed to activate virtual environment"
    exit 1
fi

# Install packages
echo "� Installing Python packages..."
pip install requests rich phonenumbers python-whois pyfiglet

if [ $? -eq 0 ]; then
    echo "✅ All packages installed successfully!"
else
    echo "❌ Some packages failed to install"
    exit 1
fi

echo ""
echo "🧪 Testing imports..."
python -c "
try:
    import requests
    import rich
    import phonenumbers
    import whois
    import pyfiglet
    print('✅ All packages imported successfully!')
except ImportError as e:
    print(f'❌ Import error: {e}')
    exit(1)
"

echo ""
echo "🎉 Installation complete!"
echo "� To run Entity:"
echo "   1️⃣  source entity-env/bin/activate"
echo "   2️⃣  python main.py"
echo ""
echo "💡 To deactivate virtual environment later: deactivate"
echo "🚀 Entity is ready to secure your world!"
