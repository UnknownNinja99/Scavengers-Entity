#!/data/data/com.termux/files/usr/bin/bash

# Entity Toolkit - Termux-Specific Installer
# Optimized for Android/Termux environment

echo "📱 Entity Toolkit - Termux Installer"
echo "===================================="

# Check if we're in Termux
if [[ "$PREFIX" != *"com.termux"* ]]; then
    echo "❌ This installer is designed for Termux only!"
    echo "For other platforms, use install.sh"
    exit 1
fi

echo "✅ Termux environment detected"

# Update packages
echo "📦 Updating Termux packages..."
pkg update -y && pkg upgrade -y

# Install essential packages
echo "🔧 Installing essential packages..."
pkg install -y python git libxml2 libxslt libjpeg-turbo openssl

# Upgrade pip
echo "🐍 Upgrading pip..."
python -m pip install --upgrade pip

# Install Termux-compatible requirements
echo "📚 Installing Python dependencies (Termux-compatible)..."
if [[ -f "requirements-termux.txt" ]]; then
    pip install -r requirements-termux.txt
else
    echo "⚠️  requirements-termux.txt not found, installing core packages..."
    pip install requests rich python-dateutil urllib3 phonenumbers python-whois pyfiglet
fi

# Test installation
echo "🧪 Testing installation..."
python -c "
try:
    import requests, rich, phonenumbers, whois, pyfiglet
    print('✅ Core modules imported successfully!')
    print('📱 Entity is ready for Termux!')
except ImportError as e:
    print(f'❌ Import error: {e}')
    print('Some modules may need manual installation')
"

# Create Termux launcher
echo "🚀 Creating Termux launcher..."
cat > entity-termux.sh << 'EOF'
#!/data/data/com.termux/files/usr/bin/bash
cd ~/Scavengers-Entity
python main.py
EOF

chmod +x entity-termux.sh

echo ""
echo "🎉 Installation completed!"
echo ""
echo "📋 Quick Start:"
echo "   • Run: ./entity-termux.sh"
echo "   • Or: python main.py"
echo ""
echo "📝 Note: Some advanced features may be limited in Termux"
echo "⚖️  Remember: Use this tool ethically and legally!"
echo ""
echo "🔧 If you encounter issues:"
echo "   • Try: pkg install python-dev clang"
echo "   • Or use: pip install --no-deps package_name"
