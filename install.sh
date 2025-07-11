#!/bin/bash

# Entity Toolkit - Automated Installation Script
# For Linux/macOS/Termux

echo "🚀 Entity Toolkit - Automated Installer"
echo "========================================"

# Check if running on Termux
if [[ "$PREFIX" == *"com.termux"* ]]; then
    echo "📱 Termux environment detected"
    TERMUX=true
else
    echo "💻 Linux/macOS environment detected"
    TERMUX=false
fi

# Function to install packages
install_packages() {
    if [[ "$TERMUX" == true ]]; then
        echo "📦 Installing Termux packages..."
        pkg update -y
        pkg install -y python git libxml2 libxslt libjpeg-turbo
    else
        echo "📦 Checking system packages..."
        # Check if python3 is installed
        if ! command -v python3 &> /dev/null; then
            echo "❌ Python 3 is not installed. Please install Python 3.7+ first."
            exit 1
        fi
        
        # Check if git is installed
        if ! command -v git &> /dev/null; then
            echo "❌ Git is not installed. Please install Git first."
            exit 1
        fi
        
        echo "✅ Required packages found"
    fi
}

# Function to setup Python environment
setup_python() {
    echo "🐍 Setting up Python environment..."
    
    # Create virtual environment (skip on Termux as it's not needed)
    if [[ "$TERMUX" != true ]]; then
        if [[ ! -d "entity-env" ]]; then
            python3 -m venv entity-env
            echo "✅ Virtual environment created"
        fi
        source entity-env/bin/activate
        echo "✅ Virtual environment activated"
    fi
    
    # Upgrade pip
    python -m pip install --upgrade pip
    
    # Install requirements
    echo "📚 Installing Python dependencies..."
    pip install -r requirements.txt
    
    if [[ $? -eq 0 ]]; then
        echo "✅ Dependencies installed successfully"
    else
        echo "❌ Failed to install dependencies"
        echo "🔧 Trying alternative installation..."
        pip install --trusted-host pypi.org --trusted-host pypi.python.org --trusted-host files.pythonhosted.org -r requirements.txt
    fi
}

# Function to create launcher script
create_launcher() {
    echo "🚀 Creating launcher script..."
    
    if [[ "$TERMUX" == true ]]; then
        # Termux launcher
        cat > entity.sh << 'EOF'
#!/data/data/com.termux/files/usr/bin/bash
cd ~/Scavengers-Entity
python main.py
EOF
        chmod +x entity.sh
        echo "✅ Termux launcher created: ./entity.sh"
    else
        # Linux/macOS launcher
        cat > entity.sh << 'EOF'
#!/bin/bash
cd "$(dirname "$0")"
source entity-env/bin/activate
python main.py
EOF
        chmod +x entity.sh
        echo "✅ Launcher created: ./entity.sh"
    fi
}

# Function to test installation
test_installation() {
    echo "🧪 Testing installation..."
    
    if [[ "$TERMUX" == true ]]; then
        python -c "import requests, rich, phonenumbers, whois; print('✅ All modules imported successfully')"
    else
        source entity-env/bin/activate
        python -c "import requests, rich, phonenumbers, whois; print('✅ All modules imported successfully')"
    fi
    
    if [[ $? -eq 0 ]]; then
        echo "🎉 Installation completed successfully!"
        echo ""
        echo "📋 Next steps:"
        echo "   • Run: ./entity.sh (or python main.py)"
        echo "   • Read the documentation in README.md"
        echo "   • Check SETUP.md for detailed usage instructions"
        echo ""
        echo "⚖️  Remember: Use this tool ethically and legally!"
    else
        echo "❌ Installation test failed. Check the error messages above."
        exit 1
    fi
}

# Main installation process
main() {
    echo "Starting installation..."
    
    install_packages
    setup_python
    create_launcher
    test_installation
    
    echo "🏁 Installation complete!"
}

# Run main function
main
