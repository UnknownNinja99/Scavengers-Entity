# Entity Toolkit - Quick Start Guide

## 🚀 Quick Installation

### For Termux (Android)
```bash
# Clone and install
git clone https://github.com/UnknownNinja99/Scavengers-Entity.git
cd Scavengers-Entity
chmod +x install.sh
./install.sh

# Run Entity
./entity.sh
```

### For Linux/macOS
```bash
# Clone and install
git clone https://github.com/UnknownNinja99/Scavengers-Entity.git
cd Scavengers-Entity
chmod +x install.sh
./install.sh

# Run Entity
./entity.sh
```

### For Windows
```cmd
REM Clone and install
git clone https://github.com/UnknownNinja99/Scavengers-Entity.git
cd Scavengers-Entity
install.bat

REM Run Entity
entity.bat
```

## 📱 Termux Specific Instructions

### Initial Termux Setup
```bash
# Update packages
pkg update && pkg upgrade

# Install basic tools
pkg install python git nano

# Give storage permissions
termux-setup-storage

# Clone Entity
git clone https://github.com/UnknownNinja99/Scavengers-Entity.git
cd Scavengers-Entity

# Install dependencies
pip install -r requirements.txt

# Run Entity
python main.py
```

### Termux Tips
- Use volume down + C to copy
- Use volume down + V to paste
- Swipe left on keyboard for arrow keys
- Use `nano` or `vim` for editing files

## 🔧 Manual Installation (if scripts fail)

### Step 1: Install Python packages
```bash
pip install requests rich phonenumbers python-whois pyfiglet
```

### Step 2: Test installation
```bash
python -c "import requests, rich, phonenumbers, whois; print('Success!')"
```

### Step 3: Run Entity
```bash
python main.py
```

## 🎯 Usage Examples

### 1. Vulnerability Scanning
```
Choose option: 1
Target: scanme.nmap.org
Port range: 1-1000
```

### 2. IP Geolocation
```
Choose option: 2
Then option: 1
IP: 8.8.8.8
```

### 3. OSINT Investigation
```
Choose option: 3
Then option: 6 (Data breach check)
Email: test@example.com
```

## ⚠️ Important Notes

1. **Legal Use Only**: Only scan systems you own or have permission to test
2. **Responsible Usage**: Don't overwhelm targets with excessive requests
3. **Educational Purpose**: This tool is for learning cybersecurity concepts

## 🆘 Troubleshooting

### Common Issues
1. **Module not found**: Run `pip install -r requirements.txt`
2. **Permission denied**: Run `chmod +x install.sh`
3. **SSL errors**: Try `pip install --trusted-host pypi.org -r requirements.txt`

### Getting Help
- Check SETUP.md for detailed instructions
- Open an issue on GitHub
- Ensure you're using Python 3.7+

## 🏁 Ready to Go!
Once installed, Entity provides a user-friendly menu system. Simply follow the on-screen prompts to use any feature.
