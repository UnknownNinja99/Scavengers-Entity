# 🐧 Linux Installation Guide for Entity

## 🚀 **Quick Installation**

### **Method 1: Virtual Environment (Recommended for Modern Linux)**
```bash
# Clone the repository
git clone https://github.com/UnknownNinja99/Scavengers-Entity.git
cd Scavengers-Entity

# Create virtual environment
python3 -m venv entity-env

# Activate virtual environment
source entity-env/bin/activate

# Install packages
pip install requests rich phonenumbers python-whois pyfiglet

# Run Entity
python main.py

# To deactivate later: deactivate
```

### **Method 2: Automated Script (Legacy Systems)**
```bash
# Clone the repository
git clone https://github.com/UnknownNinja99/Scavengers-Entity.git
cd Scavengers-Entity

# Run the Linux installer
chmod +x install-linux.sh
./install-linux.sh

# Run Entity
python3 main.py
```

### **Method 2: Manual Installation**

#### **For Modern Linux (Kali, Ubuntu 22+, Debian 12+):**
```bash
# Update system
sudo apt update

# Install dependencies
sudo apt install python3 python3-venv git -y

# Create virtual environment for Entity
python3 -m venv entity-env
source entity-env/bin/activate

# Install Python packages
pip install requests rich phonenumbers python-whois pyfiglet

# Run Entity
python main.py
```

#### **For Ubuntu/Debian:**
```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install dependencies
sudo apt install python3 python3-pip git curl wget -y

# Install Python packages
python3 -m pip install --upgrade pip
python3 -m pip install requests rich python-dateutil urllib3 phonenumbers python-whois pyfiglet

# Run Entity
python3 main.py
```

#### **For CentOS/RHEL:**
```bash
# Update system
sudo yum update -y

# Install dependencies
sudo yum install python3 python3-pip git curl wget -y

# Install Python packages
python3 -m pip install --upgrade pip
python3 -m pip install requests rich python-dateutil urllib3 phonenumbers python-whois pyfiglet

# Run Entity
python3 main.py
```

#### **For Fedora:**
```bash
# Update system
sudo dnf update -y

# Install dependencies
sudo dnf install python3 python3-pip git curl wget -y

# Install Python packages
python3 -m pip install --upgrade pip
python3 -m pip install requests rich python-dateutil urllib3 phonenumbers python-whois pyfiglet

# Run Entity
python3 main.py
```

#### **For Arch Linux:**
```bash
# Update system
sudo pacman -Syu

# Install dependencies
sudo pacman -S python python-pip git curl wget

# Install Python packages
python3 -m pip install --upgrade pip
python3 -m pip install requests rich python-dateutil urllib3 phonenumbers python-whois pyfiglet

# Run Entity
python3 main.py
```

## 🔧 **Troubleshooting**

### **Python command issues:**
```bash
# If 'python3' doesn't work, try:
python main.py

# Or create an alias:
alias python3=python
```

### **Permission issues (Modern Linux distributions):**
```bash
# If you get "externally-managed-environment" error:
# Use virtual environment (recommended)
python3 -m venv entity-env
source entity-env/bin/activate
pip install requests rich phonenumbers python-whois pyfiglet

# OR force system-wide installation (not recommended)
python3 -m pip install --break-system-packages requests rich phonenumbers python-whois pyfiglet
```

### **Missing system packages:**
```bash
# Install development tools if needed
sudo apt install build-essential python3-dev  # Ubuntu/Debian
sudo yum groupinstall "Development Tools"     # CentOS/RHEL
sudo dnf groupinstall "Development Tools"     # Fedora
```

## ✅ **Verification**

Test if everything works:
```bash
python3 -c "import requests, rich, phonenumbers; print('✅ All packages working!')"
python3 main.py
```

## 🎯 **Features Available on Linux**

All Entity features work perfectly on Linux:
- ✅ Vulnerability scanning
- ✅ OSINT investigations  
- ✅ Phishing detection
- ✅ IP geolocation
- ✅ Domain analysis
- ✅ Web vulnerability scanning
- ✅ Advanced keyboard input handling
- ✅ Full terminal UI experience

## 🆘 **If All Else Fails**

```bash
# Nuclear option - fresh Python environment
sudo apt remove python3-pip -y
sudo apt install python3-pip -y
python3 -m pip install --upgrade pip
python3 -m pip install requests rich phonenumbers python-whois pyfiglet
```
