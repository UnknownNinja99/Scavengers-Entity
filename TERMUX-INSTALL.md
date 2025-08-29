# 🚀 Termux Installation Guide for Entity

## 📱 **Complete Fresh Installation (Recommended)**

### **Step 1: Update Termux and Install Dependencies**
```bash
pkg update && pkg upgrade
```

### **Step 2: Install Required Packages**
```bash
pkg install git
pkg install python
```

### **Step 3: Clone Entity Repository**
```bash
git clone https://github.com/UnknownNinja99/Scavengers-Entity.git
cd Scavengers-Entity
```

### **Step 4: Install Python Dependencies**
```bash
python3 -m pip install requests rich phonenumbers python-whois pyfiglet
```

### **Step 5: Run Entity**
```bash
python main.py
```

---

## � **Troubleshooting**

### **If you get 'evdev' errors:**
Entity automatically skips problematic packages in Termux. The core functionality works without them.

### **If pip installation fails:**
```bash
# Upgrade pip first
python3 -m pip install --upgrade pip
# Then retry the installation
python3 -m pip install requests rich phonenumbers python-whois pyfiglet
```
rm -rf Scavengers-Entity

# Fresh clone
git clone https://github.com/UnknownNinja99/Scavengers-Entity.git
cd Scavengers-Entity

# Use Termux-specific installer
chmod +x install-termux.sh
./install-termux.sh
```

### **Method 2: Manual Installation**
```bash
# Update Termux
pkg update && pkg upgrade

# Install system dependencies
pkg install python git libxml2 libxslt libjpeg-turbo

# Install Python packages (avoiding problematic ones)
pip install requests rich python-dateutil urllib3 phonenumbers python-whois pyfiglet

# Run Entity
python main.py
```

## 🔧 **Troubleshooting Common Termux Issues**

### **Issue 1: `chmod: cannot access 'install.sh'`**
**Solution:** The file doesn't exist or wasn't cloned properly
```bash
ls -la  # Check if install.sh exists
# If missing, use install-termux.sh instead
```

### **Issue 2: `evdev` compilation error**
**Solution:** Skip the problematic package
```bash
pip install --no-deps pynput  # Skip dependencies
# Or simply don't install pynput (not essential for Entity)
```

### **Issue 3: Kernel headers missing**
**Solution:** Use pre-compiled packages
```bash
pkg install python-dev clang
# Or skip packages that need compilation
```

### **Issue 4: SSL certificate errors**
**Solution:** Update certificates
```bash
pkg install ca-certificates
```

## ⚡ **Termux-Optimized Entity Features**

### **What Works Perfectly:**
- ✅ Vulnerability scanning
- ✅ IP geolocation
- ✅ OSINT investigations
- ✅ Phishing detection
- ✅ Domain analysis
- ✅ Web vulnerability scanning

### **Limited in Termux:**
- ⚠️  Some GUI features (not applicable anyway)
- ⚠️  Advanced input handling (pynput)

## 📝 **Quick Commands for Entity on Termux**

```bash
# Navigate to Entity
cd ~/Scavengers-Entity

# Run Entity
python main.py

# Create shortcut (optional)
echo 'cd ~/Scavengers-Entity && python main.py' > ~/entity
chmod +x ~/entity
```

## 🆘 **If All Else Fails - Nuclear Option**

```bash
# Complete cleanup and reinstall
pkg uninstall python -y
pkg install python git -y
pip install --upgrade pip
git clone https://github.com/UnknownNinja99/Scavengers-Entity.git
cd Scavengers-Entity
pip install requests rich phonenumbers python-whois pyfiglet
python main.py
```

This should solve your Termux installation issues! 🎯
