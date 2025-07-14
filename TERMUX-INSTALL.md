# 🚀 Termux Installation Guide for Entity

## 📱 **Quick Fix for Current Issue**

If you're getting the `evdev` error, here's the immediate solution:

### **Step 1: Use Termux-Specific Requirements**
```bash
# In your current Scavengers-Entity directory
# NOTE: Make sure to type "phonenumbers" (with 's') not "phonenumber"
pip install --upgrade pip
pip install requests
pip install rich
pip install python-dateutil
pip install urllib3
pip install phonenumbers
pip install python-whois
pip install pyfiglet
```

### **Step 2: Test Entity**
```bash
python main.py
```

## 🛠️ **Complete Fresh Installation**

### **Method 1: Use Updated Repository**
```bash
# Remove old installation if needed
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
