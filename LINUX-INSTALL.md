# 🐧 Linux Installation Guide for Entity

## 🚀 **Complete Installation for Kali Linux / Ubuntu / Debian**

### **Step 1: Install System Dependencies**
```bash
apt install git
apt install python3
```

### **Step 2: Clone Entity Repository**
```bash
git clone https://github.com/UnknownNinja99/Scavengers-Entity.git
cd Scavengers-Entity
```

### **Step 3: Create Virtual Environment (Recommended)**
```bash
# Create a virtual environment for Entity
python3 -m venv entity-env

# Activate it
source entity-env/bin/activate
```

### **Step 4: Install Python Dependencies**
```bash
# Install packages (now it will work!)
pip install requests rich phonenumbers python-whois pyfiglet
```

### **Step 5: Run Entity**
```bash
# Run Entity
python main.py
```

---

## 🔄 **For Future Sessions**

To run Entity after installation:
```bash
cd Scavengers-Entity
source entity-env/bin/activate  # Activate virtual environment
python main.py
```
pip install requests rich phonenumbers python-whois pyfiglet

# Run Entity
python main.py
```

## 🎯 **Running Entity**

### **Every time you want to use Entity:**
```bash
cd Scavengers-Entity
source entity-env/bin/activate
python main.py

# When done, deactivate:
deactivate
```

## 🎨 **Distribution-Specific Instructions**

### **🔶 Ubuntu/Debian:**
```bash
# If python3-venv is missing:
sudo apt update
sudo apt install python3-venv git -y

# Then follow the manual installation above
```

### **🔷 Fedora:**
```bash
# If python3-venv is missing:
sudo dnf install python3-venv git -y

# Then follow the manual installation above
```

### **⚫ Arch Linux:**
```bash
# If python-venv is missing:
sudo pacman -S python git

# Then follow the manual installation above
```

### **🔴 CentOS/RHEL:**
```bash
# If python3-venv is missing:
sudo yum install python3-venv git -y

# Then follow the manual installation above
```

## 🔧 **Troubleshooting**

### **❌ Issue: `python3: command not found`**
**🔧 Solution:**
```bash
# Try using 'python' instead:
python -m venv entity-env
source entity-env/bin/activate
pip install requests rich phonenumbers python-whois pyfiglet
python main.py
```

### **❌ Issue: `No module named 'venv'`**
**🔧 Solution:**
```bash
# Install python3-venv package
sudo apt install python3-venv    # Ubuntu/Debian
sudo dnf install python3-venv    # Fedora  
sudo yum install python3-venv    # CentOS/RHEL
```

### **❌ Issue: `externally-managed-environment`**
**🔧 Solution:** ✅ **This is exactly why we use virtual environments!**
```bash
# Virtual environment bypasses this protection
python3 -m venv entity-env
source entity-env/bin/activate
# Now pip works normally!
```

### **❌ Issue: Permission denied**
**🔧 Solution:**
```bash
# Make sure you're in the right directory
cd Scavengers-Entity
# Virtual environment doesn't need sudo
```

## ⚡ **Quick Commands Reference**

```bash
# 📥 Setup (one time)
git clone https://github.com/UnknownNinja99/Scavengers-Entity.git
cd Scavengers-Entity
python3 -m venv entity-env
source entity-env/bin/activate
pip install requests rich phonenumbers python-whois pyfiglet

# 🚀 Daily use
cd Scavengers-Entity
source entity-env/bin/activate
python main.py

# 🔚 When done
deactivate
```

## ✅ **Verification**

Test if everything works:
```bash
# Test imports
python -c "import requests, rich, phonenumbers; print('🎉 All packages working!')"

# Run Entity
python main.py
```

## 🎯 **Features Available on Linux**

All Entity features work perfectly on Linux:
- ✅ **Vulnerability Scanning** - Network & web security analysis
- ✅ **OSINT Investigations** - Social media & domain intelligence  
- ✅ **Phishing Detection** - URL analysis & risk scoring
- ✅ **IP Geolocation** - Geographic tracking & analysis
- ✅ **Domain Analysis** - WHOIS & reputation checking
- ✅ **Web Vulnerability Scanning** - Security header analysis
- ✅ **Advanced Terminal UI** - Rich colored interface
- ✅ **Full Keyboard Support** - Interactive menu navigation

## 🛡️ **Why Virtual Environment?**

🔒 **Security:** Isolates Entity packages from system Python  
🧹 **Clean:** Easy to remove (just delete entity-env folder)  
⚡ **Fast:** No permission issues or conflicts  
🎯 **Modern:** Works with all modern Linux distributions  
✅ **Reliable:** Bypasses externally-managed-environment restrictions

## 🆘 **Emergency Reset**

If something goes wrong:
```bash
# Delete everything and start fresh
rm -rf entity-env
rm -rf Scavengers-Entity

# Start over
git clone https://github.com/UnknownNinja99/Scavengers-Entity.git
cd Scavengers-Entity
python3 -m venv entity-env
source entity-env/bin/activate
pip install requests rich phonenumbers python-whois pyfiglet
python main.py
```

## 🏆 **Success!**

🎉 **Entity is now installed and ready to secure your Linux system!**  
🚀 **Happy ethical hacking!** 🛡️
