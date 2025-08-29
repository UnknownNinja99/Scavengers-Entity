# 🐧 Alternative Linux Installation (Global Packages)

## 🚀 **Simple Installation (No Virtual Environment)**

If you prefer the same experience as Termux (global package installation):

### **Step 1: Install System Dependencies**
```bash
sudo apt install git python3 python3-pip
```

### **Step 2: Clone and Install**
```bash
git clone https://github.com/UnknownNinja99/Scavengers-Entity.git
cd Scavengers-Entity
pip3 install requests rich phonenumbers python-whois pyfiglet
```

### **Step 3: Run Entity (Simple)**
```bash
python3 main.py
```

### **Future Runs**
```bash
cd Scavengers-Entity
python3 main.py
```

---

## ⚠️ **Note**

This method installs packages globally. The virtual environment method is recommended for better package isolation, but this gives you the same simple experience as Termux.

**Choose what works best for you:**
- 🛡️ **Virtual Environment**: Better isolation, requires activation
- 🚀 **Global Install**: Simpler to run, may conflict with system packages
