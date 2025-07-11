# Entity Setup Guide

## 📱 Termux Installation (Android)

### Prerequisites
1. Install Termux from F-Droid or Google Play Store
2. Update Termux packages:
   ```bash
   pkg update && pkg upgrade
   ```

### Step-by-Step Installation

1. **Install Python and Git:**
   ```bash
   pkg install python git
   ```

2. **Install required system dependencies:**
   ```bash
   pkg install libxml2 libxslt libjpeg-turbo
   ```

3. **Clone the Entity repository:**
   ```bash
   git clone https://github.com/UnknownNinja99/Scavengers-Entity.git
   cd Scavengers-Entity
   ```

4. **Install Python dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

5. **Run Entity:**
   ```bash
   python main.py
   ```

### Termux-Specific Tips
- Use `termux-setup-storage` to access device storage
- For better experience, install `termux-api` for additional functionality
- Use `pkg install nano` or `pkg install vim` for text editing

---

## 💻 Linux/macOS Installation

### Prerequisites
- Python 3.7 or higher
- Git

### Installation Steps

1. **Clone the repository:**
   ```bash
   git clone https://github.com/UnknownNinja99/Scavengers-Entity.git
   cd Scavengers-Entity
   ```

2. **Create a virtual environment (recommended):**
   ```bash
   python3 -m venv entity-env
   source entity-env/bin/activate
   ```

3. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

4. **Run Entity:**
   ```bash
   python main.py
   ```

---

## 🪟 Windows Installation

### Prerequisites
- Python 3.7+ (from python.org)
- Git for Windows

### Installation Steps

1. **Clone the repository:**
   ```cmd
   git clone https://github.com/UnknownNinja99/Scavengers-Entity.git
   cd Scavengers-Entity
   ```

2. **Create virtual environment:**
   ```cmd
   python -m venv entity-env
   entity-env\Scripts\activate
   ```

3. **Install dependencies:**
   ```cmd
   pip install -r requirements.txt
   ```

4. **Run Entity:**
   ```cmd
   python main.py
   ```

---

## 🚨 Troubleshooting

### Common Issues

1. **Import Error for `phonenumbers`:**
   ```bash
   pip install phonenumbers
   ```

2. **SSL Certificate errors:**
   ```bash
   pip install --trusted-host pypi.org --trusted-host pypi.python.org --trusted-host files.pythonhosted.org -r requirements.txt
   ```

3. **Permission denied (Termux):**
   ```bash
   termux-setup-storage
   chmod +x main.py
   ```

4. **Module not found errors:**
   ```bash
   pip install --upgrade pip
   pip install -r requirements.txt --force-reinstall
   ```

### Performance Optimization

1. **For faster port scanning:**
   - Reduce thread count on older devices
   - Use smaller port ranges

2. **For better Termux performance:**
   ```bash
   pkg install proot
   ```

---

## 🔧 Advanced Configuration

### Custom API Keys (Optional)
Some features work better with API keys:

1. **HaveIBeenPwned API** (for enhanced breach checking)
   - Register at haveibeenpwned.com
   - Add your API key to the code

2. **VirusTotal API** (future enhancement)
   - Register at virustotal.com
   - Can be integrated for URL/file scanning

### Environment Variables
Create a `.env` file for sensitive configurations:
```bash
# .env file
HIBP_API_KEY=your_haveibeenpwned_api_key
VT_API_KEY=your_virustotal_api_key
```

---

## 📊 Usage Examples

### Quick Start Commands
```bash
# After installation, run Entity
python main.py

# Select options:
# 1 - Vulnerability Scanner
# 2 - IP Geolocation 
# 3 - OSINT Suite
# 4 - Phishing Detector
# 5 - About
# 0 - Exit
```

### Example Targets for Testing
- **Safe targets for testing:**
  - Your own servers/devices
  - scanme.nmap.org (official test target)
  - testphp.vulnweb.com (vulnerable web app)

---

## ⚖️ Legal Notice

**IMPORTANT:** This tool is for educational and authorized testing only!

- ✅ **Allowed:** Testing your own systems
- ✅ **Allowed:** Authorized penetration testing
- ✅ **Allowed:** Educational purposes with permission
- ❌ **Forbidden:** Scanning systems without permission
- ❌ **Forbidden:** Malicious activities
- ❌ **Forbidden:** Illegal reconnaissance

Always obtain explicit written permission before testing any system you don't own.
