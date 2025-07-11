# Entity - Advanced Security Toolkit

![Entity Banner](https://art.text-image.com/image/univers/e/Entity.png)

**Entity v1.0** by **Blue Scavengers Security** is a comprehensive, command-line cybersecurity toolkit designed for educational purposes, security professionals, and ethical hackers in Python.

---

## 🚀 Features

Entity combines multiple powerful security tools into a single, user-friendly interface.

### 1. 🔍 Vulnerability Scanner
- **Multi-threaded Port Scanning**: Quickly discover open ports on a target.
- **Banner Grabbing**: Identify services running on open ports.
- **Web Vulnerability Analysis**: Check for missing security headers, directory listing, and basic SQLi/XSS vulnerabilities.
- **SSL/TLS Certificate Analysis**: Inspect SSL certificates for expiration, weak algorithms, and misconfigurations.
- **Directory & File Enumeration**: Discover common sensitive directories and files.

### 2. 🕵️ OSINT (Open Source Intelligence) Suite
- **Social Media OSINT**: Check for a username's presence across major social media platforms.
- **Domain/IP Intelligence**: Gather detailed information on domains and IP addresses.
- **Phone Number Intelligence**: Analyze phone numbers to find the country, carrier, and type.
- **Email Investigation**: Gather intelligence on an email address and its domain.
- **Username Search**: Perform a broad search for a username across dozens of platforms.
- **Automatic Data Breach Check**: Check if an email has been exposed in known data breaches using the HaveIBeenPwned API.
- **WHOIS Lookup**: Perform a detailed WHOIS lookup on any domain.

### 3. 🛡️ Phishing Page Detector
- **URL Analysis**: Scans URLs for suspicious keywords, excessive length, and other structural red flags.
- **Domain Analysis**: Checks domain age and reputation.
- **Risk Scoring**: Provides an overall risk score to determine the likelihood of a phishing attempt.
- **Bulk Analysis**: Analyze a list of URLs at once.

### 4. 🌍 IP Geolocation & Analysis
- **IP Geolocation**: Track the geographical location of public IP addresses.
- **Private IP Handling**: Intelligently identifies private IPs and provides local network context.
- **Bulk IP Analysis**: Analyze multiple IP addresses in a single run.

---

## 🛠️ Installation

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/YOUR_USERNAME/Entity.git
    cd Entity
    ```

2.  **Install the required dependencies:**
    Make sure you have Python 3 installed. Then, run the following command to install all necessary libraries from the `requirements.txt` file.
    ```bash
    pip install -r requirements.txt
    ```

---

## 🖥️ Usage

To run the toolkit, simply execute the `main.py` script:

```bash
python main.py
```

You will be greeted with the main menu, where you can choose from the available modules.

---

## ⚖️ Disclaimer

This tool is intended for educational and authorized security testing purposes **only**. The author is not responsible for any misuse or damage caused by this program. Always obtain explicit permission before scanning any target you do not own. **Act ethically and