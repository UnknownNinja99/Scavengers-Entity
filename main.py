import re
import socket
import requests
import time
from rich.console import Console
from rich.table import Table
from datetime import datetime, timezone
from rich.progress import Progress 
import ssl
import pyfiglet
import phonenumbers
from phonenumbers import geocoder, carrier
import urllib.parse
from urllib.parse import urlparse
import whois



# Initialize the console object
console = Console()

def show_banner():
    # Generate and print the ASCII banner
    banner = pyfiglet.figlet_format('Entity', font='univers')
    console.print(f"[bold cyan]{banner}[/bold cyan]")
    console.print("[bold yellow]Entity v1.0 by: Blue Scavengers Security[/bold yellow]")
    console.print("[bold green]Author: Gyau Boateng[/bold green]\n")

def validate_target(target):
    """Validate if the input is a valid URL or IP address."""
    url_regex = re.compile(
        r'^(https?://)?'  # Optional http or https
        r'([a-zA-Z0-9.-]+)'  # Domain or IP
        r'(:\d+)?'  # Optional port
        r'(/.*)?$'  # Optional path
    )
    ip_regex = re.compile(
        r'^((25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\.){3}'
        r'(25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)$'
    )
    return url_regex.match(target) or ip_regex.match(target)

import time
from rich.progress import Progress
from concurrent.futures import ThreadPoolExecutor

def scan_port(target, port, open_ports, progress, task):
    """Scan a single port and update progress with robust banner grabbing."""
    try:
        with socket.create_connection((target, port), timeout=1) as sock:
            open_ports.append(port)
            console.print(f"[bold green]Port {port} is open.[/bold green]")
            try:
                # Perform banner grabbing
                sock.sendall(b"HEAD / HTTP/1.1\r\nHost: example.com\r\n\r\n")
                banner_bytes = sock.recv(1024)
                # Decode safely, ignoring characters that can't be decoded
                banner = banner_bytes.decode('utf-8', errors='ignore').strip()
                if banner:
                    console.print(f"[bold cyan]Banner on Port {port}:[/bold cyan] {banner}")
                else:
                    console.print(f"[cyan]Port {port}: Got a response, but no printable banner.[/cyan]")
            except Exception as e:
                console.print(f"[yellow]Port {port}: Open, but could not grab banner ({e}).[/yellow]")
    except (socket.timeout, ConnectionRefusedError, OSError):
        pass
    finally:
        progress.update(task, advance=1)

def detailed_port_scan(target, port_range=(1, 1024), threads=50):
    """Perform a detailed port scan on the target with multi-threading and progress bar."""
    console.print(f"[bold yellow]Scanning ports {port_range[0]}-{port_range[1]}...[/bold yellow]")
    open_ports = []
    total_ports = port_range[1] - port_range[0] + 1

    with Progress() as progress:
        task = progress.add_task("[cyan]Scanning Ports...", total=total_ports)

        # Use ThreadPoolExecutor for multi-threaded port scanning
        with ThreadPoolExecutor(max_workers=threads) as executor:
            for port in range(port_range[0], port_range[1] + 1):
                executor.submit(scan_port, target, port, open_ports, progress, task)

    if not open_ports:
        console.print("[bold red]No open ports found in the specified range.[/bold red]")
    return open_ports

def check_vulnerabilities(open_ports, target):
    """Check for vulnerabilities based on open ports and services."""
    console.print("[bold yellow]Checking for vulnerabilities...[/bold yellow]")

    # Map common ports to services and potential vulnerabilities
    port_service_map = {
        21: ("FTP", "Anonymous login, cleartext credentials, brute-force attacks"),
        22: ("SSH", "Brute-force attacks, weak encryption, default credentials"),
        23: ("Telnet", "Cleartext credentials, man-in-the-middle, brute-force"),
        25: ("SMTP", "Open relay, spoofing, spam relay, enumeration"),
        53: ("DNS", "DNS amplification, cache poisoning, zone transfer"),
        80: ("HTTP", "Directory traversal, XSS, SQL injection, info disclosure"),
        110: ("POP3", "Cleartext credentials, brute-force, buffer overflow"),
        143: ("IMAP", "Cleartext credentials, brute-force, buffer overflow"),
        443: ("HTTPS", "SSL/TLS misconfig, Heartbleed, POODLE, BEAST"),
        3306: ("MySQL", "Default credentials, SQL injection, info disclosure"),
        3389: ("RDP", "Brute-force, BlueKeep, weak encryption"),
        5900: ("VNC", "No authentication, brute-force, info disclosure"),
        853: ("DNS over TLS", "TLS misconfiguration, DoS, info disclosure"),
        # ...add more as needed
    }

    vulnerabilities = []
    for port in open_ports:
        if port in port_service_map:
            service, attack = port_service_map[port]
            vulnerabilities.append(f"Port {port} ({service}): {attack}")
        else:
            vulnerabilities.append(f"Port {port}: Unknown service. Investigate further.")

    # Display vulnerabilities
    if vulnerabilities:
        console.print("[bold red]Potential Vulnerabilities Found:[/bold red]")
        for vuln in vulnerabilities:
            console.print(f"[bold cyan]- {vuln}[/bold cyan]")
    else:
        console.print("[bold green]No vulnerabilities found based on open ports.[/bold green]")

def vulnerability_scanner():
    """Advanced vulnerability scanner with submenu."""
    while True:
        console.print("\n[bold blue]Vulnerability Scanner Menu[/bold blue]")
        console.print("[1] Scan Open Ports")
        console.print("[2] Web Vulnerability Scan (HTTP Headers, Status, etc.)")
        console.print("[3] SSL/TLS Certificate Analysis")
        console.print("[4] Directory Enumeration")
        console.print("[0] Back to Main Menu\n")
        choice = console.input("[bold green]Choose a scan type: [/bold green]")

        if choice == '1':
            target = console.input("[bold green]Enter the target IP or domain: [/bold green]")
            if not validate_target(target):
                console.print("[bold red]Invalid target![/bold red]")
                continue
            open_ports = detailed_port_scan(target, port_range=(1, 1024))
            check_vulnerabilities(open_ports, target)
        elif choice == '2':
            target = console.input("[bold green]Enter the target URL (with http:// or https://): [/bold green]")
            if not target.startswith("http"):
                target = "http://" + target
            try:
                response = requests.get(target, timeout=5)

                # Create a table for the main scan results
                table = Table(title="Web Vulnerability Scan Result", show_lines=True)
                table.add_column("Check", style="cyan", no_wrap=True)
                table.add_column("Result", style="magenta")

                table.add_row("HTTP Status Code", str(response.status_code))

                # Headers as a sub-table
                headers_table = Table(title="HTTP Headers", show_header=True, header_style="bold blue")
                headers_table.add_column("Header")
                headers_table.add_column("Value")
                for k, v in response.headers.items():
                    headers_table.add_row(k, v)
                table.add_row("Headers", "[See below]")

                console.print(table)
                console.print(headers_table)

                # Detect server technology
                server = response.headers.get('Server', '')
                if server:
                    console.print(f"[bold cyan]Server Technology:[/bold cyan] {server}")

                # Directory listing
                if "Index of /" in response.text:
                    console.print("[bold red]Possible Directory Listing Enabled![/bold red]")
                    console.print("[yellow]Risk: Directory listing allows attackers to browse files and directories on the server, which can expose sensitive files or application logic.[/yellow]")

                # Missing security headers and their risks
                header_risks = {
                    "X-Frame-Options": "Helps prevent clickjacking attacks by controlling whether the site can be framed by other pages.",
                    "X-XSS-Protection": "Enables the browser's cross-site scripting (XSS) filter to prevent reflected XSS attacks.",
                    "X-Content-Type-Options": "Prevents browsers from MIME-sniffing a response away from the declared content-type, reducing exposure to drive-by downloads and XSS.",
                    "Strict-Transport-Security": "Forces browsers to use HTTPS, protecting against man-in-the-middle attacks.",
                    "Content-Security-Policy": "Helps prevent XSS, clickjacking, and other code injection attacks by specifying allowed sources of content."
                }
                missing_headers = []
                for header in header_risks:
                    if header not in response.headers:
                        missing_headers.append(header)
                if missing_headers:
                    console.print(f"[bold red]Missing Security Headers:[/bold red] {', '.join(missing_headers)}")
                    for header in missing_headers:
                        console.print(f"[yellow]{header} Risk: {header_risks[header]}[/yellow]")
                else:
                    console.print("[bold green]All common security headers are present.[/bold green]")

                # SQL Injection test
                if "?" in target:
                    test_url = target + "'"
                    test_resp = requests.get(test_url, timeout=5)
                    if "sql" in test_resp.text.lower() or "syntax" in test_resp.text.lower():
                        console.print("[bold red]Possible SQL Injection vulnerability detected![/bold red]")
                        console.print("[yellow]Risk: SQL Injection allows attackers to execute arbitrary SQL code on the database, potentially leading to data theft or loss.[/yellow]")
                    else:
                        console.print("[green]No SQL Injection detected.[/green]")
                else:
                    console.print("[yellow]No query string found for SQLi test.[/yellow]")

                # Reflected XSS test
                if "?" in target:
                    param = target.split("?")[1].split("=")[0]
                    xss_test_url = target.split("?")[0] + "?" + param + "=<script>alert(1)</script>"
                    xss_resp = requests.get(xss_test_url, timeout=5)
                    if "<script>alert(1)</script>" in xss_resp.text:
                        console.print("[bold red]Possible Reflected XSS vulnerability detected![/bold red]")
                        console.print("[yellow]Risk: Reflected XSS allows attackers to execute malicious scripts in the user's browser, leading to session hijacking, defacement, or redirection.[/yellow]")
                    else:
                        console.print("[green]No reflected XSS detected.[/green]")
                else:
                    console.print("[yellow]No query string found for XSS test.[/yellow]")

                # Basic open redirect test
                if "?" in target:
                    param = target.split("?")[1].split("=")[0]
                    redirect_test_url = target.split("?")[0] + "?" + param + "=//evil.com"
                    redirect_resp = requests.get(redirect_test_url, allow_redirects=False, timeout=5)
                    if redirect_resp.status_code in [301, 302, 303, 307, 308]:
                        location = redirect_resp.headers.get("Location", "")
                        # Fixed: More secure URL validation to prevent bypasses
                        from urllib.parse import urlparse
                        parsed_location = urlparse(location)
                        if parsed_location.netloc == "evil.com" or parsed_location.netloc.endswith(".evil.com"):
                            console.print("[bold red]Possible Open Redirect vulnerability detected![/bold red]")
                            console.print("[yellow]Risk: Open redirects can be abused for phishing or malware delivery.[/yellow]")

                # Check for dangerous HTTP methods
                try:
                    options_resp = requests.options(target, timeout=5)
                    allowed_methods = options_resp.headers.get('Allow', '')
                    console.print(f"[bold cyan]Allowed HTTP Methods:[/bold cyan] {allowed_methods}")
                    dangerous = [m for m in ['PUT', 'DELETE', 'TRACE', 'CONNECT'] if m in allowed_methods]
                    if dangerous:
                        console.print(f"[bold red]Dangerous HTTP Methods Enabled:[/bold red] {', '.join(dangerous)}")
                        console.print("[yellow]Risk: These methods can allow attackers to upload files, delete data, or perform other dangerous actions.[/yellow]")
                except Exception as e:
                    console.print(f"[yellow]Could not determine allowed HTTP methods: {e}[/yellow]")

            except requests.exceptions.SSLError:
                if target.startswith("http://"):
                    target = target.replace("http://", "https://", 1)
                    try:
                        response = requests.get(target, timeout=5)
                        console.print(f"[bold cyan]Switched to HTTPS. HTTP Status Code:[/bold cyan] {response.status_code}")
                    except Exception as e:
                        console.print(f"[bold red]HTTPS Error: {e}[/bold red]")
                else:
                    console.print("[bold red]SSL Error: Could not connect using HTTPS.[/bold red]")
            except Exception as e:
                console.print(f"[bold red]Error: {e}[/bold red]")
        elif choice == '3':
            target = console.input("[bold green]Enter the target domain (no http/https): [/bold green]")
            try:
                # Fixed: Use secure SSL context with modern TLS versions only
                context = ssl.create_default_context()
                context.check_hostname = True
                context.verify_mode = ssl.CERT_REQUIRED
                # Disable weak protocols
                context.options |= ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3 | ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1
                
                with socket.create_connection((target, 443), timeout=5) as sock:
                    with context.wrap_socket(sock, server_hostname=target) as ssock:
                        cert = ssock.getpeercert()
                        issuer = dict(x[0] for x in cert['issuer'])
                        subject = dict(x[0] for x in cert['subject'])
                        valid_from = cert['notBefore']
                        valid_to = cert['notAfter']
                        sig_alg = cert.get('signatureAlgorithm', 'Unknown')

                        console.print(f"[bold cyan]SSL Certificate Analysis for {target}[/bold cyan]")
                        console.print(f"Issuer: [yellow]{issuer.get('organizationName', 'Unknown')}[/yellow]")
                        console.print(f"Subject: [yellow]{subject.get('commonName', 'Unknown')}[/yellow]")
                        console.print(f"Valid From: [yellow]{valid_from}[/yellow]")
                        console.print(f"Valid To: [yellow]{valid_to}[/yellow]")
                        console.print(f"Signature Algorithm: [yellow]{sig_alg}[/yellow]")

                        # Check for expired or not-yet-valid certificate
                        valid_from_dt = datetime.strptime(valid_from, "%b %d %H:%M:%S %Y %Z")
                        valid_to_dt = datetime.strptime(valid_to, "%b %d %H:%M:%S %Y %Z")
                        now = datetime.now(timezone.utc)
                        if now < valid_from_dt:
                            console.print("[bold red]The certificate is not yet valid![/bold red]")
                            console.print("[yellow]Risk: Users may not trust this site, and attackers could exploit this gap.[/yellow]")
                        elif now > valid_to_dt:
                            console.print("[bold red]The SSL/TLS certificate has expired![/bold red]")
                            console.print("[yellow]Risk: Expired certificates allow attackers to impersonate the site or intercept traffic.[/yellow]")
                        else:
                            console.print("[bold green]The SSL/TLS certificate is currently valid.[/bold green]")

                        # Check for self-signed certificate
                        if issuer.get('commonName') == subject.get('commonName'):
                            console.print("[bold red]Self-signed certificate detected![/bold red]")
                            console.print("[yellow]Risk: Self-signed certificates are not trusted by browsers and can be used in man-in-the-middle attacks.[/yellow]")

                        # Check for weak signature algorithm
                        if 'md5' in sig_alg.lower() or 'sha1' in sig_alg.lower():
                            console.print("[bold red]Weak signature algorithm detected![/bold red]")
                            console.print("[yellow]Risk: Weak algorithms like MD5 or SHA1 can be broken, allowing attackers to forge certificates.[/yellow]")

            except Exception as e:
                console.print(f"[bold red]SSL/TLS Error: {e}[/bold red]")
        elif choice == '4':
            target = console.input("[bold green]Enter the target URL: [/bold green]")
            wordlist = [
                "/admin", "/login", "/robots.txt", "/config", "/uploads",
                "/.git/", "/.env", "/backup", "/test", "/old", "/private", "/tmp"
            ]
            dir_risks = {
                "/admin": "Admin panels may allow attackers to brute-force credentials or access sensitive controls.",
                "/login": "Login pages can be targeted for brute-force or credential stuffing attacks.",
                "/robots.txt": "robots.txt may reveal hidden or sensitive paths that should not be public.",
                "/config": "Config directories may expose configuration files with sensitive info.",
                "/uploads": "Upload folders can be abused to upload malicious files.",
                "/backup": "Backup folders may contain old or sensitive data.",
                "/test": "Test folders may have insecure or forgotten scripts.",
                "/old": "Old folders may contain outdated, vulnerable code.",
                "/private": "Private folders may expose confidential data.",
                "/tmp": "Temporary folders may leak sensitive files.",
                "/.git/": "Exposed .git folder can leak source code and history.",
                "/.env": ".env files often contain credentials and secrets.",
            }
            found = []
            for path in wordlist:
                url = target.rstrip("/") + path
                try:
                    r = requests.get(url, timeout=3)
                    if r.status_code == 200:
                        found.append(path)
                        console.print(f"[cyan]{url}[/cyan]")
                        risk = dir_risks.get(path, "May expose sensitive files or information.")
                        console.print(f"[yellow]Risk: {risk}[/yellow]")
                except:
                    pass
            if not found:
                console.print("[bold red]No common directories found.[/bold red]")

            # Check for exposed sensitive files (with explanations)
            sensitive_files = ["/.git/", "/.env", "/.htaccess", "/config.php"]
            file_risks = {
                "/.git/": "Exposed .git folder can leak source code and history.",
                "/.env": ".env files often contain credentials and secrets.",
                "/.htaccess": ".htaccess may reveal server configuration and access rules.",
                "/config.php": "config.php may contain database credentials and sensitive config."
            }
            for path in sensitive_files:
                url = target.rstrip("/") + path
                try:
                    r = requests.get(url, timeout=3)
                    if r.status_code == 200:
                        console.print(f"[bold red]Sensitive file exposed: {url}[/bold red]")
                        risk = file_risks.get(path, "May leak credentials or sensitive configuration.")
                        console.print(f"[yellow]Risk: {risk}[/yellow]")
                except:
                    pass
        elif choice == '0':
            break
        else:
            console.print("[bold red]Invalid option, try again.[/bold red]")

def is_private_ip(ip):
    """Check if an IP address is in a private range."""
    return (ip.startswith('10.') or
            ip.startswith('192.168.') or
            (ip.startswith('172.') and 16 <= int(ip.split('.')[1]) <= 31))

def track_ip(ip):
    """Fetch and display info for a given IP, handling private IPs intelligently."""
    # Check if the IP is private
    if is_private_ip(ip):
        console.print(f"[bold yellow]Analysis for Private IP: {ip}[/bold yellow]")
        private_ip_table = Table(title=f"Local Network Analysis for {ip}", show_lines=True)
        private_ip_table.add_column("Property", style="cyan")
        private_ip_table.add_column("Value", style="magenta")
        private_ip_table.add_row("IP Type", "Private (Non-Routable on Internet)")
        private_ip_table.add_row("Note", "Geolocation is not possible for private IPs.")
        
        # Try to get local hostname
        try:
            hostname, _, _ = socket.gethostbyaddr(ip)
            private_ip_table.add_row("Local Hostname", hostname)
        except socket.herror:
            private_ip_table.add_row("Local Hostname", "Could not resolve")
            
        console.print(private_ip_table)
        console.print("\n[bold yellow]Suggestion:[/bold yellow] Use the 'Vulnerability Scanner' (Option 1) to run a port scan on this local IP.")
        return  # Exit the function since we can't do more

    # The rest of the function handles public IPs as before
    try:
        # Primary API - ip-api.com
        resp = requests.get(f"http://ip-api.com/json/{ip}", timeout=5)
        data = resp.json()
        
        if data.get("status") == "success":
            tbl = Table(title=f"Comprehensive Geolocation Analysis for {ip}", show_lines=True)
            tbl.add_column("Field", style="cyan", no_wrap=True)
            tbl.add_column("Value", style="magenta")
            
            # Enhanced data display
            fields = {
                "country": "Country",
                "regionName": "Region/State", 
                "city": "City",
                "zip": "Postal Code",
                "lat": "Latitude",
                "lon": "Longitude",
                "timezone": "Timezone",
                "isp": "Internet Service Provider",
                "org": "Organization",
                "as": "Autonomous System"
            }
            
            for key, label in fields.items():
                value = data.get(key, "N/A")
                tbl.add_row(label, str(value))
            
            console.print(tbl)
            
            # Additional analysis
            console.print(f"\n[bold yellow]Additional Information:[/bold yellow]")
            console.print(f"[cyan]Google Maps:[/cyan] https://maps.google.com/?q={data.get('lat','')},{data.get('lon','')}")
            console.print(f"[cyan]IP Type:[/cyan] {'Likely VPN/Proxy' if 'VPN' in data.get('org','').upper() or 'PROXY' in data.get('org','').upper() else 'Regular ISP'}")
            
            # Cross-reference with second API for verification
            try:
                resp2 = requests.get(f"https://ipinfo.io/{ip}/json", timeout=5)
                data2 = resp2.json()
                if data2.get('city') and data.get('city') and data2.get('city') != data.get('city'):
                    console.print(f"[yellow]Note: Secondary source shows city as '{data2.get('city','Unknown')}'[/yellow]")
            except:
                pass
                
        else:
            console.print(f"[bold red]Error:[/bold red] {data.get('message','Invalid IP')}")
            
    except Exception as e:
        console.print(f"[bold red]Error fetching IP data:[/bold red] {e}")

def phone_number_info():
    """Enhanced phone number analysis with additional details."""
    number = console.input("[bold green]Enter phone number with country code (e.g. +233*********): [/bold green]")
    try:
        parsed = phonenumbers.parse(number, None)
        country = geocoder.description_for_number(parsed, "en")
        carrier_name = carrier.name_for_number(parsed, "en")
        
        # Create a nice table for phone info
        tbl = Table(title=f"Phone Number Analysis: {number}", show_lines=True)
        tbl.add_column("Field", style="cyan", no_wrap=True)
        tbl.add_column("Value", style="magenta")
        
        tbl.add_row("Country/Region", country or 'Unknown')
        tbl.add_row("Carrier/Network", carrier_name or 'Unknown')
        tbl.add_row("Number Type", 'Mobile' if phonenumbers.number_type(parsed) == phonenumbers.PhoneNumberType.MOBILE else 'Landline/Other')
        tbl.add_row("International Format", phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.INTERNATIONAL))
        tbl.add_row("National Format", phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.NATIONAL))
        tbl.add_row("Is Valid", "Yes" if phonenumbers.is_valid_number(parsed) else "No")
        
        console.print(tbl)
        console.print(f"[yellow]Note: This shows publicly available telecom data only.[/yellow]")
        
    except Exception as e:
        console.print(f"[bold red]Error parsing phone number:[/bold red] {e}")

def ip_geolocation_tracker():
    """Enhanced interactive submenu for comprehensive tracking."""
    while True:
        console.print("\n[bold blue]═══ Advanced Geolocation & Analysis Suite ═══[/bold blue]")
        console.print("[1] 🌍 Track by IP Address")
        console.print("[2] 🌐 Track by Domain Name") 
        console.print("[3] 📍 Track Your Own IP")
        console.print("[4] 📱 Phone Number Analysis")
        console.print("[5] 🔍 Bulk IP Analysis")
        console.print("[0] ⬅️  Back to Main Menu\n")
        choice = console.input("[bold green]Choose analysis method: [/bold green]")

        if choice == "1":
            ip = console.input("[bold green]Enter the IP address: [/bold green]")
            if validate_ip(ip):
                track_ip(ip)
            else:
                console.print("[bold red]Invalid IP address format![/bold red]")
                
        elif choice == "2":
            domain = console.input("[bold green]Enter the domain: [/bold green]")
            try:
                ip = socket.gethostbyname(domain)
                console.print(f"[cyan]✓ Resolved {domain} → {ip}[/cyan]")
                track_ip(ip)
            except Exception as e:
                console.print(f"[bold red]Domain resolution error:[/bold red] {e}")
                
        elif choice == "3":
            try:
                console.print("[yellow]Fetching your public IP...[/yellow]")
                ip = requests.get("https://api.ipify.org", timeout=5).text
                console.print(f"[cyan]✓ Your public IP: {ip}[/cyan]")
                track_ip(ip)
            except Exception as e:
                console.print(f"[bold red]Error fetching your IP:[/bold red] {e}")
                
        elif choice == "4":
            phone_number_info()
            
        elif choice == "5":
            bulk_ip_analysis()
            
        elif choice == "0":
            break
        else:
            console.print("[bold red]Invalid option, try again.[/bold red]")

def validate_ip(ip):
    """Validate IP address format."""
    parts = ip.split('.')
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(part) <= 255 for part in parts)
    except ValueError:
        return False

def bulk_ip_analysis():
    """Analyze multiple IPs at once."""
    console.print("[bold yellow]Bulk IP Analysis[/bold yellow]")
    ips_input = console.input("[bold green]Enter IPs separated by commas: [/bold green]")
    ips = [ip.strip() for ip in ips_input.split(',')]
    
    for ip in ips:
        if validate_ip(ip):
            console.print(f"\n[bold cyan]Analyzing {ip}...[/bold cyan]")
            track_ip(ip)
        else:
            console.print(f"[bold red]Skipping invalid IP: {ip}[/bold red]")

def phishing_page_detector():
    """Advanced phishing page detection and analysis."""
    while True:
        console.print("\n[bold blue]═══ Phishing Page Detector ═══[/bold blue]")
        console.print("[1] 🔍 Analyze Single URL")
        console.print("[2] 📝 Bulk URL Analysis")
        console.print("[3] 🌐 Domain Reputation Check")
        console.print("[0] ⬅️  Back to Main Menu\n")
        choice = console.input("[bold green]Choose detection method: [/bold green]")

        if choice == "1":
            analyze_single_url()
        elif choice == "2":
            bulk_url_analysis()
        elif choice == "3":
            domain_reputation_check()
        elif choice == "0":
            break
        else:
            console.print("[bold red]Invalid option, try again.[/bold red]")

def analyze_single_url():
    """Analyze a single URL for phishing indicators."""
    url = console.input("[bold green]Enter the URL to analyze: [/bold green]")
    
    console.print(f"\n[bold cyan]Analyzing: {url}[/bold cyan]")
    
    # Create results table
    results_table = Table(title="Phishing Analysis Results", show_lines=True)
    results_table.add_column("Check", style="cyan", no_wrap=True)
    results_table.add_column("Result", style="magenta")
    results_table.add_column("Risk Level", style="red")
    
    risk_score = 0
    
    # 1. URL Structure Analysis
    parsed = urlparse(url)
    domain = parsed.netloc
    
    # Check for suspicious URL patterns
    suspicious_patterns = ['secure-', 'verify-', 'update-', 'confirm-', 'account-']
    url_suspicious = any(pattern in url.lower() for pattern in suspicious_patterns)
    if url_suspicious:
        results_table.add_row("Suspicious Keywords", "Found suspicious patterns", "HIGH")
        risk_score += 3
    else:
        results_table.add_row("Suspicious Keywords", "No suspicious patterns", "LOW")
    
    # Check URL length
    if len(url) > 100:
        results_table.add_row("URL Length", f"Very long ({len(url)} chars)", "MEDIUM")
        risk_score += 2
    else:
        results_table.add_row("URL Length", f"Normal ({len(url)} chars)", "LOW")
    
    # Check for IP address instead of domain
    import re
    ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
    if re.search(ip_pattern, domain):
        results_table.add_row("Domain Type", "Uses IP address", "HIGH")
        risk_score += 4
    else:
        results_table.add_row("Domain Type", "Uses domain name", "LOW")
    
    # 2. Domain Analysis
    try:
        # Check domain age
        domain_info = whois.whois(domain)
        if domain_info.creation_date:
            if isinstance(domain_info.creation_date, list):
                creation_date = domain_info.creation_date[0]
            else:
                creation_date = domain_info.creation_date
            
            age_days = (datetime.now() - creation_date).days
            if age_days < 30:
                results_table.add_row("Domain Age", f"Very new ({age_days} days)", "HIGH")
                risk_score += 4
            elif age_days < 365:
                results_table.add_row("Domain Age", f"Recent ({age_days} days)", "MEDIUM")
                risk_score += 2
            else:
                results_table.add_row("Domain Age", f"Established ({age_days} days)", "LOW")
        else:
            results_table.add_row("Domain Age", "Cannot determine", "MEDIUM")
            risk_score += 1
    except Exception as e:
        results_table.add_row("Domain Age", "Cannot retrieve WHOIS", "MEDIUM")
        risk_score += 1
    
    # 3. SSL Certificate Check
    try:
        if url.startswith('https://'):
            response = requests.get(url, timeout=5, verify=True)
            results_table.add_row("SSL Certificate", "Valid HTTPS", "LOW")
        else:
            results_table.add_row("SSL Certificate", "No HTTPS", "HIGH")
            risk_score += 3
    except requests.exceptions.SSLError:
        results_table.add_row("SSL Certificate", "Invalid SSL", "HIGH")
        risk_score += 4
    except Exception as e:
        results_table.add_row("SSL Certificate", "Cannot verify", "MEDIUM")
        risk_score += 2
    
    # 4. Content Analysis
    try:
        response = requests.get(url, timeout=10)
        content = response.text.lower()
        
        # Check for phishing keywords
        phishing_keywords = ['urgent', 'verify account', 'suspended', 'click here', 'act now', 
                           'limited time', 'confirm identity', 'update payment']
        found_keywords = [kw for kw in phishing_keywords if kw in content]
        
        if len(found_keywords) > 3:
            results_table.add_row("Phishing Keywords", f"Found {len(found_keywords)} suspicious terms", "HIGH")
            risk_score += 3
        elif len(found_keywords) > 0:
            results_table.add_row("Phishing Keywords", f"Found {len(found_keywords)} suspicious terms", "MEDIUM")
            risk_score += 2
        else:
            results_table.add_row("Phishing Keywords", "No suspicious keywords", "LOW")
        
        # Check for external redirects
        redirect_count = len(response.history)
        if redirect_count > 3:
            results_table.add_row("Redirects", f"Multiple redirects ({redirect_count})", "HIGH")
            risk_score += 3
        elif redirect_count > 0:
            results_table.add_row("Redirects", f"{redirect_count} redirects", "MEDIUM")
            risk_score += 1
        else:
            results_table.add_row("Redirects", "No redirects", "LOW")
            
    except Exception as e:
        results_table.add_row("Content Analysis", "Cannot analyze content", "MEDIUM")
        risk_score += 1
    
    console.print(results_table)
    
    # Risk Assessment
    if risk_score >= 10:
        risk_level = "[bold red]HIGH RISK - Likely Phishing[/bold red]"
    elif risk_score >= 5:
        risk_level = "[bold yellow]MEDIUM RISK - Suspicious[/bold yellow]"
    else:
        risk_level = "[bold green]LOW RISK - Appears Legitimate[/bold green]"
    
    console.print(f"\n[bold cyan]Overall Risk Score:[/bold cyan] {risk_score}/20")
    console.print(f"[bold cyan]Risk Assessment:[/bold cyan] {risk_level}")
    
    # Recommendations
    console.print(f"\n[bold yellow]Recommendations:[/bold yellow]")
    if risk_score >= 10:
        console.print("🚨 Do NOT enter personal information on this site")
        console.print("🚨 Report this URL to your security team")
        console.print("🚨 Consider blocking this domain")
    elif risk_score >= 5:
        console.print("⚠️  Exercise extreme caution")
        console.print("⚠️  Verify the site through official channels")
        console.print("⚠️  Do not enter sensitive information")
    else:
        console.print("✅ Site appears legitimate")
        console.print("✅ Standard security practices still apply")

def bulk_url_analysis():
    """Analyze multiple URLs for phishing indicators."""
    console.print("[bold yellow]Bulk URL Analysis[/bold yellow]")
    urls_input = console.input("[bold green]Enter URLs separated by commas: [/bold green]")
    urls = [url.strip() for url in urls_input.split(',')]
    
    results = []
    for url in urls:
        console.print(f"\n[bold cyan]Analyzing: {url}[/bold cyan]")
        # Simplified analysis for bulk processing
        risk_score = quick_risk_assessment(url)
        results.append((url, risk_score))
    
    # Summary table
    summary_table = Table(title="Bulk Analysis Summary", show_lines=True)
    summary_table.add_column("URL", style="cyan")
    summary_table.add_column("Risk Score", style="magenta")
    summary_table.add_column("Assessment", style="red")
    
    for url, score in results:
        if score >= 10:
            assessment = "HIGH RISK"
        elif score >= 5:
            assessment = "MEDIUM RISK"
        else:
            assessment = "LOW RISK"
        summary_table.add_row(url[:50] + "..." if len(url) > 50 else url, str(score), assessment)
    
    console.print(summary_table)

def quick_risk_assessment(url):
    """Quick risk assessment for bulk analysis."""
    risk_score = 0
    
    # Basic checks
    suspicious_patterns = ['secure-', 'verify-', 'update-', 'confirm-']
    if any(pattern in url.lower() for pattern in suspicious_patterns):
        risk_score += 3
    
    if len(url) > 100:
        risk_score += 2
    
    if not url.startswith('https://'):
        risk_score += 3
    
    return risk_score

def domain_reputation_check():
    """Check domain reputation and basic information."""
    domain = console.input("[bold green]Enter domain to check: [/bold green]")
    
    console.print(f"\n[bold cyan]Domain Reputation Check: {domain}[/bold cyan]")
    
    try:
        # WHOIS lookup
        domain_info = whois.whois(domain)
        
        info_table = Table(title="Domain Information", show_lines=True)
        info_table.add_column("Field", style="cyan")
        info_table.add_column("Value", style="magenta")
        
        if domain_info.creation_date:
            creation_date = domain_info.creation_date[0] if isinstance(domain_info.creation_date, list) else domain_info.creation_date
            info_table.add_row("Creation Date", str(creation_date))
            
            # Calculate and display domain age
            age_days = (datetime.now() - creation_date).days
            info_table.add_row("Domain Age", f"{age_days} days")
        
        if domain_info.registrar:
            info_table.add_row("Registrar", str(domain_info.registrar))
        
        if domain_info.country:
            info_table.add_row("Country", str(domain_info.country))
        
        console.print(info_table)
        
    except Exception as e:
        console.print(f"[bold red]Error retrieving domain information: {e}[/bold red]")

def osint_suite():
    """Comprehensive OSINT (Open Source Intelligence) Suite."""
    while True:
        console.print("\n[bold blue]═══ OSINT (Open Source Intelligence) Suite ═══[/bold blue]")
        console.print("[1] 👤 Social Media Account OSINT")
        console.print("[2] 🌐 Domain/IP Intelligence")
        console.print("[3] 📱 Phone Number Intelligence")
        console.print("[4] 📧 Email Address Investigation")
        console.print("[5] 🔍 Username Search Across Platforms")
        console.print("[6] 🗂️  Automatic Data Breach Check")  # Updated
        console.print("[7] 📋 WHOIS Domain Lookup")  # New
        console.print("[0] ⬅️  Back to Main Menu\n")
        choice = console.input("[bold green]Choose OSINT method: [/bold green]")

        if choice == "1":
            social_media_osint()
        elif choice == "2":
            domain_ip_osint()
        elif choice == "3":
            phone_number_osint()
        elif choice == "4":
            email_investigation()
        elif choice == "5":
            username_search()
        elif choice == "6":
            data_breach_check()
        elif choice == "7":
            whois_lookup()  # New
        elif choice == "0":
            break
        else:
            console.print("[bold red]Invalid option, try again.[/bold red]")

def social_media_osint():
    """Social Media Account OSINT."""
    console.print("\n[bold yellow]Social Media Account OSINT[/bold yellow]")
    target = console.input("[bold green]Enter username or social media handle: [/bold green]")
    
    # Common social media platforms
    platforms = {
        "Twitter": f"https://twitter.com/{target}",
        "Instagram": f"https://instagram.com/{target}",
        "Facebook": f"https://facebook.com/{target}",
        "LinkedIn": f"https://linkedin.com/in/{target}",
        "GitHub": f"https://github.com/{target}",
        "Reddit": f"https://reddit.com/user/{target}",
        "TikTok": f"https://tiktok.com/@{target}",
        "YouTube": f"https://youtube.com/@{target}",
        "Pinterest": f"https://pinterest.com/{target}",
        "Snapchat": f"https://snapchat.com/add/{target}"
    }
    
    results_table = Table(title=f"Social Media Presence Check: {target}", show_lines=True)
    results_table.add_column("Platform", style="cyan")
    results_table.add_column("URL", style="magenta")
    results_table.add_column("Status", style="green")
    
    console.print(f"\n[bold cyan]Checking social media presence for: {target}[/bold cyan]")
    
    for platform, url in platforms.items():
        try:
            response = requests.get(url, timeout=5, allow_redirects=True)
            if response.status_code == 200:
                status = "✅ Found"
                results_table.add_row(platform, url, status)
            else:
                status = "❌ Not Found"
        except:
            status = "⚠️  Error"
        
        console.print(f"{platform}: {status}")
    
    console.print(results_table)
    console.print("[yellow]Note: Results show potential accounts. Manual verification required.[/yellow]")

def domain_ip_osint():
    """Advanced Domain and IP Intelligence."""
    console.print("\n[bold yellow]Domain/IP Intelligence Gathering[/bold yellow]")
    target = console.input("[bold green]Enter domain or IP address: [/bold green]")
    
    # Check if it's an IP or domain
    if validate_ip(target):
        console.print(f"[cyan]Analyzing IP: {target}[/cyan]")
        track_ip(target)  # Reuse existing function
    else:
        console.print(f"[cyan]Analyzing Domain: {target}[/cyan]")
        
        # Domain analysis
        try:
            # Get IP from domain
            ip = socket.gethostbyname(target)
            console.print(f"[cyan]Resolved to IP: {ip}[/cyan]")
            
            # WHOIS information
            domain_info = whois.whois(target)
            
            domain_table = Table(title="Domain Intelligence", show_lines=True)
            domain_table.add_column("Field", style="cyan")
            domain_table.add_column("Value", style="magenta")
            
            if domain_info.creation_date:
                creation_date = domain_info.creation_date[0] if isinstance(domain_info.creation_date, list) else domain_info.creation_date
                domain_table.add_row("Creation Date", str(creation_date))
                age_days = (datetime.now() - creation_date).days
                domain_table.add_row("Domain Age", f"{age_days} days")
            
            if domain_info.registrar:
                domain_table.add_row("Registrar", str(domain_info.registrar))
            
            if domain_info.emails:
                emails = domain_info.emails if isinstance(domain_info.emails, list) else [domain_info.emails]
                domain_table.add_row("Contact Emails", ", ".join(emails))
            
            console.print(domain_table)
            
            # Get IP geolocation
            track_ip(ip)
            
        except Exception as e:
            console.print(f"[bold red]Error analyzing domain: {e}[/bold red]")

def phone_number_osint():
    """Enhanced Phone Number OSINT."""
    console.print("\n[bold yellow]Phone Number Intelligence[/bold yellow]")
    number = console.input("[bold green]Enter phone number with country code (e.g. +1234567890): [/bold green]")
    
    try:
        parsed = phonenumbers.parse(number, None)
        country = geocoder.description_for_number(parsed, "en")
        carrier_name = carrier.name_for_number(parsed, "en")
        
        # Enhanced phone analysis
        phone_table = Table(title=f"Phone Number Intelligence: {number}", show_lines=True)
        phone_table.add_column("Field", style="cyan")
        phone_table.add_column("Value", style="magenta")
        
        phone_table.add_row("Country/Region", country or 'Unknown')
        phone_table.add_row("Carrier/Network", carrier_name or 'Unknown')
        phone_table.add_row("Number Type", 'Mobile' if phonenumbers.number_type(parsed) == phonenumbers.PhoneNumberType.MOBILE else 'Landline/Other')
        phone_table.add_row("International Format", phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.INTERNATIONAL))
        phone_table.add_row("National Format", phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.NATIONAL))
        phone_table.add_row("Is Valid", "Yes" if phonenumbers.is_valid_number(parsed) else "No")
        
        # Additional OSINT checks
        phone_table.add_row("Possible Spam Risk", "Check manually on truecaller.com")
        phone_table.add_row("Social Media Links", f"Search '{number}' on Facebook/LinkedIn")
        
        console.print(phone_table)
        console.print("[yellow]Note: For deeper investigation, check social media platforms and reverse lookup services.[/yellow]")
        
    except Exception as e:
        console.print(f"[bold red]Error analyzing phone number: {e}[/bold red]")

def email_investigation():
    """Email Address OSINT and Investigation."""
    console.print("\n[bold yellow]Email Address Investigation[/bold yellow]")
    email = console.input("[bold green]Enter email address: [/bold green]")
    
    # Basic email validation
    email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    if not re.match(email_pattern, email):
        console.print("[bold red]Invalid email format![/bold red]")
        return
    
    domain = email.split('@')[1]
    username = email.split('@')[0]
    
    email_table = Table(title=f"Email Intelligence: {email}", show_lines=True)
    email_table.add_column("Field", style="cyan")
    email_table.add_column("Value", style="magenta")
    
    email_table.add_row("Username", username)
    email_table.add_row("Domain", domain)
    
    # Check if domain exists
    try:
        ip = socket.gethostbyname(domain)
        email_table.add_row("Domain IP", ip)
        email_table.add_row("Domain Status", "✅ Active")
    except:
        email_table.add_row("Domain Status", "❌ Invalid/Inactive")
    
    # Common email providers
    providers = {
        'gmail.com': 'Google Gmail',
        'yahoo.com': 'Yahoo Mail',
        'outlook.com': 'Microsoft Outlook',
        'hotmail.com': 'Microsoft Hotmail',
        'protonmail.com': 'ProtonMail (Privacy-focused)'
    }
    
    provider = providers.get(domain, 'Custom/Business Domain')
    email_table.add_row("Email Provider", provider)
    
    console.print(email_table)
    
    # Suggest further investigation
    console.print(f"\n[bold yellow]Suggested Investigation Steps:[/bold yellow]")
    console.print(f"🔍 Search '{username}' on social media platforms")
    console.print(f"🔍 Check if email appears in data breaches")
    console.print(f"🔍 Search '{email}' in public records")
    console.print(f"🔍 Check domain registration info for custom domains")

def username_search():
    """Username Search Across Multiple Platforms."""
    console.print("\n[bold yellow]Username Search Across Platforms[/bold yellow]")
    username = console.input("[bold green]Enter username to search: [/bold green]")
    
    # Extended list of platforms
    platforms = {
        # Social Media
        "Facebook": f"https://facebook.com/{username}",
        "Twitter": f"https://twitter.com/{username}",
        "Instagram": f"https://instagram.com/{username}",
        "LinkedIn": f"https://linkedin.com/in/{username}",
        "TikTok": f"https://tiktok.com/@{username}",
        "Snapchat": f"https://snapchat.com/add/{username}",
        "Pinterest": f"https://pinterest.com/{username}",
        # Professional/Dev
        "GitHub": f"https://github.com/{username}",
        "GitLab": f"https://gitlab.com/{username}",
        "Stack Overflow": f"https://stackoverflow.com/users/{username}",
        # Gaming
        "Twitch": f"https://twitch.tv/{username}",
        "Steam": f"https://steamcommunity.com/id/{username}",
        # Other
        "Reddit": f"https://reddit.com/user/{username}",
        "Medium": f"https://medium.com/@{username}",
        "YouTube": f"https://youtube.com/@{username}"
    }
    
    console.print(f"\n[bold cyan]Searching for username '{username}' across platforms...[/bold cyan]")
    
    found_platforms = []
    
    with Progress() as progress:
        task = progress.add_task("[cyan]Checking platforms...", total=len(platforms))
        
        for platform, url in platforms.items():
            try:
                response = requests.get(url, timeout=5, allow_redirects=True)
                if response.status_code == 200:
                    found_platforms.append((platform, url))
                    console.print(f"✅ {platform}: {url}")
                else:
                    console.print(f"❌ {platform}: Not found")
            except:
                console.print(f"⚠️  {platform}: Error checking")
            
            progress.update(task, advance=1)
    
    # Summary
    if found_platforms:
        console.print(f"\n[bold green]Found '{username}' on {len(found_platforms)} platforms:[/bold green]")
        for platform, url in found_platforms:
            console.print(f"• {platform}: {url}")
    else:
        console.print(f"[bold red]Username '{username}' not found on any checked platforms.[/bold red]")

def data_breach_check():
    """Automatic Data Breach Check using HaveIBeenPwned API."""
    console.print("\n[bold yellow]Automatic Data Breach Check[/bold yellow]")
    email = console.input("[bold green]Enter email address to check: [/bold green]")
    
    # Basic email validation
    email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    if not re.match(email_pattern, email):
        console.print("[bold red]Invalid email format![/bold red]")
        return
    
    console.print(f"\n[bold cyan]Checking breaches for: {email}[/bold cyan]")
    console.print("[yellow]Querying HaveIBeenPwned database...[/yellow]")
    
    try:
        # HaveIBeenPwned API endpoint (v2 - no API key required but rate limited)
        api_url = f"https://haveibeenpwned.com/api/v2/breachedaccount/{email}"
        headers = {
            "User-Agent": "Entity-Security-Tool-Educational-Use",
            "Accept": "application/json"
        }
        
        # Make API request
        response = requests.get(api_url, headers=headers, timeout=10)
        
        if response.status_code == 200:
            breaches = response.json()
            
            if breaches:
                console.print(f"[bold red]⚠️  {len(breaches)} breach(es) found for {email}![/bold red]")
                
                # Create detailed breach table
                breach_table = Table(title=f"Data Breaches for {email}", show_lines=True)
                breach_table.add_column("Breach Name", style="cyan")
                breach_table.add_column("Date", style="yellow")
                breach_table.add_column("Compromised Data", style="red")
                breach_table.add_column("Verified", style="green")
                
                for breach in breaches:
                    breach_name = breach.get('Name', 'Unknown')
                    breach_date = breach.get('BreachDate', 'Unknown')
                    data_classes = ', '.join(breach.get('DataClasses', []))
                    is_verified = "✅ Yes" if breach.get('IsVerified') else "❌ No"
                    
                    breach_table.add_row(breach_name, breach_date, data_classes, is_verified)
                
                console.print(breach_table)
                
                # Security recommendations
                console.print(f"\n[bold yellow]🚨 Security Recommendations:[/bold yellow]")
                console.print("1. [red]Change passwords[/red] for all affected accounts immediately")
                console.print("2. [yellow]Enable two-factor authentication (2FA)[/yellow] where possible")
                console.print("3. [cyan]Monitor your accounts[/cyan] for suspicious activity")
                console.print("4. [green]Use a password manager[/green] with unique passwords")
                console.print("5. [magenta]Check credit reports[/magenta] if financial data was compromised")
                
                # Risk level assessment
                risk_level = "HIGH" if len(breaches) > 3 else "MEDIUM" if len(breaches) > 1 else "LOW"
                console.print(f"\n[bold red]Risk Level: {risk_level}[/bold red]")
                
            else:
                console.print(f"[bold green]✅ Good news! No breaches found for {email}[/bold green]")
                console.print("[green]This email address does not appear in any known data breaches.[/green]")
        
        elif response.status_code == 404:
            console.print(f"[bold green]✅ Good news! No breaches found for {email}[/bold green]")
            console.print("[green]This email address does not appear in any known data breaches.[/green]")
        
        elif response.status_code == 429:
            console.print("[bold yellow]⚠️  Rate limit exceeded. Please try again in a few minutes.[/bold yellow]")
            console.print("[yellow]HaveIBeenPwned limits requests to prevent abuse.[/yellow]")
            
            # Fall back to manual instructions
            manual_breach_check_fallback(email)
        
        elif response.status_code == 403:
            console.print("[bold yellow]⚠️  API access restricted. Using alternative method...[/bold yellow]")
            manual_breach_check_fallback(email)
        
        else:
            console.print(f"[bold red]Error checking breaches: HTTP {response.status_code}[/bold red]")
            manual_breach_check_fallback(email)
            
    except requests.exceptions.RequestException as e:
        console.print(f"[bold red]Network error: {e}[/bold red]")
        console.print("[yellow]Falling back to manual check instructions...[/yellow]")
        manual_breach_check_fallback(email)
    
    except Exception as e:
        console.print(f"[bold red]Unexpected error: {e}[/bold red]")
        manual_breach_check_fallback(email)

def manual_breach_check_fallback(email):
    """Fallback to manual breach checking when API is unavailable."""
    console.print(f"\n[bold cyan]Manual Breach Check for: {email}[/bold cyan]")
    
    # Provide information about breach checking services
    breach_table = Table(title="Breach Check Services", show_lines=True)
    breach_table.add_column("Service", style="cyan")
    breach_table.add_column("URL", style="magenta")
    breach_table.add_column("Type", style="yellow")
    
    breach_services = [
        ("Have I Been Pwned", "https://haveibeenpwned.com", "Free"),
        ("DeHashed", "https://dehashed.com", "Paid"),
        ("LeakCheck", "https://leakcheck.io", "Freemium"),
        ("BreachDirectory", "https://breachdirectory.org", "Free"),
        ("IntelligenceX", "https://intelx.io", "Freemium")
    ]
    
    for service, url, type_info in breach_services:
        breach_table.add_row(service, url, type_info)
    
    console.print(breach_table)
    
    console.print(f"\n[bold yellow]Manual Check Instructions:[/bold yellow]")
    console.print(f"1. Visit: [cyan]https://haveibeenpwned.com[/cyan]")
    console.print(f"2. Enter the email: [green]{email}[/green]")
    console.print(f"3. Check the results for any data breaches")
    console.print(f"4. If found, review which data was compromised")
    console.print(f"5. Change passwords for affected accounts immediately")
    
def whois_lookup():
    """Comprehensive WHOIS Domain Lookup."""
    console.print("\n[bold yellow]WHOIS Domain Lookup[/bold yellow]")
    domain = console.input("[bold green]Enter domain name (e.g., example.com): [/bold green]")
    
    # Remove protocol if present
    if domain.startswith(('http://', 'https://')):
        domain = domain.split('://')[1]
    if '/' in domain:
        domain = domain.split('/')[0]
    
    console.print(f"\n[bold cyan]Performing WHOIS lookup for: {domain}[/bold cyan]")
    
    try:
        # Perform WHOIS lookup
        domain_info = whois.whois(domain)
        
        # Create comprehensive WHOIS table
        whois_table = Table(title=f"WHOIS Information for {domain}", show_lines=True)
        whois_table.add_column("Field", style="cyan", no_wrap=True)
        whois_table.add_column("Value", style="magenta")
        
        # Domain Registration Info
        if domain_info.domain_name:
            domain_name = domain_info.domain_name
            if isinstance(domain_name, list):
                domain_name = domain_name[0]
            whois_table.add_row("Domain Name", str(domain_name))

        if domain_info.registrar:
            whois_table.add_row("Registrar", str(domain_info.registrar))
        
        if domain_info.creation_date:
            creation_date = domain_info.creation_date
            if isinstance(creation_date, list):
                creation_date = creation_date[0]
            whois_table.add_row("Creation Date", str(creation_date))
            
            # Calculate domain age
            age_days = (datetime.now() - creation_date).days
            whois_table.add_row("Domain Age", f"{age_days} days ({age_days // 365} years)")
        
        if domain_info.expiration_date:
            expiration_date = domain_info.expiration_date
            if isinstance(expiration_date, list):
                expiration_date = expiration_date[0]
            whois_table.add_row("Expiration Date", str(expiration_date))
            
            # Days until expiration
            days_until_expiry = (expiration_date - datetime.now()).days
            if days_until_expiry < 30:
                whois_table.add_row("Expiry Status", f"⚠️  Expires in {days_until_expiry} days")
            else:
                whois_table.add_row("Expiry Status", f"✅ {days_until_expiry} days remaining")
        
        if domain_info.updated_date:
            updated_date = domain_info.updated_date
            if isinstance(updated_date, list):
                updated_date = updated_date[0]
            whois_table.add_row("Last Updated", str(updated_date))
        
        # Contact Information
        if domain_info.registrant_name:
            whois_table.add_row("Registrant Name", str(domain_info.registrant_name))
        
        if domain_info.registrant_organization:
            whois_table.add_row("Organization", str(domain_info.registrant_organization))
        
        if domain_info.registrant_country:
            whois_table.add_row("Country", str(domain_info.registrant_country))
        
        # Email contacts
        if domain_info.emails:
            emails = domain_info.emails
            if isinstance(emails, list):
                emails = ', '.join(emails)
            whois_table.add_row("Contact Emails", str(emails))
        
        # Name servers
        if domain_info.name_servers:
            name_servers = domain_info.name_servers
            if isinstance(name_servers, list):
                name_servers = '\n'.join(name_servers)
            whois_table.add_row("Name Servers", str(name_servers))
        
        # Status
        if domain_info.status:
            status = domain_info.status
            if isinstance(status, list):
                status = '\n'.join(status)
            whois_table.add_row("Domain Status", str(status))
        
        console.print(whois_table)
        
        # Security Analysis
        console.print(f"\n[bold yellow]Security Analysis:[/bold yellow]")
        
        # Check domain age for suspicion
        if domain_info.creation_date:
            creation_date = domain_info.creation_date[0] if isinstance(domain_info.creation_date, list) else domain_info.creation_date
            age_days = (datetime.now() - creation_date).days
            
            if age_days < 30:
                console.print("🚨 [bold red]Very new domain (< 30 days) - High risk for phishing[/bold red]")
            elif age_days < 365:
                console.print("⚠️  [yellow]Recently registered domain (< 1 year) - Medium risk[/yellow]")
            else:
                console.print("✅ [green]Established domain (> 1 year) - Lower risk[/green]")
        
        # Check for privacy protection
        if domain_info.registrant_name and 'privacy' in str(domain_info.registrant_name).lower():
            console.print("🔒 [cyan]Privacy protection enabled - Contact details hidden[/cyan]")
        
        # Additional investigation suggestions
        console.print(f"\n[bold yellow]Additional Investigation:[/bold yellow]")
        console.print(f"🔍 Check registrar reputation: {domain_info.registrar if domain_info.registrar else 'Unknown'}")
        console.print(f"🔍 Investigate contact emails for other domains")
        console.print(f"🔍 Check historical WHOIS data for changes")
        console.print(f"🔍 Analyze name servers for hosting patterns")
        
    except Exception as e:
        console.print(f"[bold red]Error performing WHOIS lookup: {e}[/bold red]")
        console.print("[yellow]This could be due to:[/yellow]")
        console.print("• Domain doesn't exist")
        console.print("• WHOIS service temporarily unavailable")
        console.print("• Privacy protection blocking data")
        console.print("• Network connectivity issues")

def show_about():
    """Displays information about the Entity toolkit."""
    console.print("\n[bold blue]═══ About Entity v1.0 ═══[/bold blue]")
    about_text = """
    [bold]Entity[/bold] is a multi-purpose cybersecurity toolkit designed for educational purposes, security professionals, and ethical hackers. It combines several key functions into a single, easy-to-use command-line interface.

    [bold cyan]Author:[/bold cyan] Felix Gyau Boateng (Lil-Junior)
    [bold yellow]Organization:[/bold yellow] Blue Scavengers Security
    [bold green]Version:[/bold green] 1.0 (July 2025)

    [bold]Disclaimer:[/bold] This tool is intended for educational and authorized security testing purposes only. The author is not responsible for any misuse or damage caused by this program. Always act ethically and with permission.
    """
    console.print(about_text)
    console.input("\n[yellow]Press Enter to return to the main menu...[/yellow]")


def main():
    show_banner()
    while True:
        console.print("\n[bold blue]═══ Welcome to Entity - Advanced Security Toolkit ═══[/bold blue]\n")
        console.print("[1] 🔍 Vulnerability Scanner")
        console.print("[2] 🌍 IP Geolocation & Analysis")
        console.print("[3] 🕵️  OSINT (Open Source Intelligence)")
        console.print("[4] 🛡️  Phishing Page Detector")
        console.print("[5] ℹ️  About This Tool")
        console.print("[0] ❌ Exit\n")
        choice = console.input("[bold green]Choose an Option: [/bold green]")

        if choice == '1':
            vulnerability_scanner()
        elif choice == '2':
            ip_geolocation_tracker()
        elif choice == '3':
            osint_suite()
        elif choice == '4':
            phishing_page_detector()
        elif choice == '5':
            show_about()
        elif choice == '0':
            console.print("[bold red]Exiting... Stay ethical and secure![/bold red]")
            break
        else:
            console.print("[bold red]Invalid option, try again.[/bold red]")

if __name__ == "__main__":
    main()