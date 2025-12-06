"""
Entity Network Scanner Module
============================
Enhanced port scanning capabilities with nmap-like features.
"""

import socket
from concurrent.futures import ThreadPoolExecutor
from typing import List, Dict, Tuple

from rich.progress import Progress
from rich.table import Table
from entity import console


class NetworkScanner:
    """Network scanning functionality with enhanced capabilities."""
    
    def __init__(self, threads: int = 50, timeout: int = 1):
        self.threads = threads
        self.timeout = timeout
        self.open_ports = []
        
        # Enhanced service detection database
        self.service_map = {
            # Common services
            21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
            80: "HTTP", 110: "POP3", 135: "RPC", 139: "NetBIOS", 143: "IMAP",
            443: "HTTPS", 445: "SMB", 993: "IMAPS", 995: "POP3S",
            
            # Database services
            1433: "MSSQL", 1521: "Oracle", 3306: "MySQL", 5432: "PostgreSQL", 
            6379: "Redis", 27017: "MongoDB",
            
            # Remote access
            3389: "RDP", 5900: "VNC", 5901: "VNC", 5902: "VNC",
            
            # VMware services
            902: "VMware-Auth", 912: "VMware-Auth",
            
            # Mail services
            587: "SMTP-Submission", 465: "SMTPS", 585: "IMAP4-SSL",
            
            # Web services
            8080: "HTTP-Alt", 8443: "HTTPS-Alt", 8000: "HTTP-Dev", 9000: "HTTP-Dev",
            
            # Other common ports
            161: "SNMP", 162: "SNMP-Trap", 389: "LDAP", 636: "LDAPS",
            1723: "PPTP", 1194: "OpenVPN", 500: "IPSec", 4500: "IPSec-NAT"
        }

    def grab_banner(self, sock: socket.socket, port: int) -> str:
        """Intelligent banner grabbing based on service type."""
        try:
            sock.settimeout(2)  # Longer timeout for banner grab
            
            # HTTP/HTTPS services
            if port in [80, 443, 8080, 8443, 8000, 9000]:
                sock.sendall(b"HEAD / HTTP/1.1\r\nHost: target\r\nConnection: close\r\n\r\n")
                banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                return banner[:200] if banner else "No HTTP response"
            
            # SSH service
            elif port == 22:
                banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                return banner[:100] if banner else "No SSH banner"
            
            # FTP service
            elif port == 21:
                banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                return banner[:100] if banner else "No FTP banner"
            
            # SMTP service
            elif port in [25, 587, 465]:
                banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                return banner[:100] if banner else "No SMTP banner"
            
            # Telnet service
            elif port == 23:
                banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                return banner[:100] if banner else "No Telnet banner"
            
            # SMB/NetBIOS (Windows services)
            elif port in [135, 139, 445]:
                return "Windows service (binary protocol)"
            
            # VMware services
            elif port in [902, 912]:
                return "VMware authentication service"
            
            # Database services (don't grab banners - could be intrusive)
            elif port in [1433, 1521, 3306, 5432, 6379, 27017]:
                return "Database service (banner not grabbed)"
            
            # RDP service
            elif port == 3389:
                return "RDP service (binary protocol)"
            
            # Generic banner grab for unknown services
            else:
                # Try to read any initial banner
                banner = sock.recv(512).decode('utf-8', errors='ignore').strip()
                return banner[:100] if banner else "No banner available"
                
        except socket.timeout:
            return "Banner timeout"
        except Exception as e:
            return f"Banner error: {str(e)[:30]}"

    def scan_port(self, target: str, port: int, progress: Progress, task) -> Dict:
        """Scan single port with enhanced banner grabbing."""
        result = {"port": port, "status": "closed", "service": "", "banner": ""}
        
        try:
            with socket.create_connection((target, port), timeout=self.timeout) as sock:
                result["status"] = "open"
                result["service"] = self.service_map.get(port, "unknown")
                result["banner"] = self.grab_banner(sock, port)
                
                self.open_ports.append(port)
                console.print(f"[green]Port {port} ({result['service']}) - OPEN[/green]")
                
        except (socket.timeout, ConnectionRefusedError, OSError):
            pass
        finally:
            progress.update(task, advance=1)
            
        return result
    
    def perform_scan(self, target: str, port_range: Tuple[int, int] = (1, 1024)) -> List[Dict]:
        """Perform comprehensive port scan."""
        console.print(f"[yellow]Scanning {target} ports {port_range[0]}-{port_range[1]}...[/yellow]")
        
        results = []
        self.open_ports = []
        total_ports = port_range[1] - port_range[0] + 1
        
        with Progress() as progress:
            task = progress.add_task("[cyan]Scanning ports...", total=total_ports)
            
            with ThreadPoolExecutor(max_workers=self.threads) as executor:
                futures = []
                for port in range(port_range[0], port_range[1] + 1):
                    future = executor.submit(self.scan_port, target, port, progress, task)
                    futures.append(future)
                
                for future in futures:
                    result = future.result()
                    if result["status"] == "open":
                        results.append(result)
        
        if not results:
            console.print("[red]No open ports found in specified range[/red]")
        else:
            self.display_scan_results(results)
            
        return results
    
    def display_scan_results(self, results: List[Dict]):
        """Display scan results in organized table."""
        table = Table(title="Port Scan Results", show_lines=True)
        table.add_column("Port", style="cyan")
        table.add_column("Service", style="green")
        table.add_column("Status", style="yellow")
        table.add_column("Banner", style="magenta")
        
        for result in results:
            table.add_row(
                str(result["port"]),
                result["service"],
                result["status"].upper(),
                result["banner"][:50] + "..." if len(result["banner"]) > 50 else result["banner"]
            )
        
        console.print(table)
    
    def analyze_vulnerabilities(self, results: List[Dict]) -> List[str]:
        """Analyze potential vulnerabilities based on open ports."""
        vulnerability_db = {
            21: "FTP: Anonymous login, cleartext credentials, brute-force",
            22: "SSH: Brute-force attacks, weak encryption, default credentials",
            23: "Telnet: Cleartext credentials, man-in-the-middle",
            25: "SMTP: Open relay, spam, credential attacks",
            53: "DNS: Zone transfer, cache poisoning, amplification attacks",
            80: "HTTP: XSS, SQLi, directory traversal, weak authentication",
            135: "RPC: Buffer overflow, privilege escalation",
            139: "NetBIOS: Information disclosure, null session attacks",
            443: "HTTPS: SSL/TLS vulnerabilities, certificate issues",
            445: "SMB: EternalBlue, null sessions, credential attacks",
            3389: "RDP: Brute-force, BlueKeep, weak encryption",
            5900: "VNC: Weak authentication, unencrypted connections"
        }
        
        vulnerabilities = []
        for result in results:
            port = result["port"]
            if port in vulnerability_db:
                vulnerabilities.append(f"Port {port}: {vulnerability_db[port]}")
        
        return vulnerabilities
