"""
Entity User Interface Module
===========================
Clean CLI interface with proper separation of concerns.
"""

import pyfiglet
from rich.console import Console

from entity.modules.network_scanner import NetworkScanner
from entity.modules.geolocation import GeolocationTracker
from entity.utils.validators import validate_target, validate_ip_address


class EntityInterface:
    """Main user interface for Entity toolkit."""
    
    def __init__(self):
        self.console = Console()
        self.network_scanner = NetworkScanner()
        self.geolocation_tracker = GeolocationTracker()
    
    def display_banner(self):
        """Display Entity banner."""
        banner = pyfiglet.figlet_format('Entity', font='univers')
        self.console.print(f"[bold cyan]{banner}[/bold cyan]")
        self.console.print("[bold yellow]Entity v2.0 by Blue Scavengers Security[/bold yellow]")
        self.console.print("[bold green]Author: Gyau Boateng[/bold green]")
        self.console.print("[bold blue]Restructured & Enhanced[/bold blue]\n")
    
    def display_main_menu(self):
        """Display main menu options."""
        self.console.print("[bold blue]═══ Entity - Advanced Security Toolkit ═══[/bold blue]\n")
        self.console.print("[1] 🔍 Network Vulnerability Scanner")
        self.console.print("[2] 🌍 IP Geolocation & Analysis") 
        self.console.print("[3] 🕵️  OSINT Intelligence Suite")
        self.console.print("[4] 🛡️  Phishing Detection Engine")
        self.console.print("[5] ℹ️  About Entity")
        self.console.print("[0] ❌ Exit\n")
    
    def get_user_choice(self) -> str:
        """Get user menu choice."""
        return self.console.input("[bold green]Choose an option: [/bold green]")
    
    def handle_network_scanner(self):
        """Handle network scanning functionality."""
        while True:
            self.console.print("\n[bold blue]Network Scanner Menu[/bold blue]")
            self.console.print("[1] Quick Port Scan (1-1024)")
            self.console.print("[2] Full Port Scan (1-65535)")
            self.console.print("[3] Custom Port Range")
            self.console.print("[4] Vulnerability Analysis")
            self.console.print("[0] Back to Main Menu\n")
            
            choice = self.console.input("[bold green]Select scan type: [/bold green]")
            
            if choice == '1':
                self._perform_port_scan((1, 1024))
            elif choice == '2':
                self._perform_port_scan((1, 65535))
            elif choice == '3':
                self._custom_port_scan()
            elif choice == '4':
                self._vulnerability_analysis()
            elif choice == '0':
                break
            else:
                self.console.print("[red]Invalid option. Please try again.[/red]")
    
    def handle_geolocation(self):
        """Handle geolocation functionality."""
        while True:
            self.console.print("\n[bold blue]Geolocation Analysis Menu[/bold blue]")
            self.console.print("[1] Analyze IP Address")
            self.console.print("[2] Analyze Domain")
            self.console.print("[3] Get My Public IP")
            self.console.print("[4] Bulk IP Analysis")
            self.console.print("[0] Back to Main Menu\n")
            
            choice = self.console.input("[bold green]Select analysis type: [/bold green]")
            
            if choice == '1':
                self._analyze_ip()
            elif choice == '2':
                self._analyze_domain()
            elif choice == '3':
                self._get_public_ip()
            elif choice == '4':
                self._bulk_ip_analysis()
            elif choice == '0':
                break
            else:
                self.console.print("[red]Invalid option. Please try again.[/red]")
    
    def _perform_port_scan(self, port_range):
        """Perform port scan with specified range."""
        target = self.console.input("[bold green]Enter target IP or domain: [/bold green]")
        
        if not validate_target(target):
            self.console.print("[red]Invalid target format![/red]")
            return
        
        # Resolve domain to IP if needed
        if not validate_ip_address(target):
            ip = self.geolocation_tracker.resolve_domain_to_ip(target)
            if not ip:
                return
            target = ip
        
        results = self.network_scanner.perform_scan(target, port_range)
        
        if results:
            vulnerabilities = self.network_scanner.analyze_vulnerabilities(results)
            if vulnerabilities:
                self.console.print("\n[bold red]Potential Vulnerabilities:[/bold red]")
                for vuln in vulnerabilities:
                    self.console.print(f"[yellow]• {vuln}[/yellow]")
    
    def _custom_port_scan(self):
        """Handle custom port range scanning."""
        target = self.console.input("[bold green]Enter target IP or domain: [/bold green]")
        
        if not validate_target(target):
            self.console.print("[red]Invalid target format![/red]")
            return
        
        try:
            start_port = int(self.console.input("[bold green]Start port: [/bold green]"))
            end_port = int(self.console.input("[bold green]End port: [/bold green]"))
            
            if not (1 <= start_port <= 65535) or not (1 <= end_port <= 65535):
                self.console.print("[red]Port range must be between 1-65535![/red]")
                return
            
            if start_port > end_port:
                self.console.print("[red]Start port must be less than end port![/red]")
                return
            
            self._perform_port_scan((start_port, end_port))
            
        except ValueError:
            self.console.print("[red]Invalid port numbers![/red]")
    
    def _vulnerability_analysis(self):
        """Perform vulnerability analysis on target."""
        target = self.console.input("[bold green]Enter target for vulnerability analysis: [/bold green]")
        
        if not validate_target(target):
            self.console.print("[red]Invalid target format![/red]")
            return
        
        self.console.print("[yellow]Performing comprehensive vulnerability scan...[/yellow]")
        results = self.network_scanner.perform_scan(target, (1, 1024))
        
        if results:
            vulnerabilities = self.network_scanner.analyze_vulnerabilities(results)
            self.console.print(f"\n[bold cyan]Vulnerability Analysis Complete[/bold cyan]")
            self.console.print(f"Found {len(results)} open ports")
            
            if vulnerabilities:
                self.console.print(f"\n[bold red]Security Concerns ({len(vulnerabilities)} found):[/bold red]")
                for i, vuln in enumerate(vulnerabilities, 1):
                    self.console.print(f"[red]{i}. {vuln}[/red]")
            else:
                self.console.print("[green]No immediate vulnerability concerns detected[/green]")
    
    def _analyze_ip(self):
        """Analyze single IP address."""
        ip = self.console.input("[bold green]Enter IP address: [/bold green]")
        result = self.geolocation_tracker.analyze_ip(ip)
        
        if "error" in result:
            self.console.print(f"[red]Error: {result['error']}[/red]")
    
    def _analyze_domain(self):
        """Analyze domain name."""
        domain = self.console.input("[bold green]Enter domain name: [/bold green]")
        ip = self.geolocation_tracker.resolve_domain_to_ip(domain)
        
        if ip:
            result = self.geolocation_tracker.analyze_ip(ip)
            if "error" in result:
                self.console.print(f"[red]Error: {result['error']}[/red]")
    
    def _get_public_ip(self):
        """Get and analyze user's public IP."""
        self.console.print("[yellow]Fetching your public IP...[/yellow]")
        ip = self.geolocation_tracker.get_public_ip()
        
        if ip:
            self.console.print(f"[cyan]Your public IP: {ip}[/cyan]")
            result = self.geolocation_tracker.analyze_ip(ip)
            if "error" in result:
                self.console.print(f"[red]Error: {result['error']}[/red]")
        else:
            self.console.print("[red]Failed to retrieve public IP[/red]")
    
    def _bulk_ip_analysis(self):
        """Analyze multiple IP addresses."""
        ips_input = self.console.input("[bold green]Enter IPs (comma-separated): [/bold green]")
        ips = [ip.strip() for ip in ips_input.split(',')]
        
        for ip in ips:
            if validate_ip_address(ip):
                self.console.print(f"\n[bold cyan]Analyzing {ip}...[/bold cyan]")
                result = self.geolocation_tracker.analyze_ip(ip)
                if "error" in result:
                    self.console.print(f"[red]Error: {result['error']}[/red]")
            else:
                self.console.print(f"[red]Skipping invalid IP: {ip}[/red]")
    
    def display_about(self):
        """Display about information."""
        self.console.print("\n[bold blue]About Entity v2.0[/bold blue]")
        self.console.print("[cyan]Entity is a comprehensive cybersecurity toolkit designed for:[/cyan]")
        self.console.print("• Network vulnerability assessment")
        self.console.print("• IP geolocation and analysis") 
        self.console.print("• OSINT (Open Source Intelligence)")
        self.console.print("• Phishing detection and analysis")
        self.console.print("\n[yellow]⚖️  Legal Notice: Use this tool ethically and responsibly![/yellow]")
        self.console.print("[green]Author: Gyau Boateng (Blue Scavengers Security)[/green]")
        self.console.print("[magenta]Version: 2.0 (Restructured & Enhanced)[/magenta]\n")
