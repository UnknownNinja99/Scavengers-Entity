"""
Entity Geolocation Tracker Module
=================================
IP and domain geolocation capabilities.
"""

import socket
from typing import Dict, Optional

import requests
from rich.table import Table

from entity import console
from entity.utils.validators import check_private_ip, validate_ip_address


class GeolocationTracker:
    """Handles IP geolocation and domain analysis."""
    
    def __init__(self):
        self.api_endpoints = {
            "primary": "http://ip-api.com/json/",
            "secondary": "https://ipinfo.io/"
        }
    
    def resolve_domain_to_ip(self, domain: str) -> Optional[str]:
        """Resolve domain name to IP address."""
        try:
            ip = socket.gethostbyname(domain)
            console.print(f"[cyan]Resolved {domain} → {ip}[/cyan]")
            return ip
        except socket.gaierror as e:
            console.print(f"[red]Domain resolution failed: {e}[/red]")
            return None
    
    def get_public_ip(self) -> Optional[str]:
        """Get user's public IP address."""
        try:
            response = requests.get("https://api.ipify.org", timeout=5)
            return response.text.strip()
        except requests.RequestException as e:
            console.print(f"[red]Failed to get public IP: {e}[/red]")
            return None
    
    def analyze_ip(self, ip: str) -> Dict:
        """Comprehensive IP analysis."""
        if not validate_ip_address(ip):
            return {"error": "Invalid IP address format"}
        
        if check_private_ip(ip):
            return self._analyze_private_ip(ip)
        else:
            return self._analyze_public_ip(ip)
    
    def _analyze_private_ip(self, ip: str) -> Dict:
        """Analyze private IP address."""
        result = {
            "ip": ip,
            "type": "private",
            "routable": False,
            "description": "Local network IP (non-routable on internet)"
        }
        
        # Try to get local hostname
        try:
            hostname, _, _ = socket.gethostbyaddr(ip)
            result["hostname"] = hostname
        except socket.herror:
            result["hostname"] = "Could not resolve"
        
        self._display_private_ip_info(result)
        return result
    
    def _analyze_public_ip(self, ip: str) -> Dict:
        """Analyze public IP address with geolocation."""
        try:
            # Primary API
            response = requests.get(f"{self.api_endpoints['primary']}{ip}", timeout=5)
            data = response.json()
            
            if data.get("status") == "success":
                result = {
                    "ip": ip,
                    "type": "public",
                    "country": data.get("country", "Unknown"),
                    "region": data.get("regionName", "Unknown"),
                    "city": data.get("city", "Unknown"),
                    "zip_code": data.get("zip", "Unknown"),
                    "latitude": data.get("lat", "Unknown"),
                    "longitude": data.get("lon", "Unknown"),
                    "timezone": data.get("timezone", "Unknown"),
                    "isp": data.get("isp", "Unknown"),
                    "organization": data.get("org", "Unknown"),
                    "as_number": data.get("as", "Unknown")
                }
                
                # Cross-reference with secondary API
                self._cross_reference_data(ip, result)
                self._display_public_ip_info(result)
                return result
            else:
                return {"error": f"API Error: {data.get('message', 'Unknown error')}"}
                
        except requests.RequestException as e:
            return {"error": f"Network error: {str(e)}"}
    
    def _cross_reference_data(self, ip: str, result: Dict):
        """Cross-reference with secondary API for verification."""
        try:
            response = requests.get(f"{self.api_endpoints['secondary']}{ip}/json", timeout=5)
            secondary_data = response.json()
            
            if secondary_data.get('city') and result.get('city'):
                if secondary_data['city'] != result['city']:
                    console.print(f"[yellow]Note: Secondary source shows city as '{secondary_data['city']}'[/yellow]")
        except requests.RequestException:
            pass  # Secondary check failed, continue with primary data
    
    def _display_private_ip_info(self, data: Dict):
        """Display private IP information."""
        table = Table(title=f"Local Network Analysis: {data['ip']}", show_lines=True)
        table.add_column("Property", style="cyan")
        table.add_column("Value", style="magenta")
        
        table.add_row("IP Type", "Private (Non-routable)")
        table.add_row("Local Hostname", data.get("hostname", "Unknown"))
        table.add_row("Network Scope", "Local network only")
        
        console.print(table)
        console.print("[yellow]💡 Suggestion: Use Network Scanner for local IP analysis[/yellow]")
    
    def _display_public_ip_info(self, data: Dict):
        """Display public IP geolocation information."""
        table = Table(title=f"Geolocation Analysis: {data['ip']}", show_lines=True)
        table.add_column("Field", style="cyan")
        table.add_column("Value", style="magenta")
        
        fields = [
            ("Country", data.get("country")),
            ("Region/State", data.get("region")),
            ("City", data.get("city")),
            ("Postal Code", data.get("zip_code")),
            ("Coordinates", f"{data.get('latitude')}, {data.get('longitude')}"),
            ("Timezone", data.get("timezone")),
            ("ISP", data.get("isp")),
            ("Organization", data.get("organization")),
            ("AS Number", data.get("as_number"))
        ]
        
        for field, value in fields:
            table.add_row(field, str(value) if value else "N/A")
        
        console.print(table)
        
        # Additional analysis
        lat, lon = data.get("latitude"), data.get("longitude")
        if lat and lon:
            console.print(f"[cyan]🗺️  Google Maps: https://maps.google.com/?q={lat},{lon}[/cyan]")
        
        org = data.get("organization", "").upper()
        if any(keyword in org for keyword in ["VPN", "PROXY", "HOSTING"]):
            console.print("[yellow]⚠️  Possible VPN/Proxy/Hosting service detected[/yellow]")
