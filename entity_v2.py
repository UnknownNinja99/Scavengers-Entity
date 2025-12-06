#!/usr/bin/env python3
"""
Entity Cybersecurity Toolkit v2.0
=================================
Professional cybersecurity toolkit with modular architecture.

Author: Gyau Boateng (Blue Scavengers Security)
Version: 2.0 (Complete restructure based on code review feedback)
License: MIT

Features:
- Enhanced network scanning (nmap-like capabilities)
- IP geolocation and domain analysis
- OSINT intelligence gathering
- Phishing detection engine
- Modular, maintainable codebase
"""

import sys
from pathlib import Path

# Add entity package to path
sys.path.insert(0, str(Path(__file__).parent))

try:
    from entity.interface import EntityInterface
except ImportError as e:
    print(f"❌ Import Error: {e}")
    print("💡 Make sure you've installed all dependencies:")
    print("   pip install requests rich phonenumbers python-whois pyfiglet")
    sys.exit(1)


class EntityToolkit:
    """Main Entity toolkit orchestrator."""
    
    def __init__(self):
        self.ui = EntityInterface()
        self.running = True
    
    def run(self):
        """Main application loop."""
        try:
            self.ui.display_banner()
            
            while self.running:
                self.ui.display_main_menu()
                choice = self.ui.get_user_choice()
                self.process_choice(choice)
                
        except KeyboardInterrupt:
            self.ui.console.print("\n[yellow]Entity terminated by user[/yellow]")
        except Exception as e:
            self.ui.console.print(f"[red]Unexpected error: {e}[/red]")
            self.ui.console.print("[yellow]Please report this issue on GitHub[/yellow]")
        finally:
            self.cleanup()
    
    def process_choice(self, choice: str):
        """Process user menu choice."""
        handlers = {
            '1': self.ui.handle_network_scanner,
            '2': self.ui.handle_geolocation,
            '3': self.handle_osint_placeholder,
            '4': self.handle_phishing_placeholder,
            '5': self.ui.display_about,
            '0': self.exit_application
        }
        
        handler = handlers.get(choice, self.handle_invalid_choice)
        handler()
    
    def handle_osint_placeholder(self):
        """Placeholder for OSINT module (to be implemented)."""
        self.ui.console.print("[yellow]OSINT module coming in next update![/yellow]")
        self.ui.console.print("[cyan]Will include: Social media analysis, breach checking, etc.[/cyan]")
    
    def handle_phishing_placeholder(self):
        """Placeholder for phishing detection (to be implemented)."""
        self.ui.console.print("[yellow]Phishing detection module coming in next update![/yellow]")
        self.ui.console.print("[cyan]Will include: URL analysis, domain reputation, etc.[/cyan]")
    
    def handle_invalid_choice(self):
        """Handle invalid menu choice."""
        self.ui.console.print("[red]Invalid option. Please choose 0-5.[/red]")
    
    def exit_application(self):
        """Exit the application gracefully."""
        self.ui.console.print("[cyan]Thank you for using Entity! Stay secure! 🛡️[/cyan]")
        self.running = False
    
    def cleanup(self):
        """Perform cleanup operations."""
        pass


def main():
    """Entry point for Entity toolkit."""
    try:
        toolkit = EntityToolkit()
        toolkit.run()
    except Exception as e:
        print(f"Critical error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
