#!/usr/bin/env python3
"""
Entity Cybersecurity Toolkit v2.0
=================================
Professional cybersecurity toolkit with modular architecture.

Author: Gyau Boateng (Blue Scavengers Security)
Version: 2.0 (Complete restructure based on code review feedback)
License: MIT

Note: This is an alias to entity_v2.py for backward compatibility.
For the actual application, use entity_v2.py
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
        if choice == "1":
            self.ui.run_network_scanner()
        elif choice == "2":
            self.ui.run_geolocation()
        elif choice == "3":
            self.ui.run_osint()
        elif choice == "4":
            self.ui.run_phishing_detector()
        elif choice == "5":
            self.ui.display_about()
        elif choice == "0":
            self.running = False
        else:
            self.ui.console.print("[red]Invalid choice. Please try again.[/red]")
    
    def cleanup(self):
        """Cleanup resources before exit."""
        pass


def main():
    """Main application entry point."""
    try:
        toolkit = EntityToolkit()
        toolkit.run()
    except Exception as e:
        print(f"Critical error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
