#!/usr/bin/env python3
"""
Avighna2 SIEM - Interface Selection Launcher
Choose between CLI and Web interfaces
"""

import os
import subprocess
import sys
from pathlib import Path


def show_banner():
    print("""
    ╔══════════════════════════════════════════════════════════════╗
    ║                  🛡️  Avighna2 SIEM System                   ║
    ║              Privacy-First • Secure • Intelligent           ║
    ╚══════════════════════════════════════════════════════════════╝
    
    Select your preferred interface:
    
    1️⃣  Web Interface    - Modern dashboard with GUI
    2️⃣  CLI Interface    - Traditional command-line interface
    3️⃣  Exit
    
    """)

def main():
    while True:
        show_banner()
        
        try:
            choice = input("Enter your choice (1-3): ").strip()
            
            if choice == '1':
                print("\n🌐 Starting Web Interface...")
                print("Access at: http://localhost:5000")
                print("Press Ctrl+C to stop\n")
                
                try:
                    # Run web interface
                    subprocess.run([sys.executable, "run_web.py"], check=True)
                except KeyboardInterrupt:
                    print("\n\n👋 Web interface stopped.")
                except subprocess.CalledProcessError as e:
                    print(f"\n❌ Error starting web interface: {e}")
                
            elif choice == '2':
                print("\n💻 Starting CLI Interface...")
                print("Type 'help' for available commands")
                print("Type 'exit' to quit\n")
                
                try:
                    # Import and run CLI
                    from app.Avighna2 import main as cli_main
                    cli_main()
                except KeyboardInterrupt:
                    print("\n\n👋 CLI interface stopped.")
                except Exception as e:
                    print(f"\n❌ Error starting CLI interface: {e}")
                
            elif choice == '3':
                print("\n👋 Goodbye! Stay secure!")
                break
                
            else:
                print("\n❌ Invalid choice. Please enter 1, 2, or 3.")
                input("Press Enter to continue...")
                
        except KeyboardInterrupt:
            print("\n\n👋 Goodbye! Stay secure!")
            break
        except Exception as e:
            print(f"\n❌ Unexpected error: {e}")
            input("Press Enter to continue...")

if __name__ == '__main__':
    # Add project root to Python path
    ROOT = Path(__file__).resolve().parent
    sys.path.insert(0, str(ROOT))
    
    main()