#!/usr/bin/env python3
"""
Avighna2 SIEM Web Application Launcher
"""

import os
import sys
from pathlib import Path

# Add the project root to Python path
ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

# Set environment variables
os.environ.setdefault('FLASK_APP', 'app.web_app:app')
os.environ.setdefault('FLASK_ENV', 'development')

if __name__ == '__main__':
    # Import after setting up the path
    from app.web_app import app
    
    print("""
    ╔══════════════════════════════════════════════════════════════╗
    ║                  🛡️  Avighna2 SIEM Web Interface            ║
    ║              Privacy-First • Secure • Intelligent           ║
    ╚══════════════════════════════════════════════════════════════╝
    
    📋 Features Available:
    • Log Ingestion (with OCR support)  
    • File Scanning (YARA rules)
    • GeoIP Lookup
    • Natural Language Queries
    • Forensic Report Generation
    • Real-time Activity Monitoring
    
    🔐 Security Features:
    • Password Protection
    • Session Management  
    • Activity Logging
    • Progressive Access Control
    
    🌐 Access the web interface at: http://localhost:5000
    
    """)
    
    try:
        app.run(
            host='0.0.0.0',
            port=5000,
            debug=True,
            threaded=True
        )
    except KeyboardInterrupt:
        print("\n\n👋 Avighna2 SIEM shutting down. Stay secure!")
    except Exception as e:
        print(f"\n❌ Error starting Avighna2: {e}")
        print("Please check your configuration and try again.")
        sys.exit(1)