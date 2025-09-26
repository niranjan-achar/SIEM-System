# run_elk_siem.py
"""
ELK-powered Avighna2 SIEM Launcher
Enhanced with Elasticsearch capabilities and real-time analytics
"""

import os
import subprocess
import sys
import time


def print_elk_banner():
    """Print ELK SIEM banner"""
    print("""
    ╔═══════════════════════════════════════════════════════════════════════╗
    ║                🔍 Avighna2 SIEM - ELK Edition                        ║
    ║           Elasticsearch-Powered Security Information System           ║
    ╚═══════════════════════════════════════════════════════════════════════╝
    
    🚀 ELK Stack Features:
    • Elasticsearch Storage - Scalable security event storage
    • Advanced Search - Complex security queries and filters  
    • Real-time Analytics - Live threat monitoring and dashboards
    • Threat Intelligence - Automated threat level analysis
    • Geographic Mapping - IP geolocation and threat visualization
    • WebSocket Updates - Real-time threat notifications
    
    🔐 Enhanced Security:
    • ELK Audit Trail - Complete activity logging in Elasticsearch
    • Threat Correlation - Advanced pattern detection
    • Scalable Architecture - Handle millions of security events
    • Real-time Alerts - Instant high-priority threat notifications
    
    🌐 Prerequisites:
    - Elasticsearch 8.x+ running on localhost:9200
    - Python 3.8+ with ELK dependencies installed
    - Modern web browser with WebSocket support
    """)

def check_elasticsearch():
    """Check if Elasticsearch is running"""
    try:
        import requests
        response = requests.get('http://localhost:9200', timeout=5)
        if response.status_code == 200:
            cluster_info = response.json()
            print(f"✅ Elasticsearch {cluster_info.get('version', {}).get('number', 'Unknown')} is running")
            return True
        else:
            print("❌ Elasticsearch is not responding properly")
            return False
    except Exception as e:
        print(f"❌ Cannot connect to Elasticsearch: {e}")
        print("\n🔧 To install and run Elasticsearch:")
        print("1. Download from: https://www.elastic.co/downloads/elasticsearch")
        print("2. Extract and run: bin/elasticsearch (Linux/Mac) or bin\\elasticsearch.bat (Windows)")
        print("3. Wait for startup, then restart this application")
        return False

def install_elk_dependencies():
    """Install ELK-specific dependencies"""
    elk_packages = [
        'elasticsearch>=8.0.0',
        'elasticsearch-dsl>=8.0.0', 
        'flask-socketio',
        'python-socketio',
        'eventlet'
    ]
    
    print("📦 Installing ELK dependencies...")
    
    for package in elk_packages:
        try:
            subprocess.check_call([sys.executable, '-m', 'pip', 'install', package])
            print(f"✅ Installed {package}")
        except subprocess.CalledProcessError as e:
            print(f"❌ Failed to install {package}: {e}")
            return False
    
    return True

def main():
    """Main ELK SIEM launcher"""
    print_elk_banner()
    
    # Check if running in virtual environment (recommended)
    if not hasattr(sys, 'real_prefix') and not (hasattr(sys, 'base_prefix') and sys.base_prefix != sys.prefix):
        print("⚠️  Warning: Not running in virtual environment")
        print("   Recommended: python -m venv venv && venv\\Scripts\\activate")
        input("   Press Enter to continue anyway...")
    
    # Check Elasticsearch connection
    print("🔍 Checking Elasticsearch connection...")
    if not check_elasticsearch():
        print("\n❌ Elasticsearch is required for ELK SIEM")
        print("   Falling back to standard SIEM mode...")
        
        # Fallback to regular SIEM
        try:
            from app.web_app import app
            print("\n🌐 Starting Standard SIEM Web Interface...")
            app.run(host='0.0.0.0', port=5000, debug=True)
        except ImportError:
            print("❌ Cannot start standard SIEM either. Please check dependencies.")
        return
    
    # Install ELK dependencies if needed
    try:
        import elasticsearch
        import flask_socketio
        print("✅ ELK dependencies are available")
    except ImportError:
        print("📦 Installing missing ELK dependencies...")
        if not install_elk_dependencies():
            print("❌ Failed to install ELK dependencies")
            return
    
    # Set environment variables for ELK mode
    os.environ['ELK_MODE'] = 'true'
    os.environ['FLASK_ENV'] = 'development'
    
    print("🚀 Starting ELK-powered SIEM...")
    print("🌐 Web interface will be available at:")
    print("   • http://localhost:5000")
    print("   • http://127.0.0.1:5000") 
    print("   • http://192.168.1.6:5000 (if accessible)")
    print(f"🔐 Login password: {os.getenv('SIEM_PASSWORD', 'Avighna123!')}")
    print("\n⏳ Starting server...")
    
    # Import and run ELK web app
    try:
        from app.elk_web_app import app, socketio

        # Run with SocketIO for real-time features
        socketio.run(
            app, 
            host='0.0.0.0', 
            port=5000, 
            debug=True,
            use_reloader=True
        )
        
    except KeyboardInterrupt:
        print("\n\n👋 ELK SIEM stopped by user")
    except Exception as e:
        print(f"\n❌ ELK SIEM startup failed: {e}")
        print("📝 Check Elasticsearch connection and try again")

if __name__ == '__main__':
    main()