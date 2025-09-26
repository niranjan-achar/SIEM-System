# 🛡️ Avighna2 SIEM System
### *Advanced Security Information and Event Management Platform*

<div align="center">

![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)
![Flask](https://img.shields.io/badge/Flask-2.3+-green.svg)
![License](https://img.shields.io/badge/License-MIT-yellow.svg)
![Status](https://img.shields.io/badge/Status-Production%20Ready-brightgreen.svg)

*🔒 Privacy-First • 🤖 AI-Powered • 🌐 Web-Based • 📊 Real-Time Analytics*

</div>

---

## � Table of Contents
- [🌟 Overview](#-overview)
- [✨ Key Features](#-key-features)
- [🚀 Quick Start](#-quick-start)
- [🔧 Installation](#-installation)
- [💻 Usage Guide](#-usage-guide)
- [🌐 Enhanced GeoIP](#-enhanced-geoip)
- [📊 API Documentation](#-api-documentation)
- [🛠️ Configuration](#️-configuration)
- [🔒 Security](#-security)
- [📈 Screenshots](#-screenshots)
- [🤝 Contributing](#-contributing)

---

## 🌟 Overview

**Avighna2** is a cutting-edge Security Information and Event Management (SIEM) platform that combines traditional security analysis with modern AI capabilities. Built with privacy-first principles, it offers both web-based and command-line interfaces for comprehensive cybersecurity monitoring and incident response.

### 🎯 Mission
*To democratize enterprise-grade security monitoring through intelligent automation and user-friendly interfaces.*

---

## ✨ Key Features

### 🔐 **Advanced Security Engine**
- 🛡️ **Multi-Factor Authentication** - Secure login with session management
- 📊 **Real-Time Monitoring** - Live threat detection and alerting  
- 🔍 **Behavioral Analysis** - ML-powered anomaly detection
- 📋 **Comprehensive Audit Trail** - Complete activity logging
- 🚨 **Automated Response** - Configurable incident response workflows

### 🌐 **Enhanced GeoIP Intelligence** *(NEW)*
- 🌍 **Universal Input Support** - IP addresses AND domain names
- 🏢 **Website Intelligence** - Server details, company information
- 📍 **Precise Geolocation** - Country, city, coordinates, ISP data
- 🔗 **Smart URL Resolution** - Handles redirects and complex URLs
- 📊 **Rich Visualization** - Interactive maps and detailed reports

### 📊 **Advanced Analytics**
- 📁 **Multi-Format Log Ingestion** - Apache, IIS, Syslog, JSON, XML, Windows Event Logs
- 🖼️ **OCR Technology** - Extract logs from images and PDF documents
- 🧬 **YARA Rule Engine** - Custom malware detection patterns
- 🤖 **Natural Language Processing** - Conversational query interface
- 📄 **Professional Reporting** - Automated forensic PDF generation

### 🖥️ **Modern Interface Stack**
- 🌐 **Responsive Web Dashboard** - Bootstrap 5 + custom themes
- 💻 **CLI Interface** - Power-user command-line tools
- 🔌 **RESTful API** - Full programmatic access
- 📱 **Mobile-Friendly** - Optimized for tablets and smartphones
- 🎨 **Customizable UI** - Dark/light themes, custom branding

---

## 🚀 Quick Start

### ⚡ **One-Click Launch** *(Recommended)*
```powershell
# Windows - Double-click or run:
start_web.bat

# Linux/Mac
chmod +x start_web.sh && ./start_web.sh
```

### 🐍 **Python Direct Launch**
```bash
# Quick setup and launch
git clone https://github.com/niranjan-achar/Security-Information-and-Event-Management.git
cd Security-Information-and-Event-Management
pip install -r requirements.txt
python app/web_app.py
```

### 🌐 **Access Your Dashboard**
1. **🚀 Launch** using any method above
2. **🌐 Open Browser** → `http://localhost:5000`
3. **🔐 Login** → Username: `admin` | Password: `Avighna123!`
4. **🎯 Start Analyzing** → Upload logs, scan files, query with NLP!

---

## 🔧 Installation

### 📋 **System Requirements**
- **Python**: 3.8+ (3.10+ recommended)
- **OS**: Windows 10/11, Linux (Ubuntu 20.04+), macOS 10.15+
- **RAM**: 4GB minimum, 8GB recommended
- **Storage**: 2GB free space
- **Network**: Internet access for GeoIP and threat intelligence

### 🛠️ **Detailed Installation**

#### **Step 1: Clone Repository**
```bash
git clone https://github.com/niranjan-achar/Security-Information-and-Event-Management.git
cd Security-Information-and-Event-Management
```

#### **Step 2: Virtual Environment** *(Recommended)*
```bash
# Create virtual environment
python -m venv venv

# Activate virtual environment
# Windows PowerShell:
venv\Scripts\Activate.ps1
# Windows CMD:
venv\Scripts\activate.bat
# Linux/Mac:
source venv/bin/activate
```

#### **Step 3: Install Dependencies**
```bash
# Core dependencies
pip install -r requirements.txt

# Optional: Enhanced features
pip install elasticsearch flask-socketio  # For ELK stack support
```

#### **Step 4: Configuration**
```bash
# Create configuration file
cp .env.example .env

# Edit configuration (optional)
# Change default password, API keys, etc.
notepad .env  # Windows
nano .env     # Linux/Mac
```

#### **Step 5: Initialize Database**
```bash
# Database will be auto-created on first run
python app/web_app.py
```

---

## 💻 Usage Guide

### � **Dashboard Overview**
The main dashboard provides instant access to all SIEM capabilities:

- **🎛️ Quick Actions** - One-click access to core features
- **📊 Real-Time Activity** - Live monitoring of system events  
- **🤖 NLP Query Interface** - Conversational analysis engine
- **📈 Analytics Panel** - Visual threat intelligence
- **⚡ Instant Results** - Real-time response display

### 🔍 **Core Features**

#### 📤 **Log Ingestion & Analysis**
```bash
✅ Supported Formats:
   • Apache/Nginx logs (.log, .txt)
   • Windows Event Logs (.evtx)
   • JSON/XML logs
   • CSV data files
   • Syslog formats

✅ OCR Processing:
   • Image logs (PNG, JPG, TIFF)
   • PDF documents
   • Scanned security reports
```

#### 🔬 **File Scanning Engine**
```bash
✅ Malware Detection:
   • YARA rule engine
   • Custom pattern matching
   • Behavioral analysis
   • Hash-based detection

✅ File Support:
   • Executables (.exe, .dll)
   • Scripts (.bat, .ps1, .sh)
   • Documents (.pdf, .doc)
   • Archives (.zip, .rar)
```

#### 🤖 **Natural Language Queries**
```bash
Example Queries:
🔍 "Show me failed login attempts"
🔍 "What are the top attacking IPs?"
🔍 "Generate security summary"
🔍 "Find brute force attempts"
🔍 "Analyze suspicious activity"
```

#### 📄 **Professional Reporting**
```bash
✅ Report Features:
   • Executive summaries
   • Technical analysis
   • Visual charts and graphs
   • Actionable recommendations
   • Compliance mapping
```

---

## 🌐 Enhanced GeoIP Intelligence

### 🌟 **Revolutionary Dual-Input Support**

Our enhanced GeoIP system accepts **both IP addresses and domain names**, providing comprehensive intelligence:

#### 🔍 **IP Address Analysis**
```bash
Examples:
• 8.8.8.8          → Google DNS (Mountain View, CA)
• 1.1.1.1          → Cloudflare (San Francisco, CA)  
• 192.168.1.1      → Private network analysis
```

#### 🌐 **Domain Name Intelligence** *(NEW)*
```bash
Examples:
• google.com       → Complete website + geo analysis
• github.com       → Server details + location data
• malicious.site   → Threat intelligence + geolocation
```

### 📊 **Rich Intelligence Data**

#### 🏢 **Website Information**
- **Domain Analysis** - Clean domain extraction
- **Website Name** - Automatic company detection
- **Server Details** - Technology stack identification
- **URL Resolution** - Redirect chain analysis

#### 📍 **Geographic Intelligence**
- **Precise Location** - Country, city, coordinates
- **ISP Information** - Provider and organization data
- **Threat Context** - Risk assessment and reputation
- **Visual Mapping** - Interactive location display

### 🎯 **Smart Input Processing**
```bash
✅ Handles All Formats:
   • Clean domains: google.com
   • URLs: https://www.google.com/search
   • Subdomains: mail.google.com
   • With paths: github.com/user/repo
   • IP addresses: 192.168.1.1
```

---

## 📊 API Documentation

### 🔌 **RESTful API Endpoints**

#### **Authentication Required**
All API endpoints require authentication via session or API key.

#### **Core Endpoints**
```http
POST /api/ingest              # Log file ingestion
POST /api/scan                # File malware scanning  
POST /api/geoip               # Enhanced GeoIP lookup
POST /api/nlp                 # Natural language queries
POST /api/report              # Generate forensic reports
GET  /api/activity            # Retrieve activity logs
```

#### **GeoIP API Example** *(Enhanced)*
```bash
# Request
curl -X POST http://localhost:5000/api/geoip \
  -H "Content-Type: application/json" \
  -d '{"ip": "google.com"}'

# Response
{
  "success": true,
  "target": "google.com",
  "info": {
    "original_input": "google.com",
    "input_type": "domain",
    "resolved_ip": "142.250.77.78",
    "website_info": {
      "domain": "google.com",
      "website_name": "Google",
      "server": "gws",
      "final_url": "http://www.google.com/"
    },
    "country": "United States",
    "city": "Mountain View",
    "latitude": 37.4056,
    "longitude": -122.0775,
    "isp": "Google LLC",
    "source": "ip-api.com"
  }
}
```

---

## �️ Configuration

### ⚙️ **Environment Variables** (.env file)
```bash
# 🔐 Security Configuration
OWNER_PASS=Avighna123!              # Web interface password
SECRET_KEY=your-flask-secret-key     # Session encryption key
SESSION_TIMEOUT=3600                 # Session timeout (seconds)

# 🌐 Server Configuration  
HOST=0.0.0.0                        # Bind address
PORT=5000                           # Server port
DEBUG=True                          # Development mode

# 🔍 OCR Configuration (Optional)
TESSERACT_CMD=C:\Program Files\Tesseract-OCR\tesseract.exe

# 🌍 GeoIP Configuration
GEOIP_DB_PATH=data/GeoLite2-City.mmdb
GEOIP_API_FALLBACK=True

# 📊 Database Configuration
DB_PATH=avighna_activity.db
LOG_RETENTION_DAYS=90

# 🚨 Alert Configuration
ENABLE_EMAIL_ALERTS=False
ALERT_THRESHOLD=10
```

---

## 🔒 Security

### 🛡️ **Security Features**

#### **Authentication & Authorization**
- 🔐 **Secure Login System** - Bcrypt password hashing
- 🕒 **Session Management** - Automatic timeout and renewal
- 🔑 **API Key Support** - Programmatic access control
- 📋 **Audit Logging** - Complete access trail

#### **Data Protection**
- 🔒 **Encryption at Rest** - SQLite database encryption
- 🌐 **HTTPS Support** - SSL/TLS configuration ready
- 🗑️ **Secure Deletion** - Cryptographic file wiping
- 📊 **Privacy First** - No external data transmission

#### **Network Security**
- 🛡️ **CORS Protection** - Cross-origin request filtering
- 🚫 **Rate Limiting** - DDoS and brute-force protection
- 🔍 **Input Validation** - SQL injection and XSS prevention
- 📡 **Secure Headers** - HSTS, CSP, and security headers

### 🔧 **Security Best Practices**

```bash
# 1. Change Default Password
OWNER_PASS=YourStrongPassword123!

# 2. Generate Secure Secret Key
SECRET_KEY=$(python -c 'import secrets; print(secrets.token_hex(32))')

# 3. Enable HTTPS (Production)
SSL_CERT_PATH=/path/to/cert.pem
SSL_KEY_PATH=/path/to/key.pem

# 4. Restrict Network Access
HOST=127.0.0.1  # Local only
# or
HOST=192.168.1.100  # Specific interface

# 5. Enable Audit Logging
AUDIT_LOG_LEVEL=INFO
AUDIT_LOG_PATH=logs/audit.log
```

---

## 📈 Screenshots

### 🏠 **Main Dashboard**
*Clean, intuitive interface with real-time monitoring*

### � **Enhanced GeoIP Analysis**
*Comprehensive domain and IP intelligence display*

### 📊 **Analytics Dashboard**
*Visual threat intelligence and trend analysis*

### 📄 **Professional Reports**
*Executive-ready forensic documentation*

---

## 🔧 Troubleshooting

### ❓ **Common Issues & Solutions**

#### **🚀 Startup Issues**
```bash
❌ Problem: "Port 5000 already in use"
✅ Solution: 
   • Change port: python app/web_app.py --port 5001
   • Kill process: netstat -ano | findstr :5000

❌ Problem: "Module not found"
✅ Solution:
   • Activate virtual environment
   • Install requirements: pip install -r requirements.txt
   • Set PYTHONPATH: export PYTHONPATH=.
```

#### **� OCR Issues**
```bash
❌ Problem: "Tesseract not found"
✅ Solution:
   Windows: choco install tesseract
   Linux: sudo apt-get install tesseract-ocr
   Mac: brew install tesseract
   
   Update .env: TESSERACT_CMD=/usr/bin/tesseract
```

#### **🌐 GeoIP Issues**
```bash
❌ Problem: "GeoIP database not found"
✅ Solution:
   • Download from MaxMind (free account required)
   • Place in: data/GeoLite2-City.mmdb
   • Fallback to API automatically enabled
```

#### **🔐 Authentication Issues**
```bash
❌ Problem: "Login failed"
✅ Solution:
   • Check password in .env file
   • Clear browser cache/cookies
   • Restart application
```

### 📊 **Performance Optimization**
```bash
# For large log files
MAX_FILE_SIZE=100MB
CHUNK_SIZE=1024
PARALLEL_PROCESSING=True

# Database optimization
DB_POOL_SIZE=10
DB_TIMEOUT=30

# Memory management
MAX_MEMORY_USAGE=2GB
ENABLE_CACHING=True
```

---

## 📁 File Support Matrix

### 📊 **Log File Formats**
| Format | Extension | OCR Support | Notes |
|--------|-----------|-------------|-------|
| Apache/Nginx | `.log`, `.txt` | ✅ | Common log format |
| Windows Events | `.evtx` | ❌ | Native parsing |
| JSON Logs | `.json` | ✅ | Structured data |
| CSV Data | `.csv` | ✅ | Tabular format |
| XML Logs | `.xml` | ✅ | Structured markup |
| Syslog | `.syslog` | ✅ | RFC 3164/5424 |

### 🖼️ **OCR Document Support**
| Type | Extensions | Quality | Speed |
|------|------------|---------|-------|
| Images | `.png`, `.jpg`, `.tiff` | High | Fast |
| PDF Documents | `.pdf` | High | Medium |
| Scanned Reports | All image formats | Medium | Slow |

### 🔍 **Malware Scanning**
| File Type | Extensions | Detection Method |
|-----------|------------|------------------|
| Executables | `.exe`, `.dll`, `.sys` | YARA + Heuristics |
| Scripts | `.bat`, `.ps1`, `.sh`, `.py` | Pattern matching |
| Documents | `.pdf`, `.doc`, `.xls` | Macro analysis |
| Archives | `.zip`, `.rar`, `.7z` | Recursive scanning |

---

## � Advanced Features

### 🤖 **ELK Stack Integration** *(Optional)*
Transform your SIEM into an enterprise-grade solution:

```bash
# Enable ELK stack
python run_elk_siem.py

# Features:
✅ Elasticsearch backend
✅ Real-time data streaming  
✅ Advanced analytics
✅ Scalable architecture
✅ WebSocket live updates
```

### 🔗 **API Integration Examples**

#### **Python SDK**
```python
import requests

# Initialize session
session = requests.Session()
session.post('http://localhost:5000/login', 
             data={'password': 'Avighna123!'})

# GeoIP lookup
result = session.post('http://localhost:5000/api/geoip',
                      json={'ip': 'google.com'})
print(result.json())
```

#### **PowerShell**
```powershell
# Login and get session
$session = New-Object Microsoft.PowerShell.Commands.WebRequestSession
Invoke-WebRequest -Uri "http://localhost:5000/login" -Method POST -Body @{password="Avighna123!"} -WebSession $session

# Upload and analyze log
$result = Invoke-RestMethod -Uri "http://localhost:5000/api/ingest" -Method POST -InFile "access.log" -WebSession $session
```

### 📊 **Custom Dashboards**
Create personalized monitoring views:

- **Executive Dashboard** - High-level KPIs and trends
- **SOC Dashboard** - Real-time threat monitoring
- **Compliance Dashboard** - Regulatory requirement tracking
- **Network Dashboard** - Infrastructure monitoring

---

## 🔄 Deployment Options

### 🐳 **Docker Deployment** *(Coming Soon)*
```bash
# Quick start with Docker
docker run -p 5000:5000 avighna2/siem:latest

# Docker Compose with ELK
docker-compose up -d
```

### ☁️ **Cloud Deployment**

#### **AWS**
```bash
# EC2 deployment
aws ec2 run-instances --image-id ami-12345 --instance-type t3.medium

# ECS container deployment  
aws ecs create-service --cluster avighna-cluster --service-name siem
```

#### **Azure**
```bash
# Container Instances
az container create --resource-group rg-siem --name avighna2

# App Service deployment
az webapp create --resource-group rg-siem --plan plan-siem
```

### 🏢 **Enterprise Features**

#### **High Availability**
- Load balancer support (nginx, HAProxy)
- Database clustering (PostgreSQL, MySQL)
- Redis session storage
- Backup and disaster recovery

#### **Scaling**
- Horizontal scaling support
- Microservices architecture ready
- Queue-based processing (Celery, RQ)
- Caching layers (Redis, Memcached)

---

## � Documentation

### 📖 **Additional Resources**
- **[API Reference](docs/api.md)** - Complete API documentation
- **[Deployment Guide](docs/deployment.md)** - Production deployment
- **[Security Guide](docs/security.md)** - Hardening and best practices
- **[Developer Guide](docs/development.md)** - Contributing and extending

### 🎓 **Training Materials**
- **Video Tutorials** - Step-by-step walkthroughs
- **Use Case Studies** - Real-world scenarios
- **Best Practices** - Industry-standard procedures
- **Troubleshooting Guide** - Common issues and solutions

---

## 🤝 Contributing

### 🌟 **How to Contribute**

1. **🍴 Fork** the repository
2. **🌿 Create** a feature branch: `git checkout -b feature/amazing-feature`
3. **💻 Commit** your changes: `git commit -m 'Add amazing feature'`
4. **📤 Push** to branch: `git push origin feature/amazing-feature`
5. **🔀 Create** a Pull Request

### 🎯 **Contribution Areas**
- 🐛 Bug fixes and improvements
- ✨ New features and modules
- 📚 Documentation enhancements
- 🧪 Test coverage expansion
- 🎨 UI/UX improvements
- 🌐 Internationalization

### 📋 **Development Setup**
```bash
# Clone and setup development environment
git clone https://github.com/niranjan-achar/Security-Information-and-Event-Management.git
cd Security-Information-and-Event-Management

# Install development dependencies
pip install -r requirements-dev.txt

# Run tests
python -m pytest tests/

# Code quality checks
black app/
flake8 app/
mypy app/
```

---

## 📞 Support & Community

### 💬 **Getting Help**
- **📚 Documentation** - Check the comprehensive docs first
- **🐛 Issues** - Report bugs via GitHub Issues
- **💡 Discussions** - Join GitHub Discussions for questions
- **📧 Email** - Contact the development team

### 🌐 **Community**
- **⭐ Star** this repository if you find it useful
- **🍴 Fork** and contribute to the project
- **📢 Share** with your security community
- **📝 Blog** about your experience and use cases

### 🏆 **Recognition**
Special thanks to all contributors and the cybersecurity community for making this project possible.

---

## 📜 License

This project is licensed under the **MIT License** - see the [LICENSE](LICENSE) file for details.

---

## 🚀 What's Next?

### 🔮 **Roadmap**
- 🤖 **AI-Powered Threat Detection** - Machine learning integration
- 🌐 **Cloud-Native Architecture** - Kubernetes support
- 📱 **Mobile App** - iOS and Android companions
- 🔗 **SOAR Integration** - Security orchestration capabilities
- 🌍 **Multi-Language Support** - Internationalization

---

<div align="center">

### 🛡️ **Avighna2 SIEM**
*Empowering cybersecurity professionals with intelligent, privacy-first security monitoring*

**[⭐ Star on GitHub](https://github.com/niranjan-achar/Security-Information-and-Event-Management)** • **[📚 Documentation](docs/)** • **[🐛 Report Issue](https://github.com/niranjan-achar/Security-Information-and-Event-Management/issues)** • **[💡 Discussions](https://github.com/niranjan-achar/Security-Information-and-Event-Management/discussions)**

---

*Built with ❤️ by the cybersecurity community*

![Footer](https://img.shields.io/badge/Made%20with-Python%20%2B%20Flask-blue?style=for-the-badge&logo=python)
![Security](https://img.shields.io/badge/Security-First-red?style=for-the-badge&logo=shield)
![Privacy](https://img.shields.io/badge/Privacy-Protected-green?style=for-the-badge&logo=lock)

</div>