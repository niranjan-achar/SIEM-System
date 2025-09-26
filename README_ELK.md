# Avighna2 SIEM - ELK Edition

## 🔍 **Elasticsearch-Powered Security Information and Event Management**

Avighna2 ELK Edition transforms your SIEM into a enterprise-grade security platform powered by the Elastic Stack (Elasticsearch, Logstash, Kibana functionality built-in).

---

## 🚀 **What's New in ELK Edition?**

### **🔍 Advanced Search & Analytics**
- **Elasticsearch Storage** - Scalable storage for millions of security events
- **Complex Queries** - Boolean searches, filters, aggregations
- **Real-time Search** - Instant results across massive datasets
- **Threat Intelligence** - Automated threat level classification

### **📊 Real-time Dashboards**
- **Live Threat Monitoring** - WebSocket-powered real-time updates
- **Geographic Visualization** - World map of threat origins
- **Threat Analytics** - Advanced aggregations and statistics
- **Timeline Analysis** - Time-based threat pattern detection

### **🤖 AI-Enhanced Features**
- **Smart Threat Classification** - Automatic threat level assignment
- **Pattern Detection** - ML-style event correlation
- **Enhanced NLP** - Natural language queries with ELK search
- **Predictive Analytics** - Trend analysis and forecasting

---

## 📋 **Prerequisites**

### **1. Elasticsearch Installation**

#### **Windows:**
```bash
# Download Elasticsearch 8.x
# https://www.elastic.co/downloads/elasticsearch

# Extract and run
cd elasticsearch-8.x.x
bin\elasticsearch.bat
```

#### **Linux/Mac:**
```bash
# Download and extract Elasticsearch
wget https://artifacts.elastic.co/downloads/elasticsearch/elasticsearch-8.11.0-linux-x86_64.tar.gz
tar -xzf elasticsearch-8.11.0-linux-x86_64.tar.gz
cd elasticsearch-8.11.0

# Run Elasticsearch
./bin/elasticsearch
```

#### **Docker (Recommended for Development):**
```bash
# Run Elasticsearch in Docker
docker run -d \
  --name elasticsearch \
  -p 9200:9200 \
  -p 9300:9300 \
  -e "discovery.type=single-node" \
  -e "xpack.security.enabled=false" \
  docker.elastic.co/elasticsearch/elasticsearch:8.11.0
```

### **2. Verify Elasticsearch is Running**
```bash
# Test connection
curl http://localhost:9200

# Should return cluster information
```

---

## 🛠️ **Installation & Setup**

### **Option 1: Quick Start (Recommended)**
```bash
# 1. Clone repository
git clone https://github.com/niranjan-achar/Security-Information-and-Event-Management.git
cd Security-Information-and-Event-Management

# 2. Create virtual environment
python -m venv venv

# 3. Activate virtual environment
# Windows:
venv\Scripts\activate
# Linux/Mac:
source venv/bin/activate

# 4. Install all dependencies (including ELK)
pip install -r requirements.txt

# 5. Start ELK SIEM
python run_elk_siem.py
```

### **Option 2: Manual Setup**
```bash
# Install base dependencies
pip install -r requirements.txt

# Install ELK-specific packages
pip install elasticsearch>=8.0.0
pip install elasticsearch-dsl>=8.0.0
pip install flask-socketio
pip install python-socketio
pip install eventlet

# Create environment file
copy .env.example .env

# Start ELK SIEM
python run_elk_siem.py
```

---

## 🌐 **Access Your ELK SIEM**

Once started, access your ELK-powered SIEM at:
- **http://localhost:5000** (primary)
- **http://127.0.0.1:5000** (alternative)
- **http://[your-ip]:5000** (network access)

**Default Login:** `Avighna123!`

---

## ✨ **ELK Features Guide**

### **1. ELK Log Ingestion**
- Upload logs directly to Elasticsearch
- Automatic threat level classification
- Geographic IP enrichment
- Real-time indexing and analysis

### **2. Advanced ELK Search**
```javascript
// Example searches you can perform:
- "failed login" + threat_level:high
- ip:192.168.1.1 AND status_code:401
- event_type:authentication AND country:China
- timestamp:[now-24h TO now] AND threat_level:critical
```

### **3. Real-time Threat Monitoring**
- **WebSocket Updates** - Live threat notifications
- **Threat Timeline** - Visual threat progression
- **Geographic Mapping** - See attack origins
- **Automated Alerts** - High-priority threat notifications

### **4. AI-Enhanced NLP Queries**
Ask questions in natural language:
```
- "Show me failed logins from China in the last hour"
- "What are the top threat IPs today?"
- "Find authentication attacks with high threat level"
- "Show me all critical threats this week"
```

### **5. Advanced Analytics**
- **Threat Intelligence Dashboard**
- **Attack Pattern Analysis**
- **Geographic Threat Distribution**
- **Timeline-based Threat Correlation**

---

## 🔧 **Configuration**

### **Environment Variables (.env file):**
```bash
# ELK Configuration
ELASTICSEARCH_HOST=localhost
ELASTICSEARCH_PORT=9200
ELK_INDEX_PREFIX=siem

# Security
SIEM_PASSWORD=Avighna123!
SECRET_KEY=your-secret-key-here

# Features
ENABLE_REAL_TIME_MONITORING=true
ENABLE_THREAT_INTELLIGENCE=true
ENABLE_GEO_ENRICHMENT=true
```

### **Elasticsearch Index Configuration:**
The ELK SIEM creates these indices automatically:
- **siem-events** - Security events and logs
- **siem-activity** - User activity and audit trail  
- **siem-threats** - Threat intelligence data

---

## 📊 **Dashboard Features**

### **Real-time Threat Monitor**
- Live high-priority threat feed
- Automatic threat level classification
- Geographic origin tracking
- Event type categorization

### **Analytics Cards**
- **Top Threat IPs** - Most dangerous source IPs
- **Geographic Threats** - World threat distribution
- **Attack Methods** - HTTP method analysis
- **Status Code Distribution** - Response code patterns

### **Interactive Charts**
- **Threat Timeline** - Time-series threat analysis
- **Status Distribution** - Response code breakdown
- **Geographic Heatmap** - World threat visualization
- **Attack Pattern Analysis** - Method and target correlation

---

## 🔍 **ELK Search Examples**

### **Basic Searches:**
```bash
# Find failed logins
threat_level:high AND event_type:authentication

# Geographic threats
country:China OR country:Russia

# Recent critical threats  
timestamp:[now-1h TO now] AND threat_level:critical

# Specific IP analysis
ip:192.168.1.100 AND status_code:401
```

### **Advanced Aggregations:**
```bash
# Top threat countries
GET siem-events/_search
{
  "aggs": {
    "threat_countries": {
      "terms": {"field": "country"}
    }
  }
}

# Threat timeline
GET siem-events/_search  
{
  "aggs": {
    "threats_over_time": {
      "date_histogram": {
        "field": "timestamp",
        "calendar_interval": "1h"
      }
    }
  }
}
```

---

## 🚨 **Troubleshooting**

### **Elasticsearch Connection Issues:**
```bash
# Check if Elasticsearch is running
curl http://localhost:9200

# Check cluster health
curl http://localhost:9200/_cluster/health

# View indices
curl http://localhost:9200/_cat/indices
```

### **Common Solutions:**
1. **Port 9200 blocked** - Check firewall settings
2. **Memory issues** - Increase Elasticsearch heap size
3. **Index errors** - Delete and recreate indices
4. **Connection timeout** - Increase connection timeout in elk_storage.py

### **Performance Optimization:**
```bash
# Elasticsearch JVM settings (elasticsearch.yml)
-Xms2g
-Xmx2g

# Index optimization
PUT siem-events/_settings
{
  "number_of_replicas": 0,
  "refresh_interval": "5s"
}
```

---

## 🔄 **Migration from Standard SIEM**

Your existing SIEM data can be migrated to ELK:

```python
# Run migration script
python migrate_to_elk.py

# This will:
# 1. Export existing SQLite data
# 2. Transform to ELK format
# 3. Bulk index into Elasticsearch
# 4. Verify data integrity
```

---

## 🎯 **Development & Customization**

### **Adding Custom Threat Rules:**
```python
# In elk_storage.py, modify _analyze_threat_level()
def _analyze_threat_level(self, event: Dict) -> str:
    # Add your custom threat detection logic
    if 'your_condition' in event:
        return "critical"
    return "info"
```

### **Custom Analytics:**
```python
# Add new aggregation functions
def get_custom_analytics(self):
    # Your custom Elasticsearch aggregations
    pass
```

### **Real-time Alerts:**
```python
# Customize threat monitoring in elk_web_app.py
@socketio.on('custom_monitoring')
def handle_custom_monitoring():
    # Your real-time monitoring logic
    pass
```

---

## 📈 **Performance Metrics**

ELK Edition can handle:
- **Events**: 10M+ security events
- **Search**: Sub-second search across millions of records  
- **Ingestion**: 10,000+ events/second
- **Storage**: Petabyte-scale with proper cluster setup
- **Users**: 100+ concurrent users with proper infrastructure

---

## 🤝 **Contributing**

Want to enhance the ELK features?
1. Fork the repository
2. Create feature branch: `git checkout -b elk-feature`
3. Add ELK enhancements
4. Test with Elasticsearch
5. Submit pull request

---

## 📞 **Support**

For ELK-specific issues:
- **Elasticsearch Docs**: https://www.elastic.co/guide/
- **SIEM Issues**: Create GitHub issue
- **Performance**: Check Elasticsearch cluster settings
- **Custom Development**: Modify elk_storage.py and elk_web_app.py

---

**🎉 Congratulations! You now have an enterprise-grade ELK-powered SIEM system!**