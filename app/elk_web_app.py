# app/elk_web_app.py
"""
ELK-powered Flask web application for Avighna2 SIEM
Enhanced with Elasticsearch capabilities and real-time analytics
"""

import json
import os
import tempfile
import threading
import time
import uuid
from datetime import datetime, timedelta
from functools import wraps

from flask import (
    Flask,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from flask_socketio import SocketIO, emit
from werkzeug.utils import secure_filename

# Import SIEM modules
from app import enrichment, geo, ingest, nlp_query, report_gen, scanner, utils
from app.elk_storage import elk_storage

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'your-secret-key-change-this')

# Initialize SocketIO for real-time features
socketio = SocketIO(app, cors_allowed_origins="*")

# Configuration
UPLOAD_FOLDER = 'temp_uploads'
ALLOWED_EXTENSIONS = {'log', 'txt', 'csv', 'json', 'pdf', 'png', 'jpg', 'jpeg', 'bmp', 'tif', 'tiff', 'xml', 'evtx'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 50MB max file size

# Create upload directory
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Password (in production, use proper authentication)
SIEM_PASSWORD = os.getenv('SIEM_PASSWORD', 'Avighna123!')

def require_auth(f):
    """Authentication decorator"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('authenticated'):
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def allowed_file(filename):
    """Check if file extension is allowed"""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/')
@require_auth
def dashboard():
    """Main dashboard with ELK analytics"""
    # Get ELK status
    elk_status = elk_storage.get_elasticsearch_status()
    
    # Get threat analytics
    analytics = elk_storage.get_threat_analytics()
    
    return render_template('elk_dashboard.html', 
                         elk_status=elk_status, 
                         analytics=analytics)

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Login page"""
    if request.method == 'POST':
        password = request.form.get('password')
        if password == SIEM_PASSWORD:
            session['authenticated'] = True
            session['user'] = 'siem_user'
            session['login_time'] = datetime.now().isoformat()
            
            # Log successful authentication
            elk_storage.log_activity(
                user='siem_user',
                action='login_success',
                details='Successful web interface login',
                ip_address=request.remote_addr
            )
            
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            # Log failed authentication
            elk_storage.log_activity(
                user='unknown',
                action='login_failed',
                details='Failed web interface login attempt',
                ip_address=request.remote_addr
            )
            
            flash('Invalid password!', 'danger')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    """Logout and clear session"""
    user = session.get('user', 'unknown')
    elk_storage.log_activity(
        user=user,
        action='logout',
        details='User logged out from web interface',
        ip_address=request.remote_addr
    )
    
    session.clear()
    flash('Logged out successfully!', 'info')
    return redirect(url_for('login'))

# API Routes for ELK-powered functionality

@app.route('/api/ingest', methods=['POST'])
@require_auth
def api_ingest():
    """Enhanced log ingestion with ELK storage"""
    try:
        print("[DEBUG] ELK Ingest request received")
        
        if 'file' in request.files and request.files['file'].filename:
            file = request.files['file']
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(filepath)
                print(f"[DEBUG] File saved to: {filepath}")
                
                # Process with existing ingest module
                events = ingest.parse_access_log(filepath)
                
                # Enhanced processing with geolocation
                enriched_events = []
                for event in events:
                    # Add geolocation data
                    if 'ip' in event:
                        geo_data = geo.lookup_ip(event['ip'])
                        if geo_data:
                            event.update(geo_data)
                    
                    # Add timestamp
                    event['ingestion_time'] = datetime.now().isoformat()
                    enriched_events.append(event)
                
                # Store in Elasticsearch
                elk_success = elk_storage.index_events(enriched_events)
                
                # Generate summary
                summary = ingest.summarize_events(events)
                
                # Log activity
                elk_storage.log_activity(
                    user=session.get('user', 'unknown'),
                    action='log_ingestion',
                    details=f'Processed {len(events)} events from {filename}',
                    result=f'ELK Storage: {"Success" if elk_success else "Failed"}',
                    ip_address=request.remote_addr
                )
                
                # Clean up temp file
                os.remove(filepath)
                
                # Emit real-time update
                socketio.emit('new_events', {
                    'count': len(events),
                    'filename': filename,
                    'elk_stored': elk_success
                })
                
                return jsonify({
                    'success': True,
                    'events_count': len(events),
                    'elk_stored': elk_success,
                    'summary': summary,
                    'events': events[:10]  # Return first 10 for display
                })
                
        elif request.content_type == 'application/json':
            data = request.get_json()
            filepath = data.get('filepath')
            
            if filepath and os.path.exists(filepath):
                events = ingest.parse_access_log(filepath)
                elk_success = elk_storage.index_events(events)
                summary = ingest.summarize_events(events)
                
                elk_storage.log_activity(
                    user=session.get('user', 'unknown'),
                    action='log_ingestion',
                    details=f'Processed {len(events)} events from {filepath}',
                    result=f'ELK Storage: {"Success" if elk_success else "Failed"}',
                    ip_address=request.remote_addr
                )
                
                return jsonify({
                    'success': True,
                    'events_count': len(events),
                    'elk_stored': elk_success,
                    'summary': summary,
                    'events': events[:10]
                })
        
        return jsonify({'success': False, 'error': 'No valid file provided'})
        
    except Exception as e:
        print(f"[ERROR] Ingestion failed: {e}")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/elk/search', methods=['POST'])
@require_auth
def api_elk_search():
    """Advanced ELK search API"""
    try:
        data = request.get_json()
        query = data.get('query', '')
        filters = data.get('filters', {})
        size = data.get('size', 100)
        
        results = elk_storage.search_events(query, filters, size)
        
        elk_storage.log_activity(
            user=session.get('user', 'unknown'),
            action='elk_search',
            details=f'Search query: {query}',
            result=f'Found {len(results)} results',
            ip_address=request.remote_addr
        )
        
        return jsonify({
            'success': True,
            'results': results,
            'count': len(results)
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/elk/analytics', methods=['GET'])
@require_auth
def api_elk_analytics():
    """Get comprehensive ELK analytics"""
    try:
        analytics = elk_storage.get_threat_analytics()
        
        return jsonify({
            'success': True,
            'analytics': analytics
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/elk/threats/realtime', methods=['GET'])
@require_auth
def api_realtime_threats():
    """Get real-time threat data"""
    try:
        minutes = request.args.get('minutes', 5, type=int)
        threats = elk_storage.get_real_time_threats(minutes)
        
        return jsonify({
            'success': True,
            'threats': threats,
            'count': len(threats)
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/elk/status', methods=['GET'])
@require_auth
def api_elk_status():
    """Get Elasticsearch cluster status"""
    try:
        status = elk_storage.get_elasticsearch_status()
        return jsonify(status)
        
    except Exception as e:
        return jsonify({'available': False, 'error': str(e)})

# Enhanced NLP with ELK search
@app.route('/api/nlp', methods=['POST'])
@require_auth
def api_nlp():
    """Enhanced NLP queries with ELK search capabilities"""
    try:
        data = request.get_json()
        query = data.get('query', '').strip()
        
        print(f"[DEBUG] ELK NLP Query: {query}")
        
        # Try traditional NLP first
        traditional_response = nlp_query.handle_query(query)
        
        # If no traditional response, try ELK search
        elk_response = None
        if not traditional_response:
            # Convert natural language to ELK search
            elk_query, filters = _parse_nlp_to_elk(query)
            if elk_query or filters:
                elk_results = elk_storage.search_events(elk_query, filters, 20)
                elk_response = _format_elk_results(elk_results, query)
        
        response = traditional_response or elk_response or "I couldn't understand your query. Try asking about 'failed logins', 'top IPs', or 'recent threats'."
        
        elk_storage.log_activity(
            user=session.get('user', 'unknown'),
            action='nlp_query',
            details=query,
            result=response[:200] + "..." if len(response) > 200 else response,
            ip_address=request.remote_addr
        )
        
        return jsonify({
            'success': True,
            'response': response,
            'elk_enhanced': elk_response is not None
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

def _parse_nlp_to_elk(query: str) -> tuple:
    """Convert natural language query to ELK search parameters"""
    query_lower = query.lower()
    
    # Search patterns
    elk_query = None
    filters = {}
    
    if 'failed' in query_lower or 'error' in query_lower:
        filters['status_code'] = [400, 401, 403, 404, 500, 502, 503]
    
    if 'recent' in query_lower or 'latest' in query_lower:
        filters['time_range'] = [
            (datetime.now() - timedelta(hours=24)).isoformat(),
            datetime.now().isoformat()
        ]
    
    if 'threat' in query_lower or 'attack' in query_lower:
        filters['threat_level'] = ['high', 'critical']
    
    # Extract IP if mentioned
    import re
    ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
    ip_matches = re.findall(ip_pattern, query)
    if ip_matches:
        filters['ip'] = ip_matches[0]
    
    return elk_query, filters

def _format_elk_results(results: list, original_query: str) -> str:
    """Format ELK search results into natural language response"""
    if not results:
        return f"No events found matching '{original_query}'"
    
    response_parts = [f"Found {len(results)} events:"]
    
    # Group by IP for summary
    ip_counts = {}
    threat_counts = {'low': 0, 'medium': 0, 'high': 0, 'critical': 0}
    
    for event in results[:10]:  # Limit to first 10
        ip = event.get('ip', 'unknown')
        ip_counts[ip] = ip_counts.get(ip, 0) + 1
        
        threat_level = event.get('threat_level', 'info')
        if threat_level in threat_counts:
            threat_counts[threat_level] += 1
    
    # Add top IPs
    top_ips = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:5]
    if top_ips:
        response_parts.append("\nTop IPs:")
        for ip, count in top_ips:
            response_parts.append(f"  • {ip}: {count} events")
    
    # Add threat summary
    if any(threat_counts.values()):
        response_parts.append(f"\nThreat Levels: High({threat_counts['high']}), Medium({threat_counts['medium']}), Low({threat_counts['low']})")
    
    return '\n'.join(response_parts)

# Real-time monitoring with WebSocket
@socketio.on('monitor_threats')
def handle_threat_monitoring():
    """Real-time threat monitoring via WebSocket"""
    print("[DEBUG] Client connected for threat monitoring")
    
    def threat_monitor():
        while True:
            try:
                threats = elk_storage.get_real_time_threats(5)
                if threats:
                    emit('threat_update', {
                        'threats': threats,
                        'count': len(threats),
                        'timestamp': datetime.now().isoformat()
                    })
                time.sleep(30)  # Check every 30 seconds
            except Exception as e:
                print(f"[ERROR] Threat monitoring error: {e}")
                break
    
    # Start monitoring in background thread
    monitor_thread = threading.Thread(target=threat_monitor)
    monitor_thread.daemon = True
    monitor_thread.start()

# Keep existing API endpoints for backward compatibility
@app.route('/api/scan', methods=['POST'])
@require_auth  
def api_scan():
    """File scanning with YARA rules"""
    # Implementation remains the same as your original web_app.py
    pass

@app.route('/api/geoip', methods=['POST'])
@require_auth
def api_geoip():
    """GeoIP lookup"""
    # Implementation remains the same as your original web_app.py
    pass

@app.route('/api/report', methods=['POST'])
@require_auth
def api_report():
    """Generate forensic reports"""
    # Implementation remains the same as your original web_app.py
    pass

@app.route('/api/activity', methods=['GET'])
@require_auth
def api_activity():
    """Get recent activity from ELK"""
    try:
        activities = elk_storage.search_events(
            filters={'time_range': [
                (datetime.now() - timedelta(hours=24)).isoformat(),
                datetime.now().isoformat()
            ]},
            size=20
        )
        
        return jsonify({
            'success': True,
            'activities': activities
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

if __name__ == '__main__':
    print("""
    ╔══════════════════════════════════════════════════════════════╗
    ║              🛡️  Avighna2 SIEM - ELK Edition               ║
    ║          Privacy-First • Secure • Elasticsearch-Powered     ║
    ╚══════════════════════════════════════════════════════════════╝
    
    🔍 ELK Features Available:
    • Advanced Elasticsearch Storage
    • Real-time Threat Analytics  
    • Complex Security Queries
    • Threat Intelligence Correlation
    • Real-time WebSocket Updates
    • Geographic Threat Mapping
    
    🔐 Enhanced Security Features:
    • Elasticsearch Audit Trail
    • Real-time Threat Detection
    • Advanced Search Capabilities
    • Scalable Event Storage
    
    🌐 Access the ELK-powered interface at: http://localhost:5000
    """)
    
    socketio.run(app, host='0.0.0.0', port=5000, debug=True)