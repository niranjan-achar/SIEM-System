# app/web_app.py
"""
Flask Web Frontend for Avighna2 SIEM Assistant
Provides a modern web interface for all SIEM functionality
"""

import hashlib
import json
import os
import time
from datetime import datetime
from pathlib import Path

from dotenv import load_dotenv
from flask import (
    Flask,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    send_file,
    session,
    url_for,
)
from werkzeug.utils import secure_filename

# Import Avighna2 modules
from app import db, enrichment, ingest, nlp_query, report_gen, utils

try:
    from app import geo, ocr_ingest, scanner
except ImportError:
    scanner = geo = ocr_ingest = None

# Load environment variables
ROOT = Path(__file__).resolve().parent.parent
load_dotenv(dotenv_path=ROOT / ".env")

# Flask app configuration
app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "your-secret-key-change-this")
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size
app.config['UPLOAD_FOLDER'] = ROOT / "temp_uploads"
app.config['UPLOAD_FOLDER'].mkdir(exist_ok=True)

# Security configuration
OWNER_PASS = os.getenv("OWNER_PASS", "Avighna123!").strip()
ALLOWED_EXTENSIONS = {'.log', '.txt', '.csv', '.json', '.pdf', '.png', '.jpg', '.jpeg', '.bmp', '.tif', '.tiff', '.xml', '.evtx'}

# Initialize database
db.init_db()

# Security helpers
def is_authenticated():
    """Check if user is authenticated"""
    return session.get('authenticated', False)

def require_auth(f):
    """Decorator to require authentication"""
    def decorated_function(*args, **kwargs):
        if not is_authenticated():
            return jsonify({'error': 'Authentication required'}), 401
        return f(*args, **kwargs)
    decorated_function.__name__ = f.__name__
    return decorated_function

def allowed_file(filename):
    """Check if file extension is allowed"""
    return '.' in filename and Path(filename).suffix.lower() in ALLOWED_EXTENSIONS

# Routes
@app.route('/')
def index():
    """Main dashboard"""
    return render_template('dashboard.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Login page"""
    if request.method == 'POST':
        password = request.form.get('password', '').strip()
        if password == OWNER_PASS:
            session['authenticated'] = True
            session['login_time'] = time.time()
            flash('Successfully logged in!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Invalid password!', 'error')
    return render_template('login.html')

@app.route('/logout')
def logout():
    """Logout"""
    session.clear()
    flash('Successfully logged out!', 'info')
    return redirect(url_for('login'))

@app.route('/api/ingest', methods=['POST'])
@require_auth
def api_ingest():
    """API endpoint for log ingestion"""
    try:
        print(f"[DEBUG] Ingest request received. Files: {list(request.files.keys())}")
        print(f"[DEBUG] Request content type: {request.content_type}")
        
        if 'file' in request.files:
            # File upload
            file = request.files['file']
            print(f"[DEBUG] File received: {file.filename}")
            if file and file.filename and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                filepath = app.config['UPLOAD_FOLDER'] / filename
                file.save(str(filepath))
                print(f"[DEBUG] File saved to: {filepath}")
                
                # Process the file
                result = process_log_file(str(filepath))
                print(f"[DEBUG] Processing result: {result}")
                
                # Clean up
                filepath.unlink(missing_ok=True)
                
                return jsonify(result)
            else:
                return jsonify({'error': 'Invalid file type or no file provided'}), 400
        
        elif request.is_json and request.json and 'filepath' in request.json:
            # File path provided  
            filepath = request.json['filepath']
            print(f"[DEBUG] Processing file path: {filepath}")
            result = process_log_file(filepath)
            return jsonify(result)
        
        else:
            return jsonify({'error': 'No file or filepath provided'}), 400
            
    except Exception as e:
        print(f"[ERROR] Ingest API error: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500

def process_log_file(filepath):
    """Process a log file and return results"""
    try:
        print(f"[DEBUG] Processing log file: {filepath}")
        p = Path(filepath)
        
        if not p.exists():
            return {'error': f'File not found: {filepath}'}
            
        ext = p.suffix.lower()
        print(f"[DEBUG] File extension: {ext}")
        
        # Handle OCR for images/PDFs
        if ext in ('.pdf', '.png', '.jpg', '.jpeg', '.bmp', '.tif', '.tiff'):
            if ocr_ingest is None:
                return {'error': 'OCR module not available. Install: pillow, pytesseract, pdfplumber'}
            
            print("[DEBUG] Processing with OCR...")
            text_log = ocr_ingest.ocr_ingest_any(str(p))
            tmp_path = ROOT / "logs" / f"ocr_{p.stem}.log"
            tmp_path.write_text(text_log, encoding="utf-8")
            events = ingest.parse_access_log(str(tmp_path))
        else:
            # Regular log file
            print("[DEBUG] Processing as regular log file...")
            events = ingest.parse_access_log(str(p))
        
        print(f"[DEBUG] Parsed {len(events)} events")
        summary = ingest.summarize_events(events)
        print(f"[DEBUG] Generated summary: {summary[:100]}...")
        
        # Detect brute force patterns
        fails = [e for e in events if e.get("code") in (401, 403, 500)]
        brute_force_detected = len(fails) >= 3
        
        # Log activity
        db.log_activity("web_user", "ingest", p.name, summary, None)
        
        return {
            'success': True,
            'summary': summary,
            'events_count': len(events),
            'failed_attempts': len(fails),
            'brute_force_detected': brute_force_detected,
            'events': events[:100]  # Limit to first 100 events for display
        }
        
    except Exception as e:
        print(f"[ERROR] Process log file error: {str(e)}")
        import traceback
        traceback.print_exc()
        return {'error': str(e)}

@app.route('/api/scan', methods=['POST'])
@require_auth
def api_scan():
    """API endpoint for file scanning"""
    try:
        if scanner is None:
            return jsonify({'error': 'Scanner module not available'}), 500
            
        if 'file' in request.files:
            file = request.files['file']
            if file and file.filename:
                filename = secure_filename(file.filename)
                filepath = app.config['UPLOAD_FOLDER'] / filename
                file.save(str(filepath))
                
                result = scanner.scan_file(str(filepath))
                
                # Clean up
                filepath.unlink(missing_ok=True)
                
                # Log activity
                db.log_activity("web_user", "scan_file", filename, str(result), None)
                
                return jsonify({
                    'success': True,
                    'result': result,
                    'suspicious': bool(result.get('matches'))
                })
        
        return jsonify({'error': 'No file provided'}), 400
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/geoip', methods=['POST'])
@require_auth
def api_geoip():
    """API endpoint for GeoIP lookup - supports both IP addresses and domain names"""
    try:
        print(f"[DEBUG] GeoIP request received")
        data = request.get_json()
        target = data.get("ip", "").strip() if data else ""  # Can be IP or domain
        print(f"[DEBUG] Target to lookup: {target}")

        if not target:
            return jsonify({"error": "IP address or domain name required"}), 400

        if geo:
            print("[DEBUG] Using enhanced geo module")
            info = geo.lookup(target)
        else:
            print("[DEBUG] Using enrichment module (IP only)")
            # Fallback to enrichment for IP-only lookup (basic IP validation)
            import re

            if not re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", target):
                return (
                    jsonify(
                        {"error": "Domain names not supported with enrichment module"}
                    ),
                    400,
                )
            info = enrichment.geoip_lookup(target)

        print(f"[DEBUG] GeoIP result: {info}")

        # Check for errors in the response
        if info and info.get("error"):
            return jsonify(
                {
                    "success": False,
                    "error": info["error"],
                    "original_input": info.get("original_input", target),
                    "input_type": info.get("input_type", "unknown"),
                }
            )

        # Log activity
        db.log_activity("web_user", "geoip", target, str(info), None)

        return jsonify({"success": True, "target": target, "info": info})

    except Exception as e:
        print(f"[ERROR] GeoIP API error: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500

@app.route('/api/nlp', methods=['POST'])
@require_auth
def api_nlp():
    """API endpoint for NLP queries"""
    try:
        print(f"[DEBUG] NLP request received")
        data = request.get_json()
        query = data.get('query', '').strip() if data else ''
        print(f"[DEBUG] Query: {query}")
        
        if not query:
            return jsonify({'error': 'Query required'}), 400
        
        response = nlp_query.handle_query(query)
        print(f"[DEBUG] NLP Response: {response}")
        
        if response:
            # Log activity
            db.log_activity("web_user", "nlp_query", query, response[:300], None)
            
            return jsonify({
                'success': True,
                'query': query,
                'response': response
            })
        else:
            return jsonify({
                'success': False,
                'error': 'Could not process query - no matching patterns found'
            })
        
    except Exception as e:
        print(f"[ERROR] NLP API error: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500

@app.route('/api/report', methods=['POST'])
@require_auth
def api_report():
    """API endpoint for report generation"""
    try:
        print("[DEBUG] Report generation requested")
        # Try to find a log file to generate report from
        logp = ROOT / "logs" / "corrupt_access.log"
        if not logp.exists():
            logp = ROOT / "logs" / "access.log"
            
        if not logp.exists():
            return jsonify({'error': 'No log files found for report generation. Please upload some logs first.'}), 400
        
        print(f"[DEBUG] Using log file: {logp}")
        events = ingest.parse_access_log(str(logp))
        print(f"[DEBUG] Parsed {len(events)} events")
        
        findings = ingest.summarize_events(events)
        print(f"[DEBUG] Generated findings")
        
        report_path = report_gen.generate_report("Web Case", findings, events)
        print(f"[DEBUG] Report generated at: {report_path}")
        
        # Calculate hash
        file_hash = utils.sha256_of_file(report_path)
        
        # Log activity
        db.log_activity("web_user", "report", logp.name, findings, str(report_path))
        
        return jsonify({
            'success': True,
            'report_path': str(report_path.name),
            'hash': file_hash,
            'download_url': f'/download/{report_path.name}'
        })
        
    except Exception as e:
        print(f"[ERROR] Report API error: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500

@app.route('/download/<filename>')
@require_auth
def download_file(filename):
    """Download generated reports with proper headers"""
    try:
        reports_dir = ROOT / "reports"
        file_path = reports_dir / filename

        if file_path.exists() and file_path.is_file():
            print(f"[DEBUG] Downloading file: {file_path}")

            # Log download activity
            db.log_activity(
                "web_user",
                "download",
                filename,
                f"Downloaded report: {filename}",
                str(file_path),
            )

            return send_file(
                str(file_path),
                as_attachment=True,
                download_name=filename,
                mimetype="application/pdf",
            )
        else:
            print(f"[DEBUG] File not found: {file_path}")
            return jsonify({"error": f"File not found: {filename}"}), 404

    except Exception as e:
        print(f"[ERROR] Download error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/activity')
@require_auth
def api_activity():
    """Get recent activity logs"""
    try:
        import sqlite3
        conn = sqlite3.connect(ROOT / "avighna_activity.db")
        cursor = conn.execute(
            "SELECT ts, user, action, summary, report_path FROM activity ORDER BY id DESC LIMIT 50"
        )
        
        activities = []
        for row in cursor.fetchall():
            activities.append({
                'timestamp': row[0],
                'user': row[1],
                'action': row[2],
                'summary': row[3][:100] + '...' if len(row[3]) > 100 else row[3],
                'report_path': row[4]
            })
        
        conn.close()
        
        return jsonify({
            'success': True,
            'activities': activities
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
