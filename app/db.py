# app/db.py
import sqlite3
from pathlib import Path
import time, hashlib
ROOT = Path(__file__).resolve().parent.parent
DB_PATH = ROOT / "avighna_activity.db"

def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""CREATE TABLE IF NOT EXISTS activity (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ts TEXT,
        user TEXT,
        action TEXT,
        input_hash TEXT,
        summary TEXT,
        report_path TEXT
    )""")
    conn.commit(); conn.close()

def log_activity(user, action, input_text, summary="", report_path=None):
    h = hashlib.sha256((input_text or "").encode("utf-8")).hexdigest()
    conn = sqlite3.connect(DB_PATH)
    conn.execute("INSERT INTO activity (ts,user,action,input_hash,summary,report_path) VALUES (?,?,?,?,?,?)",
                 (time.strftime("%Y-%m-%dT%H:%M:%SZ"), user, action, h, summary, report_path))
    conn.commit(); conn.close()
