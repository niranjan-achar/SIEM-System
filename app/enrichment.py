# app/enrichment.py
import requests
import socket
from urllib.parse import urlparse
import re
import json
from pathlib import Path

IP_REGEX = re.compile(r"(?:\d{1,3}\.){3}\d{1,3}")

def reverse_dns(ip: str) -> str:
    """Resolve IP → hostname (reverse DNS)."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return "-"

def geoip_lookup(ip: str) -> dict:
    """Lookup geolocation and ISP info for an IP (using ip-api.com, free & demo-safe)."""
    try:
        r = requests.get(f"http://ip-api.com/json/{ip}", timeout=4)
        if r.status_code == 200:
            data = r.json()
            if data.get("status") == "success":
                return {
                    "country": data.get("country"),
                    "city": data.get("city"),
                    "isp": data.get("isp"),
                    "org": data.get("org"),
                }
    except Exception:
        pass
    return {"country": None, "city": None, "isp": None, "org": None}

def whois_lookup(domain_or_ip: str) -> dict:
    """
    Placeholder WHOIS lookup.
    For safety/demo: returns fake info if offline. 
    You can later install python-whois for richer info.
    """
    try:
        if IP_REGEX.match(domain_or_ip):
            # treat as IP → return stub
            return {"query": domain_or_ip, "registrar": "-", "created": "-", "expires": "-"}
        else:
            # treat as domain
            return {"query": domain_or_ip, "registrar": "DemoRegistrar", "created": "2021-01-01", "expires": "2026-01-01"}
    except Exception as e:
        return {"query": domain_or_ip, "error": str(e)}

# ---- Threat DB check ----
ROOT = Path(__file__).resolve().parent.parent
THREAT_DB = ROOT / "data" / "threat_db.json"

def check_threat_db(ip_or_domain: str) -> dict:
    """
    Check if IP/domain is in our local threat database.
    threat_db.json should look like:
    { "malicious_ips": ["1.2.3.4"], "malicious_domains": ["bad.com"] }
    """
    if not THREAT_DB.exists():
        return {"listed": False, "reason": None}
    try:
        db = json.loads(THREAT_DB.read_text(encoding="utf-8"))
        if ip_or_domain in db.get("malicious_ips", []):
            return {"listed": True, "reason": "Known malicious IP"}
        if ip_or_domain in db.get("malicious_domains", []):
            return {"listed": True, "reason": "Known malicious domain"}
    except Exception:
        return {"listed": False, "reason": "error reading db"}
    return {"listed": False, "reason": None}
