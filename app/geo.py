# app/geo.py
"""
Enhanced GeoIP enrichment with domain name support
Supports both IP addresses and domain names with website information
"""

import re
import socket
from pathlib import Path

import geoip2.database
import requests

# Default DB path (download GeoLite2-City.mmdb from MaxMind free account)
DB_PATH = Path(__file__).resolve().parent.parent / "data" / "GeoLite2-City.mmdb"


def is_valid_ip(address):
    """Check if given string is a valid IP address"""
    try:
        socket.inet_aton(address)
        return True
    except socket.error:
        return False


def resolve_domain_to_ip(domain):
    """
    Resolve domain name to IP address
    Returns tuple: (success, ip_or_error, website_info)
    """
    try:
        # Clean domain name
        domain = domain.strip().lower()

        # Remove protocol if present
        if domain.startswith(("http://", "https://")):
            domain = domain.split("://", 1)[1]

        # Remove path if present
        domain = domain.split("/")[0]

        # Remove port if present
        domain = domain.split(":")[0]

        # Validate domain format
        if not re.match(r"^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", domain):
            return False, "Invalid domain format", None

        # Resolve domain to IP
        ip = socket.gethostbyname(domain)

        # Get website information
        website_info = {
            "domain": domain,
            "website_name": domain.split(".")[
                0
            ].title(),  # Basic website name from domain
            "resolved_ip": ip,
        }

        # Try to get more detailed website info
        try:
            # Make a quick HEAD request to get server info
            response = requests.head(
                f"http://{domain}", timeout=5, allow_redirects=True
            )
            website_info["server"] = response.headers.get("Server", "Unknown")
            website_info["final_url"] = response.url
        except:
            website_info["server"] = "Unknown"
            website_info["final_url"] = f"http://{domain}"

        return True, ip, website_info

    except socket.gaierror:
        return False, "Domain not found", None
    except Exception as e:
        return False, f"Resolution error: {str(e)}", None


def _lookup_with_mmdb(ip):
    """Lookup using local MaxMind database"""
    reader = geoip2.database.Reader(str(DB_PATH))
    resp = reader.city(ip)
    return {
        "country": resp.country.name,
        "city": resp.city.name,
        "latitude": float(resp.location.latitude) if resp.location.latitude else None,
        "longitude": (
            float(resp.location.longitude) if resp.location.longitude else None
        ),
        "isp": None,
        "source": "MaxMind Local DB",
    }


def _lookup_with_api(ip):
    """Lookup using ip-api.com"""
    r = requests.get(f"http://ip-api.com/json/{ip}", timeout=4)
    if r.status_code == 200:
        data = r.json()
        if data.get("status") == "success":
            return {
                "country": data.get("country"),
                "city": data.get("city"),
                "latitude": data.get("lat"),
                "longitude": data.get("lon"),
                "isp": data.get("isp"),
                "source": "ip-api.com",
            }
    return None


def lookup(ip_or_domain):
    """
    Enhanced lookup supporting both IP addresses and domain names
    Returns dict with comprehensive geo and website info
    """
    original_input = ip_or_domain
    website_info = None

    # Check if input is an IP address or domain name
    if is_valid_ip(ip_or_domain):
        # It's an IP address
        ip = ip_or_domain
    else:
        # It's a domain name - resolve it
        success, result, website_info = resolve_domain_to_ip(ip_or_domain)
        if not success:
            return {
                "error": result,
                "original_input": original_input,
                "input_type": "domain",
            }
        ip = result

    # Get geographic information
    geo_data = None

    # Try local DB first
    if DB_PATH.exists():
        try:
            geo_data = _lookup_with_mmdb(ip)
        except Exception as e:
            print(f"[GeoIP] Local DB failed for {ip}: {e}, falling back to API")

    # Fallback to API if local DB failed
    if not geo_data:
        geo_data = _lookup_with_api(ip)

    # Enhance response with original input and website info
    if geo_data:
        geo_data["original_input"] = original_input
        geo_data["resolved_ip"] = ip
        geo_data["input_type"] = "domain" if website_info else "ip"

        if website_info:
            geo_data["website_info"] = website_info

    return geo_data or {
        "error": "Unable to resolve geographic information",
        "original_input": original_input,
        "resolved_ip": ip,
        "input_type": "domain" if website_info else "ip",
    }
