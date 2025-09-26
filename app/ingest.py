# app/ingest.py
import re
from collections import Counter
from datetime import datetime

IP_REGEX = re.compile(r"(?:\d{1,3}\.){3}\d{1,3}")

def parse_access_log(path):
    """
    Very simple Apache-style access.log parser.
    Returns list of events: dict {ip, ts_str, method_path, code, size}
    """
    events=[]
    with open(path,"r",encoding="utf-8",errors="ignore") as f:
        for line in f:
            line=line.strip()
            if not line: continue
            # try to extract ip and request and status
            ips = IP_REGEX.findall(line)
            ip = ips[0] if ips else "0.0.0.0"
            # get timestamp bracket [...]
            ts_match = re.search(r"\[(.*?)\]", line)
            ts = ts_match.group(1) if ts_match else ""
            # request "GET /path HTTP/1.1"
            req_match = re.search(r'\"(GET|POST|PUT|DELETE|HEAD)\s+([^"]+)\s+HTTP/[\d\.]+"', line)
            method_path = req_match.group(0) if req_match else ""
            code_match = re.search(r'"\s+(\d{3})\s+(\d+)', line)
            code = int(code_match.group(1)) if code_match else 0
            size = int(code_match.group(2)) if code_match else 0
            events.append({"ip":ip,"ts":ts,"req":method_path,"code":code,"size":size,"raw":line})
    return events

def summarize_events(events, top_n=10):
    ips = Counter([e["ip"] for e in events])
    top = ips.most_common(top_n)
    lines = ["Top IPs:"]
    for ip,c in top:
        lines.append(f" - {ip}: {c} hits")
    # quick counts
    total = len(events)
    codes = Counter([e["code"] for e in events])
    lines.append(f"\nTotal events: {total}")
    lines.append("Status codes: " + ", ".join(f"{k}:{v}" for k,v in codes.items()))
    return "\n".join(lines)
