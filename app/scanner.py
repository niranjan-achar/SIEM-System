# app/scanner.py
"""
YARA-based file scanner for Avighna2
Lets you scan files/logs against rule sets to detect suspicious patterns.
"""

import yara
from pathlib import Path

# Default rules path (you can add more .yar files here)
RULES_DIR = Path(__file__).resolve().parent.parent / "data" / "yara_rules"

def load_rules():
    """Load all YARA rules from the rules directory."""
    if not RULES_DIR.exists():
        return None
    rule_files = [str(p) for p in RULES_DIR.glob("*.yar")]
    if not rule_files:
        return None
    try:
        rules = yara.compile(filepaths={str(i): f for i,f in enumerate(rule_files)})
        return rules
    except Exception as e:
        print("[!] Error compiling YARA rules:", e)
        return None

def scan_file(path):
    """Scan a file against loaded YARA rules."""
    rules = load_rules()
    if not rules:
        return {"status":"no_rules","matches":[]}
    p = Path(path)
    if not p.exists():
        return {"status":"file_not_found","matches":[]}
    try:
        matches = rules.match(str(p))
        return {"status":"ok","matches":[m.rule for m in matches]}
    except Exception as e:
        return {"status":"error","error":str(e),"matches":[]}
