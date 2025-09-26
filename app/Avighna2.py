# app/Avighna2.py
"""
Avighna2 — Conversational SIEM Assistant
Updated: dotenv + robust passcode, beeps, lockout, file-finding, quarantine handling
Step 1 add-on: OCR ingest for PDFs/images -> text -> parse as logs
"""

import argparse
import os
import sys
import time
import getpass
import datetime
from pathlib import Path

from dotenv import load_dotenv

# application modules (ensure these exist in app/)
from app import ingest, db, utils, enrichment, nlp_query, report_gen
try:
    from app import scanner, geo
except Exception:
    scanner, geo = None, None

# 🔹 NEW: OCR module
try:
    from app import ocr_ingest
except Exception:
    ocr_ingest = None

# color support
try:
    from colorama import Fore, Style
except Exception:
    class Dummy:
        def __getattr__(self, k): return ""
    Fore = Style = Dummy()

# ----------------- Config / env -----------------
ROOT = Path(__file__).resolve().parent.parent
# load .env explicitly from project root
load_dotenv(dotenv_path=ROOT / ".env")
OWNER_PASS = os.getenv("OWNER_PASS", "Avighna123!").strip()

# allowed extensions for file-finding (added images + pdf)
ALLOWED_EXTS = [".log", ".txt", ".csv", ".json", ".pdf", ".png", ".jpg", ".jpeg", ".bmp", ".tif", ".tiff", ".xml", ".evtx"]

# ----------------- Security state -----------------
FAILED_ATTEMPTS = 0
LOCKED_UNTIL = None  # datetime.datetime or None

# ----------------- Helpers / Presentation -----------------
def banner():
    print(Fore.CYAN + Style.BRIGHT + "═" * 64)
    print("      🛡️  Avighna2 — Conversational SIEM Assistant")
    print("        (Privacy-First • Secure • Intelligent • OCR-ready)")
    print("═" * 64 + Style.RESET_ALL)
    print(f"{Fore.GREEN}[Avighna]{Style.RESET_ALL} Passcode system active. OWNER_PASS loaded.\n")

def avighna_print(msg, color=Fore.WHITE):
    lines = str(msg).splitlines() or [msg]
    for i, line in enumerate(lines):
        prefix = f"{Fore.GREEN}[Avighna]{Style.RESET_ALL}" if i == 0 else " " * 9
        print(color + f"{prefix} {line}" + Style.RESET_ALL)

def safe_path(relpath: str) -> Path:
    """
    Resolve a user-provided relative path inside project root.
    Raises ValueError if resolved path would leave ROOT.
    """
    p = (ROOT / relpath).resolve()
    try:
        p.relative_to(ROOT)
    except Exception:
        raise ValueError("Access denied: path outside project root")
    return p

# ----------------- Beep / Alert helpers -----------------
def play_beep(times=1, freq=1000, dur=300):
    """Play beep times times. Uses winsound on Windows otherwise bell fallback."""
    try:
        import winsound
        for _ in range(times):
            winsound.Beep(freq, dur)
            time.sleep(0.06)
    except Exception:
        for _ in range(times):
            sys.stdout.write("\a"); sys.stdout.flush()
            time.sleep(0.06)

def trigger_alert(reason="Suspicious activity detected"):
    """Show alert, play sound and call lockdown_mode as fallback."""
    try:
        play_beep(times=4, freq=750, dur=400)
    except Exception:
        pass
    avighna_print(f"⚠️ ALERT: {reason}", Fore.RED)
    # call lockdown_mode which will prompt for passcode until correct
    try:
        lockdown_mode()
    except Exception:
        pass

def lockdown_mode():
    """Interactive unlock loop — prompts owner until correct passcode."""
    while True:
        try:
            pw = getpass.getpass("Enter owner passcode to unlock: ").strip()
        except Exception:
            pw = input("Enter owner passcode to unlock: ").strip()
        if pw == OWNER_PASS:
            avighna_print("✅ Access restored. Monitoring resumed.", Fore.GREEN)
            break
        else:
            avighna_print("❌ Wrong passcode.", Fore.RED)
            play_beep(times=1)

def is_locked():
    """Return True if the protected actions are currently locked due to failed attempts."""
    global LOCKED_UNTIL
    if LOCKED_UNTIL is None: return False
    return datetime.datetime.now() < LOCKED_UNTIL

# ----------------- Passcode handling -----------------
def request_passcode(prompt="Enter owner passcode: "):
    """
    Ask for passcode. Implements progressive penalties:
      - 1-2 wrong attempts: brief beep + message
      - 3rd wrong attempt: 3 short beeps + warning
      - 5th wrong attempt: lock for 2 minutes, loud beeps, call trigger_alert
    Returns True if passcode matches, False otherwise.
    """
    global FAILED_ATTEMPTS, LOCKED_UNTIL
    now = datetime.datetime.now()

    if is_locked():
        wait = int((LOCKED_UNTIL - now).total_seconds())
        avighna_print(f"[LOCKED] Too many failed attempts. Try again in {wait}s", Fore.RED)
        return False

    try:
        pw = getpass.getpass(prompt).strip()
    except Exception:
        pw = input(prompt).strip()

    if pw == OWNER_PASS:
        FAILED_ATTEMPTS = 0
        return True

    # wrong attempt
    FAILED_ATTEMPTS += 1
    play_beep(times=1, freq=1000, dur=300)
    avighna_print("❌ Wrong passcode.", Fore.RED)

    if FAILED_ATTEMPTS == 3:
        play_beep(times=3, freq=1200, dur=350)
        avighna_print("⚠️  3 wrong attempts — be careful.", Fore.YELLOW)

    if FAILED_ATTEMPTS >= 5:
        LOCK_DURATION_MIN = 2
        LOCKED_UNTIL = now + datetime.timedelta(minutes=LOCK_DURATION_MIN)
        play_beep(times=6, freq=800, dur=500)
        avighna_print(f"⛔ Too many failures! Locked for {LOCK_DURATION_MIN} minutes.", Fore.RED)
        # escalate alert but do not crash
        try:
            trigger_alert("Multiple unauthorized access attempts!")
        except Exception:
            pass

    return False

# ----------------- File finding (search by name) -----------------
def find_file_by_name(name, search_roots=None, max_depth=3):
    """
    Try to locate a file by name (or partial name) across logical locations.
    - name: filename or partial name (with or without extension)
    - search_roots: list of Path to search (defaults to project root + common drives)
    - max_depth: restrict how deep to search (to avoid full-disk scan)
    Returns Path or None.
    """
    name = name.strip()
    base = Path(name)
    # quick check: absolute or relative path provided
    if any(ch in name for ch in (":", "\\", "/")):
        try:
            p = Path(name).expanduser().resolve()
            if p.exists(): return p
        except Exception:
            pass

    # quick check inside project root
    try:
        p = (ROOT / name).resolve()
        if p.exists():
            return p
    except Exception:
        pass

    # prepare search roots: project root and common drives
    roots = []
    if search_roots:
        roots = [Path(r) for r in search_roots if Path(r).exists()]
    else:
        roots = [ROOT]
        for d in ("C:\\", "D:\\", "E:\\"):
            if Path(d).exists():
                roots.append(Path(d))

    candidates = []
    # walk each root with depth pruning
    for root in roots:
        root = root.resolve()
        for dirpath, dirnames, filenames in os.walk(root):
            try:
                rel = Path(dirpath).resolve().relative_to(root)
                depth = len(rel.parts)
            except Exception:
                depth = 0
            if depth > max_depth:
                dirnames[:] = []
                continue
            for fn in filenames:
                fn_lower = fn.lower()
                # exact or startswith
                if fn_lower == name.lower() or fn_lower.startswith(name.lower()):
                    candidates.append(Path(dirpath) / fn)
                    continue
                # if name has no suffix, try allowed extensions
                if not base.suffix:
                    for ext in ALLOWED_EXTS:
                        if fn_lower == (name + ext).lower():
                            candidates.append(Path(dirpath) / fn)
                            break
            if candidates:
                # prefer candidates inside project folder
                for c in candidates:
                    try:
                        if str(ROOT) in str(c):
                            return c
                    except Exception:
                        pass
                return candidates[0]
    return None

# ----------------- Quarantine -----------------
def quarantine_log(path, reason="corrupted"):
    """
    Move a log file to logs/quarantine and return message.
    Accepts Path or str.
    """
    p = Path(path)
    try:
        p = p.resolve()
    except Exception:
        p = Path(path)
    qdir = ROOT / "logs" / "quarantine"
    qdir.mkdir(parents=True, exist_ok=True)
    qpath = qdir / p.name
    try:
        p.replace(qpath)
        return f"Log {p} quarantined ({reason})."
    except Exception as e:
        return f"Failed to quarantine {p}: {e}"

# ----------------- CLI Loop -----------------
def start_cli():
    banner()
    db.init_db()

    while True:
        try:
            text = input(Fore.YELLOW + "[You] > " + Style.RESET_ALL).strip()
        except (EOFError, KeyboardInterrupt):
            avighna_print("Goodbye.", Fore.GREEN)
            break

        if not text:
            continue

        cmd = text.strip()
        lower = cmd.lower()

        if lower in ("exit", "quit"):
            avighna_print("Goodbye.", Fore.GREEN)
            break

        if lower == "help":
            show_help()
            continue

        # ---------- ingest <name|path> ----------
        if lower.startswith("ingest "):
            try:
                arg = cmd.split(maxsplit=1)[1].strip()

                # locate file by safe_path or name search
                p = None
                try:
                    p_candidate = safe_path(arg)
                    if p_candidate.exists():
                        p = p_candidate
                except Exception:
                    p = None
                if p is None:
                    p = find_file_by_name(arg)
                if p is None or not p.exists():
                    avighna_print(f"[!] File not found: {arg}", Fore.RED)
                    continue

                ext = p.suffix.lower()
                # 🔹 If PDF or image → OCR → create temp log → parse
                if ext in (".pdf", ".png", ".jpg", ".jpeg", ".bmp", ".tif", ".tiff"):
                    if ocr_ingest is None:
                        avighna_print("[!] OCR module not available. Install: pillow, pytesseract, pdfplumber", Fore.RED)
                        continue
                    avighna_print("🖼️  OCR mode: extracting text...", Fore.CYAN)
                    try:
                        text_log = ocr_ingest.ocr_ingest_any(str(p))
                        tmp_path = ROOT / "logs" / f"ocr_{p.stem}.log"
                        tmp_path.write_text(text_log, encoding="utf-8")
                        events = ingest.parse_access_log(str(tmp_path))
                    except Exception as e:
                        msg = quarantine_log(p, f"OCR/parse failed: {e}")
                        avighna_print(f"⚠️ {msg}", Fore.YELLOW)
                        db.log_activity("cli_user", "quarantine", p.name, msg, None)
                        continue
                else:
                    # normal .log/.txt, etc.
                    try:
                        events = ingest.parse_access_log(str(p))
                    except Exception as e:
                        msg = quarantine_log(p, str(e))
                        avighna_print(f"⚠️ {msg}", Fore.YELLOW)
                        db.log_activity("cli_user", "quarantine", p.name, msg, None)
                        continue

                summary = ingest.summarize_events(events)
                avighna_print(summary, Fore.CYAN)
                db.log_activity("cli_user", "ingest", p.name, summary, None)

                # simple detection: brute force
                fails = [e for e in events if e.get("code") in (401, 403, 500)]
                if len(fails) >= 3:
                    avighna_print("🚨 Brute-force login pattern detected!", Fore.RED)

            except Exception as e:
                avighna_print(f"Error ingesting: {e}", Fore.RED)
            continue

        # ---------- report (protected) ----------
        if lower.startswith("generate report") or lower == "report":
            if is_locked():
                avighna_print("Protected actions currently locked. Wait and retry.", Fore.RED)
                continue
            if not request_passcode():
                continue
            try:
                # default: try a logical log
                logp = ROOT / "logs" / "corrupt_access.log"
                if not logp.exists():
                    candidate = find_file_by_name("access.log")
                    if candidate:
                        logp = candidate
                events = ingest.parse_access_log(str(logp))
                findings = ingest.summarize_events(events)
                outp = report_gen.generate_report("Demo Case", findings, events)
                h = utils.sha256_of_file(outp)
                avighna_print(f"Report generated: {outp}", Fore.GREEN)
                avighna_print(f"SHA256: {h}", Fore.GREEN)
                db.log_activity("cli_user", "report", logp.name, findings, str(outp))
            except Exception as e:
                avighna_print(f"Report failed: {e}", Fore.RED)
            continue

        # ---------- scan file <name|path> (protected) ----------
        if lower.startswith("scan file"):
            if is_locked():
                avighna_print("Protected actions currently locked. Wait and retry.", Fore.RED)
                continue
            if not request_passcode():
                continue
            try:
                parts = cmd.split(maxsplit=2)
                if len(parts) < 3:
                    avighna_print("Usage: scan file <filename_or_path>", Fore.YELLOW)
                    continue
                arg = parts[2].strip()
                p = None
                try:
                    p_candidate = safe_path(arg)
                    if p_candidate.exists():
                        p = p_candidate
                except Exception:
                    p = None
                if p is None:
                    p = find_file_by_name(arg)
                if p is None or not p.exists():
                    avighna_print(f"[!] File not found: {arg}", Fore.RED)
                    continue
                if scanner is None:
                    avighna_print("[!] Scanner module not available.", Fore.RED)
                    continue
                res = scanner.scan_file(str(p))
                if res.get("status") == "ok" and res.get("matches"):
                    avighna_print(f"❌ Suspicious patterns: {res['matches']}", Fore.RED)
                    db.log_activity("cli_user", "scan_file", p.name, str(res), None)
                else:
                    avighna_print("[+] No suspicious patterns found.", Fore.GREEN)
                    db.log_activity("cli_user", "scan_file", p.name, str(res), None)
            except Exception as e:
                avighna_print(f"Scan failed: {e}", Fore.RED)
            continue

        # ---------- geoip <ip> ----------
        if lower.startswith("geoip "):
            try:
                ip = cmd.split(maxsplit=1)[1].strip()
                if geo:
                    info = geo.lookup(ip)
                else:
                    info = enrichment.geoip_lookup(ip)
                avighna_print(f"GeoIP info for {ip}: {info}", Fore.CYAN)
                db.log_activity("cli_user", "geoip", ip, str(info), None)
            except Exception as e:
                avighna_print(f"GeoIP failed: {e}", Fore.RED)
            continue

        # ---------- NLP queries ----------
        resp = nlp_query.handle_query(cmd)
        if resp:
            avighna_print(resp, Fore.CYAN)
            db.log_activity("cli_user", "nlp_query", cmd, (resp[:300] if len(resp)>300 else resp), None)
            continue

        avighna_print("Unknown command. Type 'help' for commands.", Fore.YELLOW)

def show_help():
    avighna_print("""
Commands:
  ingest <name|path>   - Parse logs, OR OCR PDFs/images -> parse (filename or path)
  report               - Generate forensic PDF report (passcode protected)
  scan file <name|path>- Scan file with YARA rules (passcode protected)
  geoip <ip>           - Lookup IP geolocation
  show top <N> ...     - Natural queries (via NLP)
  exit                 - Quit
""", Fore.CYAN)

# ----------------- Entry -----------------
def main():
    parser = argparse.ArgumentParser()
    args = parser.parse_args()
    start_cli()

if __name__ == "__main__":
    main()
