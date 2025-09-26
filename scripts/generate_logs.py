# scripts/generate_logs.py
"""
Generate sample Apache-style logs for Avighna2
"""
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
LOGS = ROOT / "logs"

def main():
    LOGS.mkdir(exist_ok=True)

    access_log = LOGS / "access.log"
    corrupt_log = LOGS / "corrupt_access.log"

    access_log.write_text("""192.168.1.5 - - [19/Sep/2025:10:00:01 +0000] "GET /index.html HTTP/1.1" 200 1024
10.0.0.2 - - [19/Sep/2025:10:00:02 +0000] "POST /login HTTP/1.1" 401 512
192.168.1.5 - - [19/Sep/2025:10:00:03 +0000] "GET /admin HTTP/1.1" 403 256
8.8.8.8 - - [19/Sep/2025:10:00:04 +0000] "GET /health HTTP/1.1" 200 64
10.0.0.2 - - [19/Sep/2025:10:00:05 +0000] "GET /home HTTP/1.1" 200 128
""", encoding="utf-8")

    corrupt_log.write_text("""203.0.113.10 - - [20/Sep/2025:11:01:01 +0000] "GET /malware.exe HTTP/1.1" 200 2048
198.51.100.20 - - [20/Sep/2025:11:02:05 +0000] "POST /attack HTTP/1.1" 500 0
192.0.2.5 - - [20/Sep/2025:11:03:09 +0000] "GET /index.html HTTP/1.1" 200 512
8.8.4.4 - - [20/Sep/2025:11:04:12 +0000] "GET /dns-query HTTP/1.1" 200 64
""", encoding="utf-8")

    print(f"[+] Generated {access_log}")
    print(f"[+] Generated {corrupt_log}")

if __name__ == "__main__":
    main()
