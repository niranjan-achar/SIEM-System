# app/utils.py
from pathlib import Path
import hashlib

def sha256_of_file(path):
    p = Path(path)
    if not p.exists(): return ""
    h = hashlib.sha256()
    with p.open("rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()

def confirm_action(prompt_text):
    while True:
        ans = input(f"{prompt_text} (yes/no) > ").strip().lower()
        if ans in ("yes","y"): return True
        if ans in ("no","n"): return False
        print("Please answer yes or no.")
