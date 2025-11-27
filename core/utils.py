# core/utils.py
import os
from datetime import datetime

def log(msg):
    print(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}")

def sanitize_url(url):
    return url.strip().rstrip("/") + "/" if not url.endswith("/") else url