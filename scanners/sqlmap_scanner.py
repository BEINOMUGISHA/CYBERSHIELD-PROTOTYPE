# scanners/sqlmap_scanner.py - CyberShield SQLMap Integration v2.0
import requests
import time
import threading
from datetime import datetime

API_BASE = "http://127.0.0.1:8776"
SESSION = requests.Session()
SESSION.headers.update({
    "Content-Type": "application/json",
    "User-Agent": "CyberShield/2.0"
})

class SQLMapScanner:
    def __init__(self):
        self.task_id = None
        self.stop_requested = False
        self.callback = None  # For GUI progress updates

    def log(self, message):
        timestamp = datetime.now().strftime("%H:%M:%S")
        full_msg = f"[SQLMap {timestamp}] {message}"
        print(full_msg)
        if self.callback:
            self.callback(full_msg)

    def create_task(self):
        try:
            r = SESSION.post(f"{API_BASE}/task/new", timeout=10)
            if r.status_code == 200:
                self.task_id = r.json().get("taskid")
                if self.task_id:
                    self.log(f"Task created: {self.task_id}")
                    return True
        except Exception as e:
            self.log(f"Failed to connect to SQLMap API: {e}")
            self.log("Start SQLMap API: python sqlmap/sqlmapapi.py -s -p 8776")
        return False

    def start_scan(self, url, level=3, risk=2, threads=6, timeout=600):
        if not self.task_id:
            return False

        payload = {
            "url": url,
            "level": level,
            "risk": risk,
            "batch": True,
            "threads": threads,
            "randomAgent": True,
            "forms": True,
            "crawlDepth": 2,
            "flushSession": True,
            "skipWafCheck": False,
            "forceSSL": True,
            "timeout": 30,
            "retries": 2
        }

        try:
            r = SESSION.post(f"{API_BASE}/scan/{self.task_id}/start", json=payload, timeout=15)
            if r.status_code == 200 and r.json().get("success"):
                self.log(f"Deep SQL injection scan started (Level {level}, Risk {risk})")
                self.log("This may take 2–15 minutes on complex targets...")
                return True
        except Exception as e:
            self.log(f"Failed to start scan: {e}")
        return False

    def get_status(self):
        try:
            r = SESSION.get(f"{API_BASE}/scan/{self.task_id}/status", timeout=10)
            return r.json()
        except:
            return None

    def get_log(self):
        try:
            r = SESSION.get(f"{API_BASE}/scan/{self.task_id}/log", timeout=10)
            return r.json().get("log", [])
        except:
            return []

    def get_results(self):
        try:
            r = SESSION.get(f"{API_BASE}/scan/{self.task_id}/data", timeout=15)
            return r.json().get("data", [])
        except:
            return []

    def delete_task(self):
        if self.task_id:
            try:
                SESSION.get(f"{API_BASE}/task/{self.task_id}/delete", timeout=10)
                self.log("Task cleaned up.")
            except:
                pass
            self.task_id = None

    def scan_deep(self, url, callback=None, max_wait=900):
        """
        Main function - runs full SQLMap scan with progress
        """
        self.callback = callback
        self.stop_requested = False

        if not self.create_task():
            return {
                "vulnerable": False,
                "findings": [],
                "error": "SQLMap API server not running!",
                "hint": "Run: python sqlmap/sqlmapapi.py -s -p 8776"
            }

        if not self.start_scan(url):
            self.delete_task()
            return {"vulnerable": False, "findings": [], "error": "Failed to start scan"}

        start_time = time.time()
        last_log_size = 0

        self.log("Waiting for SQLMap to complete (max 15 minutes)...")

        while time.time() - start_time < max_wait:
            if self.stop_requested:
                self.log("Scan cancelled by user")
                self.delete_task()
                return {"vulnerable": False, "findings": [], "cancelled": True}

            status = self.get_status()
            if not status:
                time.sleep(5)
                continue

            current_status = status.get("status", "running")
            if current_status == "terminated":
                break
            elif current_status == "running":
                # Show live logs
                logs = self.get_log()
                if logs and len(logs) > last_log_size:
                    new_logs = logs[last_log_size:]
                    for entry in new_logs[-3:]:  # Show last 3 lines
                        msg = entry.get("message", "")
                        if "payload" in msg.lower() or "injectable" in msg.lower():
                            self.log(f"Progress: {msg}")
                    last_log_size = len(logs)
            time.sleep(8)

        # Final results
        data = self.get_results()
        findings = []

        for item in data:
            if item.get("vulnerable"):
                param = item.get("parameter", "Unknown")
                payload = item.get("payload", "")[:120]
                dbms = item.get("dbms", "Unknown")
                technique = item.get("title", "Unknown")

                findings.append({
                    "parameter": param,
                    "payload": payload,
                    "dbms": dbms,
                    "technique": technique,
                    "type": "SQL Injection (Confirmed)"
                })

        vulnerable = bool(findings)
        if vulnerable:
            self.log(f"SQL INJECTION FOUND! {len(findings)} parameter(s) injectable!")
            for f in findings[:3]:
                self.log(f" → {f['parameter']} → {f['technique']}")
        else:
            self.log("No SQL injection found.")

        self.delete_task()
        return {
            "vulnerable": vulnerable,
            "findings": findings,
            "count": len(findings),
            "engine": "SQLMap"
        }

# Easy-to-use function (for backward compatibility)
def scan_deep(url, callback=None):
    scanner = SQLMapScanner()
    return scanner.scan_deep(url, callback=callback)