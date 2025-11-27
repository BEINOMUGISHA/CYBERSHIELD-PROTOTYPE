# core/scanner.py - CyberShield Master Scanner Engine v3.2 — LIVE + CVSS + FORENSIC
import time
import threading
from urllib.parse import urlparse
from datetime import datetime

# Import all your pro scanners
from scanners import (
    crawler,
    xss_scanner,
    headers_scanner,
    ssl_scanner,
    dir_bruter,
    sqlmap_scanner
)

# Vulnerability class — same as in main.py (must match!)
class Vulnerability:
    def __init__(self, vuln_type, severity, description, url, param=None, line=None, payload=None):
        self.type = vuln_type
        self.severity = severity.upper()
        self.description = description
        self.url = url
        self.param = param
        self.line = line
        self.payload = payload
        self.timestamp = datetime.now().strftime("%H:%M:%S")

        # Real CVSS v3.1 scores
        scores = {
            "XSS": 8.8, "SQL Injection": 9.8, "RCE": 9.8, "LFI": 7.5,
            "Missing CSP": 7.4, "Clickjacking": 6.5, "Open Redirect": 6.1,
            "Directory Listing": 5.3, "Weak SSL": 6.5, "SQLMap": 9.8
        }
        self.score = scores.get(vuln_type.split()[0], 6.5)
        self.vector = f"CVSS:3.1/AV:N/AC:L/PR:N/UI:{'R' if 'XSS' in vuln_type else 'N'}/S:U/C:H/I:H/A:N"

    def location_str(self):
        loc = self.url
        if self.param: loc += f"?{self.param}=..."
        if self.line: loc += f" @ line ~{self.line}"
        return loc

class VulnerabilityScanner:
    def __init__(self):
        self.stop_flag = False
        self.current_step = ""
        self.lock = threading.Lock()

    def stop(self):
        with self.lock:
            self.stop_flag = True
        print("[!] Scan cancelled by user")

    def is_stopped(self):
        with self.lock:
            return self.stop_flag

    def safe_callback(self, callback, message, progress=None):
        if callback and not self.is_stopped():
            try:
                callback(message, progress)
            except:
                pass

    def scan(self, target, callback=None):
        start_time = time.time()
        self.stop_flag = False

        if not target.startswith(("http://", "https://")):
            target = "https://" + target
        target = target.rstrip("/")

        results = {
            "target": target,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "scan_duration": 0,
            "urls_crawled": 0,
            "findings": [],
            "critical": [],
            "high": [],
            "medium": [],
            "low": [],
            "scanner_version": "CyberShield v3.2"
        }

        self.safe_callback(callback, "Initializing CyberShield v3.2 engine...", 2)

        # === 1. Crawling ===
        if self.is_stopped(): return results
        self.safe_callback(callback, "Phase 1/7: Smart crawling in progress...", 10)
        try:
            urls = crawler.crawl(target, max_pages=60, max_depth=4)
            results["urls_crawled"] = len(urls)
            self.safe_callback(callback, f"Crawled {len(urls)} pages", 18)
        except Exception as e:
            urls = [target]
            results["findings"].append(f"Crawler failed: {str(e)}")

        # === 2. XSS Scanning ===
        if self.is_stopped(): return results
        self.safe_callback(callback, "Phase 2/7: Hunting for XSS vulnerabilities...", 25)
        try:
            xss_findings = xss_scanner.scan(urls[:20])
            for finding in xss_findings:
                if "XSS" in finding or "alert" in finding.lower():
                    vuln = Vulnerability(
                        vuln_type="Reflected XSS",
                        severity="CRITICAL",
                        description=finding,
                        url=target,
                        param="q",
                        payload="<script>alert(1)</script>"
                    )
                    results["findings"].append(vuln)
                    results["critical"].append(vuln)
                else:
                    results["findings"].append(finding)
            self.safe_callback(callback, f"XSS check complete ({len(xss_findings)} issues)", 35)
        except Exception as e:
            results["findings"].append(f"XSS scanner error: {str(e)}")

        # === 3. Security Headers ===
        if self.is_stopped(): return results
        self.safe_callback(callback, "Phase 3/7: Analyzing HTTP security headers...", 40)
        try:
            header_issues = headers_scanner.check(target)
            for issue in header_issues:
                header_name = issue.split("missing")[0].strip() if "missing" in issue else issue
                severity = "HIGH" if "Content-Security-Policy" in issue or "HSTS" in issue else "MEDIUM"
                vuln = Vulnerability(
                    vuln_type=f"Missing {header_name}",
                    severity=severity,
                    description=issue,
                    url=target
                )
                results["findings"].append(vuln)
                if severity == "HIGH":
                    results["high"].append(vuln)
                else:
                    results["medium"].append(vuln)
        except Exception as e:
            results["findings"].append(f"Header check failed: {str(e)}")

        # === 4. SSL/TLS Analysis ===
        if self.is_stopped(): return results
        self.safe_callback(callback, "Phase 4/7: Validating SSL/TLS configuration...", 50)
        try:
            hostname = urlparse(target).netloc.split(":")[0]
            ssl_issues = ssl_scanner.check(hostname)
            for issue in ssl_issues:
                vuln = Vulnerability(
                    vuln_type="Weak SSL/TLS",
                    severity="HIGH" if "weak" in issue.lower() else "MEDIUM",
                    description=issue,
                    url=target
                )
                results["findings"].append(vuln)
                results["high" if "weak" in issue.lower() else "medium"].append(vuln)
        except Exception as e:
            results["findings"].append(f"SSL check failed: {str(e)}")

        # === 5. Directory Brute Force ===
        if self.is_stopped(): return results
        self.safe_callback(callback, "Phase 5/7: Brute-forcing hidden directories...", 60)
        try:
            dir_findings = dir_bruter.scan(target)
            for d in dir_findings:
                path = d.split("→")[-1].strip()
                vuln = Vulnerability(
                    vuln_type="Exposed Directory",
                    severity="HIGH" if any(x in path.lower() for x in ["admin", "backup", ".git"]) else "MEDIUM",
                    description=d,
                    url=target + path.split()[-1]
                )
                results["findings"].append(vuln)
                results["high" if vuln.severity == "HIGH" else "medium"].append(vuln)
        except Exception as e:
            results["findings"].append(f"Dir brute failed: {str(e)}")

        # === 6. SQL Injection via SQLMap ===
        if self.is_stopped(): return results
        self.safe_callback(callback, "Phase 6/7: Running SQLMap deep injection scan...", 70)
        try:
            sqli_result = sqlmap_scanner.scan_deep(target, callback=lambda msg:
                self.safe_callback(callback, msg, None))

            if sqli_result.get("vulnerable"):
                for vuln_data in sqli_result["findings"]:
                    param = vuln_data.get("parameter", "unknown")
                    tech = vuln_data.get("technique", "Unknown")
                    dbms = vuln_data.get("dbms", "Unknown")
                    vuln = Vulnerability(
                        vuln_type="SQL Injection",
                        severity="CRITICAL",
                        description=f"SQLi in parameter '{param}' via {tech} → {dbms}",
                        url=target,
                        param=param,
                        payload=vuln_data.get("payload", "N/A")
                    )
                    results["findings"].append(vuln)
                    results["critical"].append(vuln)
                results["findings"].append(f"SQLMap confirmed {len(sqli_result['findings'])} injectable parameter(s)")
            else:
                results["findings"].append("SQLMap: No SQL injection found")
        except Exception as e:
            results["findings"].append(f"SQLMap failed: {str(e)}")

        # === Finalize ===
        results["scan_duration"] = round(time.time() - start_time, 2)
        self.safe_callback(callback, "Scan completed! Generating forensic report...", 100)

        # Deduplicate
        seen = set()
        dedup_findings = []
        for f in results["findings"]:
            key = str(f) if isinstance(f, Vulnerability) else f
            if key not in seen:
                seen.add(key)
                dedup_findings.append(f)
        results["findings"] = dedup_findings

        return results