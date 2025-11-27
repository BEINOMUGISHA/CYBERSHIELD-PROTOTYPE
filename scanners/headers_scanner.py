# scanners/headers_scanner.py
import requests

def check(url):
    try:
        r = requests.get(url, timeout=10, verify=False)
        headers = r.headers
        issues = []

        missing = [
            ("X-Frame-Options", "Clickjacking protection missing"),
            ("X-Content-Type-Options", "MIME sniffing protection missing"),
            ("X-XSS-Protection", "Legacy XSS protection missing"),
            ("Referrer-Policy", "Referrer leakage risk"),
            ("Content-Security-Policy", "No CSP → High XSS risk"),
            ("Strict-Transport-Security", "HSTS missing → SSL stripping possible"),
            ("Permissions-Policy", "Feature policy missing"),
        ]

        for header, risk in missing:
            if not headers.get(header):
                issues.append(f"Missing header: {header} → {risk}")

        if "Server" in headers:
            issues.append(f"Server header exposed: {headers['Server']} (info leak)")
        if "X-Powered-By" in headers:
            issues.append(f"X-Powered-By exposed: {headers['X-Powered-By']} (fingerprinting)")

        return issues if issues else ["All recommended security headers present"]
    except:
        return ["Failed to analyze headers"]