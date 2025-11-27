# scanners/ssl_scanner.py
import ssl
import socket
from urllib.parse import urlparse

def check(hostname):
    issues = []
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                version = ssock.version()
                cipher = ssock.cipher()

                if version in ["TLSv1", "TLSv1.1"]:
                    issues.append(f"Weak TLS version: {version} (deprecated)")
                if "RC4" in cipher[0] or "3DES" in cipher[0]:
                    issues.append(f"Insecure cipher: {cipher[0]}")

        # Check for weak cert (self-signed, expired, etc.)
        if not cert:
            issues.append("No SSL certificate presented")
    except Exception as e:
        issues.append(f"SSL/TLS error: {str(e)}")
    return issues if issues else ["SSL/TLS configuration secure"]