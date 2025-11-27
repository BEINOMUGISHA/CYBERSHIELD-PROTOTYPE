# scanners/ddos_scanner.py - CyberShield DDoS Vulnerability Detector
import requests
import threading
import time
from urllib.parse import urljoin

def check_rate_limiting(url, threads=20, requests_per_thread=30):
    """Test if server has rate limiting (HTTP Flood test)"""
    findings = []
    success_count = 0
    lock = threading.Lock()

    def attack():
        nonlocal success_count
        session = requests.Session()
        session.headers.update({"User-Agent": "CyberShield-DDoS-Test/1.0"})
        for _ in range(requests_per_thread):
            try:
                r = session.get(url, timeout=5)
                with lock:
                    if r.status_code == 200:
                        success_count += 1
            except:
                pass

    start = time.time()
    threads_list = []
    for _ in range(threads):
        t = threading.Thread(target=attack)
        t.start()
        threads_list.append(t)
    for t in threads_list:
        t.join()

    duration = time.time() - start
    rps = success_count / duration

    if success_count > (threads * requests_per_thread * 0.9):
        findings.append(f"NO RATE LIMITING → Accepted {success_count} requests in {duration:.1f}s ({rps:.1f} RPS) → HTTP Flood possible")
    elif success_count > (threads * requests_per_thread * 0.6):
        findings.append(f"WEAK rate limiting → {success_count}/{threads*requests_per_thread} requests succeeded")
    else:
        findings.append("Rate limiting appears active")

    return findings

def check_slowloris(url):
    """Test Slow HTTP Headers attack (Slowloris-like)"""
    findings = []
    try:
        import socket
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(10)
        host = url.replace("http://", "").replace("https://", "").split("/")[0]
        port = 80 if url.startswith("http://") else 443

        if port == 443:
            import ssl
            context = ssl.create_default_context()
            s = context.wrap_socket(s, server_hostname=host)

        s.connect((host, port))
        s.send(b"GET / HTTP/1.1\r\n")
        s.send(b"Host: " + host.encode() + b"\r\n")

        # Send headers slowly
        for i in range(100):
            time.sleep(0.5)
            s.send(f"X-{i}: {i}\r\n".encode())
            if i == 50:
                # If server hasn't closed connection after 25 seconds → vulnerable
                findings.append("SLOWLORIS VULNERABLE → Accepted 50+ slow headers without timeout")
                break
        s.send(b"\r\n")
        s.close()
    except Exception as e:
        if "vulnerable" not in strFID:
            findings.append("Slowloris test: Connection closed early (likely protected)")

    return findings or ["Slowloris protection appears active"]

def scan(target):
    """Main DDoS vulnerability scanner"""
    findings = []
    findings.append("=== DDoS VULNERABILITY ASSESSMENT ===")

    # Test main page
    try:
        print("[DDoS] Testing rate limiting...")
        rate_issues = check_rate_limiting(target, threads=15, requests_per_thread=25)
        findings.extend(rate_issues)

        print("[DDoS] Testing Slowloris vulnerability...")
        slow_issues = check_slowloris(target)
        findings.extend(slow_issues)

        # Bonus: Check for WAF
        r = requests.get(target, headers={"User-Agent": "CyberShield-Test"})
        if "cloudflare" not in r.headers.get("Server", "").lower() and "cloudfront" not in str(r.headers).lower():
            findings.append("No Cloudflare/Cloudfront detected → More exposed to DDoS")

    except Exception as e:
        findings.append(f"DDoS test failed: {str(e)}")

    return findings