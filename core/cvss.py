# core/cvss.py - CyberShield CVSS v3.1 Automatic Scoring Engine
from enum import Enum

class Severity(Enum):
    NONE = 0.0
    LOW = 4.0
    MEDIUM = 7.0
    HIGH = 9.0
    CRITICAL = 10.0

def calculate_cvss_score(finding_text):
    """Auto-calculate CVSS v3.1 Base Score from finding text"""
    text = finding_text.lower()
    
    # Default vector (will be overridden)
    vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"
    
    # === Attack Vector (AV) ===
    if any(x in text for x in ["local", "physical", "adjacent"]):
        av = "L"  # Local
    elif "network" in text:
        av = "N"
    else:
        av = "N"  # Assume network (worst case)

    # === Attack Complexity (AC) ===
    ac = "L" if any(x in text for x in ["low", "simple", "no auth", "default"]) else "H"

    # === Privileges Required (PR) ===
    pr = "N" if any(x in text for x in ["no auth", "unauth", "anonymous", "public"]) else "L"

    # === User Interaction (UI) ===
    ui = "R" if "click" in text or "user" in text or "social" in text else "N"

    # === Scope (S) ===
    s = "C" if "rce" in text or "command" in text or "root" in text else "U"

    # === Impact (C/I/A) ===
    c = i = a = "N"
    if "sql injection" in text or "rce" in text or "command injection" in text or "lfi" in text:
        c = i = a = "H"  # Full compromise
    elif "xss" in text and ("stored" in text or "persistent" in text):
        c = i = "H"; a = "N"
    elif "xss" in text:
        c = i = "L"; a = "N"
    elif "open redirect" in text:
        i = "L"
    elif "missing header" in text or "rate limiting" in text or "slowloris" in text:
        a = "H" if "ddos" in text or "slowloris" in text else "L"

    # Build vector
    vector = f"CVSS:3.1/AV:{av}/AC:{ac}/PR:{pr}/UI:{ui}/S:{s}/C:{c}/I:{i}/A:{a}"

    # Calculate score using official formula
    iss = 1 - ((1 - {"H":0.56, "L":0.22, "N":0}.get(c,0)) *
                (1 - {"H":0.56, "L":0.22, "N":0}.get(i,0)) *
                (1 - {"H":0.56, "L":0.22, "N":0}.get(a,0)))

    if s == "U":
        exploitability = 8.22 * {"N":0.85, "A":0.62, "L":0.55, "P":0.2}.get(av, 0.85) * \
                                   {"L":0.77, "H":0.44}.get(ac, 0.77) * \
                                   {"N":0.85, "H":0.62, "L":0.71}.get(pr, 0.85) * \
                                   {"N":0.85, "R":0.62}.get(ui, 0.85)
        base_score = min(10, round(exploitability + (3.326 * iss), 1))
    else:
        base_score = min(10, round(1.08 * (exploitability + (3.326 * iss)), 1))

    # Final score & severity
    score = round(base_score, 1)
    severity = "Critical" if score >= 9.0 else "High" if score >= 7.0 else "Medium" if score >= 4.0 else "Low"

    return {
        "score": score,
        "severity": severity,
        "vector": vector,
        "color": "#e31e24" if score >= 9.0 else "#f5a623" if score >= 7.0 else "#f8d32d" if score >= 4.0 else "#7cb342"
    }