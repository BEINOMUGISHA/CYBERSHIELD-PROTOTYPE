# core/remediation.py - CyberShield Fix Advisor (Pro Edition)
REMEDIATIONS = {
    # XSS
    "xss": {
        "title": "Cross-Site Scripting (XSS)",
        "severity": "Critical",
        "fix": [
            "• Escape all user input with HTML entity encoding",
            "• Use a secure library: OWASP Java Encoder, DOMPurify (JS), or built-in template escaping",
            "• Set HttpOnly + Secure flags on cookies",
            "• Implement Content-Security-Policy (CSP) header",
            "• Example CSP: default-src 'self'; script-src 'self'; object-src 'none'"
        ],
        "code_example": """<!-- BAD -->
<input value="{{ user_input }}">

<!-- GOOD -->
<input value="{{ user_input|escape }}">  {# Django/Jinja #}
<input value="<?= htmlspecialchars($input, ENT_QUOTES) ?>">  {# PHP #}"""
    },

    # SQL Injection
    "sql injection": {
        "title": "SQL Injection",
        "severity": "Critical",
        "fix": [
            "• Use Prepared Statements / Parameterized Queries (NEVER concatenate SQL)",
            "• Use ORM (Django ORM, SQLAlchemy, Hibernate)",
            "• Validate and sanitize all input",
            "• Least privilege database user"
        ],
        "code_example": """# BAD
cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")

# GOOD
cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))"""
    },

    # Missing Headers
    "missing header": {
        "title": "Missing Security Headers",
        "severity": "High",
        "fix": [
            "• X-Frame-Options: DENY → prevents clickjacking",
            "• X-Content-Type-Options: nosniff → stops MIME sniffing",
            "• Content-Security-Policy → blocks XSS",
            "• Strict-Transport-Security (HSTS) → forces HTTPS",
            "• Referrer-Policy: strict-origin-when-cross-origin"
        ],
        "code_example": """# Nginx
add_header X-Frame-Options "DENY" always;
add_header Content-Security-Policy "default-src 'self'" always;

# Apache .htaccess
Header set X-Frame-Options "DENY"
Header set Content-Security-Policy "default-src 'self'\""""
    },

    # Directory Listing
    "directory listing": {
        "title": "Directory Listing Enabled",
        "severity": "Medium",
        "fix": [
            "• Disable directory browsing in web server",
            "• Add index.php/index.html to all folders",
            "• Use .htaccess (Apache) or web.config (IIS)"
        ],
        "code_example": """# Apache .htaccess
Options -Indexes

# Nginx
autoindex off;"""
    },

    # DDoS / Rate Limiting
    "no rate limiting": {
        "title": "No Rate Limiting (HTTP Flood / Brute Force Risk)",
        "severity": "High",
        "fix": [
            "• Implement rate limiting (e.g., 100 req/min per IP)",
            "• Use Cloudflare, nginx limit_req, or Flask-Limiter",
            "• Add CAPTCHA on login/forms after 5 fails"
        ],
        "code_example": """# Flask-Limiter
from flask_limiter import Limiter
limiter = Limiter(app, default_limits=["100 per minute"])

@route("/login")
@limiter.limit("5 per minute")
def login(): pass"""
    },

    "slowloris": {
        "title": "Slowloris / Slow HTTP Attack Vulnerable",
        "severity": "High",
        "fix": [
            "• Set low Keep-Alive timeout (5–10 seconds)",
            "• Limit headers size and count",
            "• Use reverse proxy (nginx, Cloudflare) with timeout settings"
        ],
        "code_example": """# Nginx protection
client_header_timeout 10s;
client_body_timeout 10s;
keepalive_timeout 5s;
limit_conn_zone $binary_remote_addr zone=limit:10m;"""
    }
}

def get_remediation(finding_text):
    """Return fix advice for any finding"""
    text = finding_text.lower()
    for keyword, advice in REMEDIATIONS.items():
        if keyword in text:
            return advice
    return {
        "title": "Security Finding",
        "severity": "Info",
        "fix": ["• Review the finding and apply secure coding practices"],
        "code_example": ""
    }