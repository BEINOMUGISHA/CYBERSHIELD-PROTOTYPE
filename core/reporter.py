# core/reporter.py - CyberShield Professional Report Engine v4.0 (FINAL FORM)
import os
import time
from datetime import datetime
from jinja2 import Environment, FileSystemLoader, Template
import pdfkit
import threading

# ==================== JINJA2 SETUP ====================
template_dir = os.path.join(os.path.dirname(__file__), "..", "reports", "templates")
env = Environment(loader=FileSystemLoader(template_dir))

# ==================== PDFKIT CONFIG (WINDOWS SAFE) ====================
WKHTMLTOPDF_PATH = r"C:\Program Files\wkhtmltopdf\bin\wkhtmltopdf.exe"
pdfkit_config = None

if os.path.exists(WKHTMLTOPDF_PATH):
    try:
        pdfkit_config = pdfkit.configuration(wkhtmltopdf=WKHTMLTOPDF_PATH)
    except:
        pdfkit_config = None

if not pdfkit_config:
    try:
        pdfkit_config = pdfkit.configuration()  # Try from PATH
    except:
        print("[!] wkhtmltopdf not found — PDF generation disabled")
        pdfkit_config = None


# ==================== RISK CLASSIFIER ====================
def classify_risk(finding: str) -> str:
    text = finding.lower()
    if any(kw in text for kw in ["sql injection", "rce", "command injection", "lfi", "rfi", "code execution"]):
        return "critical"
    if any(kw in text for kw in ["xss", "csrf", "open redirect", "ssrf", "path traversal"]):
        return "high"
    if any(kw in text for kw in ["directory listing", "missing header", "ssl", "rate limiting", "slowloris"]):
        return "medium"
    return "low"


# ==================== TEXT SUMMARY (CONSOLE) ====================
def text_summary(results):
    target = results.get("target", "Unknown")
    timestamp = results.get("timestamp", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    urls_crawled = results.get("urls_crawled", 0)
    findings = results.get("findings", [])
    critical = results.get("critical", [])

    critical_count = len(critical)
    high_count = len([f for f in findings if classify_risk(f) in ("critical", "high")])

    banner = """
╔══════════════════════════════════════════════════════════════╗
║                  CYBERSHIELD UNSTOPPABLE v4.0               ║
║              web and  APP Vulnerability Scanner               ║
╚══════════════════════════════════════════════════════════════╝
"""
    print(banner)
    print(f" Target:           {target}")
    print(f" Scan Time:        {timestamp}")
    print(f" URLs Crawled:     {urls_crawled}")
    print(f" Total Findings:   {len(findings)}")
    print(f" Critical/High:    {critical_count + high_count}")
    print("\n" + ("=" * 60))

    if findings:
        print(" TOP FINDINGS:")
        for f in findings[:12]:
            icon = "!!" if classify_risk(f) == "critical" else "!" if classify_risk(f) == "high" else "•"
            print(f"   {icon} {f}")
    else:
        print(" No vulnerabilities detected — Target appears secure!")

    print(f"\n Full report saved → reports/output/")
    print("=" * 60 + "\n")


# ==================== GENERATE HTML REPORT (WITH CVSS + FIXES) ====================
def generate_html_report(results, output_dir="reports/output"):
    os.makedirs(output_dir, exist_ok=True)
    
    timestamp = int(time.time())
    filename = f"cybershield_report_{timestamp}.html"
    filepath = os.path.join(output_dir, filename)

    # Load template or use bulletproof fallback
    try:
        template = env.get_template("report_template.html")
    except Exception as e:
        print(f"[!] Template missing → using built-in fallback: {e}")
        template = Template("""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>CyberShield Report</title>
<style>body{font-family:Segoe UI,Arial;background:#0d1117;color:#c9d1d9;padding:40px;}
h1{color:#58a6ff;} .finding{margin:20px 0;padding:20px;background:#161b22;border-left:6px solid #f85149;border-radius:8px;}
.cvss{background:#e31e24;color:white;padding:5px 10px;border-radius:5px;font-weight:bold;}
</style></head><body>
<h1>CYBERSHIELD REPORT</h1>
<p><strong>Target:</strong> {{ target }} | <strong>Date:</strong> {{ date }}</p>
<h2>Findings ({{ findings|length }})</h2>
{% for f in findings %}
<div class="finding">
    <strong><span class="cvss">CVSS {{ f.cvss.score }}</span> {{ f.text }}</strong>
    <br><small>{{ f.cvss.vector }}</small>
</div>
{% endfor %}
<hr><small>CyberShield UNSTOPPABLE v4.0</small>
</body></html>""")

    # Import CVSS & Remediation
    try:
        from core.cvss import calculate_cvss_score
        from core.remediation import get_remediation
    except ImportError as e:
        print(f"[!] Missing module: {e}")
        calculate_cvss_score = lambda x: {"score": 0.0, "severity": "Unknown", "vector": "", "color": "#666"}
        get_remediation = lambda x: {"title": "Unknown", "severity": "Info", "fix": ["Review manually"], "code_example": ""}

    enhanced_findings = []
    total_cvss = 0.0

    for finding in results.get("findings", []):
        cvss = calculate_cvss_score(finding)
        advice = get_remediation(finding)
        total_cvss += cvss["score"]

        enhanced_findings.append({
            "text": finding,
            "risk": classify_risk(finding),
            "cvss": cvss,
            "advice": advice
        })

    overall_risk = "CRITICAL" if total_cvss > 30 else "HIGH" if total_cvss > 15 else "MEDIUM" if total_cvss > 5 else "LOW"

    # Remediation Guide
    fixes_html = "<div class='section'><h2>REMEDIATION GUIDE — How to Fix</h2>"
    seen = set()
    for f in enhanced_findings:
        title = f["advice"]["title"]
        if title not in seen:
            seen.add(title)
            color = f["cvss"]["color"]
            fixes_html += f"""
            <div class="finding" style="border-left:6px solid {color};">
                <div class="finding-title">
                    {title}
                    <span style="background:{color};color:white;padding:4px 10px;border-radius:5px;font-weight:bold;">
                        CVSS {f['cvss']['score']} • {f['cvss']['severity']}
                    </span>
                </div>
                <ul style="margin:15px 0;padding-left:25px;">
                    {''.join(f"<li>{item}</li>" for item in f['advice']['fix'])}
                </ul>
                {f'<pre style="background:#000;padding:15px;border-radius:8px;overflow-x:auto;color:#79c0ff;">{f["advice"]["code_example"]}</pre>' if f['advice']['code_example'] else ''}
            </div><br>"""
    fixes_html += "</div>" if seen else "<p>No major issues requiring remediation.</p>"

    context = {
        "target": results.get("target", "Unknown"),
        "date": datetime.now().strftime("%B %d, %Y at %H:%M:%S"),
        "findings": enhanced_findings,
        "total_findings": len(enhanced_findings),
        "total_cvss": round(total_cvss, 1),
        "overall_risk": overall_risk,
        "fixes_section": fixes_html
    }

    try:
        html_content = template.render(**context)
    except Exception as e:
        html_content = f"<h1>Report Render Error</h1><pre>{e}</pre>"

    with open(filepath, "w", encoding="utf-8") as f:
        f.write(html_content)

    print(f"[+] HTML Report Generated → {filepath}")
    return filepath


# ==================== GENERATE PDF REPORT ====================
def generate_pdf_report(html_path, output_dir="reports/output"):
    if not html_path or not os.path.exists(html_path) or not pdfkit_config:
        return None

    pdf_path = html_path.replace(".html", ".pdf")

    def convert():
        try:
            options = {
                'page-size': 'A4',
                'margin-top': '0.75cm',
                'margin-right': '0.75cm',
                'margin-bottom': '0.75cm',
                'margin-left': '0.75cm',
                'encoding': "UTF-8",
                'quiet': ''
            }
            pdfkit.from_file(html_path, pdf_path, configuration=pdfkit_config, options=options)
            print(f"[+] PDF Report Generated → {pdf_path}")
        except Exception as e:
            print(f"[!] PDF Failed: {e}")

    threading.Thread(target=convert, daemon=True).start()
    return pdf_path


# ==================== MAIN GENERATE FUNCTION ====================
def generate(results, generate_pdf=True):
    """Main entry point — generate HTML + PDF reports"""
    print("\n[+] Generating professional vulnerability report...")
    text_summary(results)
    html_path = generate_html_report(results)
    
    if generate_pdf and html_path:
        generate_pdf_report(html_path)

    return html_path