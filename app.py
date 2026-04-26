
import json
import random
from datetime import datetime, date

import matplotlib.pyplot as plt
import pandas as pd
import streamlit as st

try:
    from anthropic import Anthropic
except Exception:
    Anthropic = None

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle


# ---------------- PAGE SETUP ----------------
st.set_page_config(
    page_title="Enterprise GRC Risk Intelligence Platform",
    page_icon="🛡️",
    layout="wide"
)


# ---------------- STYLE ----------------
st.markdown("""
<style>
.block-container { padding-top: 1.2rem; padding-bottom: 2rem; }

.hero-box {
    background: linear-gradient(135deg, #0f172a 0%, #1e3a8a 55%, #2563eb 100%);
    border-radius: 18px;
    padding: 28px 30px;
    color: white;
    margin-bottom: 1.5rem;
}
.hero-box h1 { color: white !important; font-size: 1.8rem !important; margin-bottom: 6px; }
.hero-box p  { color: #dbeafe !important; font-size: 0.98rem; margin: 0; }

.card {
    background: #ffffff;
    padding: 20px 16px;
    border-radius: 14px;
    border: 1px solid #e2e8f0;
    text-align: center;
    margin-bottom: 10px;
}
.card h2 { color: #1e40af !important; font-size: 2rem !important; }
.card h4 { color: #64748b !important; font-size: 0.82rem !important; text-transform: uppercase; letter-spacing: 0.05em; }

.card.critical { border-left: 5px solid #7f1d1d; background: #fef2f2; }
.card.high     { border-left: 5px solid #ef4444; background: #fff5f5; }
.card.medium   { border-left: 5px solid #f59e0b; background: #fffbeb; }
.card.low      { border-left: 5px solid #22c55e; background: #f0fdf4; }

.section-box {
    background: #f8fafc;
    padding: 18px 20px;
    border-radius: 14px;
    border: 1px solid #e2e8f0;
    margin-bottom: 16px;
}

.plain-english-box {
    background: #fffbeb;
    border: 1px solid #fcd34d;
    border-radius: 12px;
    padding: 16px 20px;
    margin: 12px 0;
    font-size: 1rem;
    line-height: 1.6;
    color: #78350f;
}

.action-tag {
    display: inline-block;
    font-size: 0.72rem;
    font-weight: 700;
    padding: 3px 9px;
    border-radius: 20px;
    margin-right: 8px;
    text-transform: uppercase;
    letter-spacing: 0.04em;
}
.tag-now   { background: #fee2e2; color: #991b1b; }
.tag-week  { background: #fef3c7; color: #92400e; }
.tag-doc   { background: #dbeafe; color: #1e40af; }

.sidebar-card {
    background: #f8fafc;
    padding: 12px 14px;
    border-radius: 12px;
    border: 1px solid #e2e8f0;
    margin-bottom: 12px;
}

.step-label {
    font-size: 0.78rem;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.06em;
    color: #64748b;
    margin-bottom: 6px;
}

.small-muted {
    color: #64748b;
    font-size: 0.88rem;
}
</style>
""", unsafe_allow_html=True)


# ---------------- SESSION STATE ----------------
defaults = {
    "history": [],
    "last_result": None,
    "selected_asset": "Database",
    "selected_threat": "Data Breach",
    "smart_description": "",
    "input_mode": "smart",
    "ai_detected": None,
}
for key, value in defaults.items():
    if key not in st.session_state:
        st.session_state[key] = value


# ---------------- DATA ----------------
ASSET_OPTIONS = [
    "Database", "Application", "Cloud Environment", "Network",
    "Endpoint / Laptop", "Email System", "User Credentials", "Server",
    "API", "Backup System", "Identity / IAM", "SaaS Platform",
    "Mobile Device", "Vendor / Third Party",
    "HVAC / Building Management System", "IoT Device",
    "OT / Industrial System", "Building Access Control",
    "Security Camera / CCTV", "Finance System", "HR System",
    "Customer Portal"
]

THREAT_OPTIONS = [
    "Data Breach", "Unauthorized Access", "Malware", "Phishing",
    "Misconfiguration", "Insider Threat", "Ransomware",
    "Supply Chain Attack", "Zero-Day Exploit",
    "Denial of Service (DDoS)", "Credential Attack",
    "Data Loss", "Privilege Escalation", "API Abuse"
]

ASSET_THREAT_MAP = {
    "Database": ["Data Breach", "Unauthorized Access", "Ransomware", "Misconfiguration", "Privilege Escalation", "Data Loss"],
    "Application": ["Unauthorized Access", "Phishing", "Misconfiguration", "Denial of Service (DDoS)", "Zero-Day Exploit"],
    "Cloud Environment": ["Misconfiguration", "Data Breach", "Unauthorized Access", "Denial of Service (DDoS)", "Zero-Day Exploit", "Supply Chain Attack"],
    "Network": ["Denial of Service (DDoS)", "Unauthorized Access", "Malware", "Misconfiguration"],
    "Endpoint / Laptop": ["Malware", "Phishing", "Ransomware", "Unauthorized Access", "Data Loss"],
    "Email System": ["Phishing", "Data Breach", "Unauthorized Access", "Malware"],
    "User Credentials": ["Credential Attack", "Unauthorized Access", "Phishing", "Privilege Escalation"],
    "Server": ["Malware", "Ransomware", "Privilege Escalation", "Unauthorized Access", "Zero-Day Exploit"],
    "API": ["API Abuse", "Unauthorized Access", "Denial of Service (DDoS)", "Zero-Day Exploit"],
    "Backup System": ["Data Loss", "Ransomware", "Unauthorized Access"],
    "Identity / IAM": ["Privilege Escalation", "Unauthorized Access", "Credential Attack"],
    "SaaS Platform": ["Data Breach", "Unauthorized Access", "Phishing", "Supply Chain Attack", "Credential Attack"],
    "Mobile Device": ["Malware", "Phishing", "Unauthorized Access", "Data Loss"],
    "Vendor / Third Party": ["Supply Chain Attack", "Data Breach", "Unauthorized Access"],
    "HVAC / Building Management System": ["Unauthorized Access", "Misconfiguration", "Denial of Service (DDoS)", "Insider Threat"],
    "IoT Device": ["Unauthorized Access", "Malware", "Denial of Service (DDoS)", "Misconfiguration"],
    "OT / Industrial System": ["Unauthorized Access", "Malware", "Denial of Service (DDoS)", "Insider Threat", "Ransomware"],
    "Building Access Control": ["Unauthorized Access", "Insider Threat", "Misconfiguration"],
    "Security Camera / CCTV": ["Unauthorized Access", "Data Breach", "Misconfiguration"],
    "Finance System": ["Data Breach", "Unauthorized Access", "Insider Threat", "Data Loss", "Ransomware"],
    "HR System": ["Data Breach", "Unauthorized Access", "Insider Threat", "Phishing", "Data Loss"],
    "Customer Portal": ["Phishing", "API Abuse", "Data Breach", "Denial of Service (DDoS)", "Credential Attack"]
}

THREAT_PROFILES = {
    "Data Breach": {"likelihood": 4, "impact": 5},
    "Unauthorized Access": {"likelihood": 4, "impact": 4},
    "Malware": {"likelihood": 4, "impact": 4},
    "Phishing": {"likelihood": 5, "impact": 3},
    "Misconfiguration": {"likelihood": 4, "impact": 4},
    "Insider Threat": {"likelihood": 3, "impact": 5},
    "Ransomware": {"likelihood": 4, "impact": 5},
    "Supply Chain Attack": {"likelihood": 3, "impact": 5},
    "Zero-Day Exploit": {"likelihood": 3, "impact": 5},
    "Denial of Service (DDoS)": {"likelihood": 4, "impact": 4},
    "Credential Attack": {"likelihood": 5, "impact": 4},
    "Data Loss": {"likelihood": 3, "impact": 5},
    "Privilege Escalation": {"likelihood": 3, "impact": 5},
    "API Abuse": {"likelihood": 4, "impact": 4},
}

ASSET_THREAT_SCORES = {
    ("Endpoint / Laptop", "Malware"): (4, 3),
    ("Endpoint / Laptop", "Phishing"): (4, 3),
    ("Endpoint / Laptop", "Ransomware"): (3, 4),
    ("Endpoint / Laptop", "Data Loss"): (3, 4),
    ("Email System", "Phishing"): (5, 4),
    ("Email System", "Malware"): (4, 3),
    ("Email System", "Unauthorized Access"): (3, 4),
    ("Database", "Data Breach"): (4, 5),
    ("Database", "Unauthorized Access"): (4, 5),
    ("Database", "Data Loss"): (3, 5),
    ("Database", "Ransomware"): (3, 5),
    ("Cloud Environment", "Misconfiguration"): (5, 5),
    ("Cloud Environment", "Data Breach"): (4, 5),
    ("Cloud Environment", "Supply Chain Attack"): (3, 5),
    ("API", "API Abuse"): (5, 4),
    ("API", "Denial of Service (DDoS)"): (4, 5),
    ("API", "Unauthorized Access"): (4, 4),
    ("Finance System", "Data Breach"): (3, 5),
    ("Finance System", "Insider Threat"): (3, 5),
    ("Finance System", "Data Loss"): (3, 5),
    ("HR System", "Data Breach"): (3, 5),
    ("HR System", "Phishing"): (4, 4),
    ("Vendor / Third Party", "Supply Chain Attack"): (4, 5),
    ("Vendor / Third Party", "Data Breach"): (3, 5),
    ("Network", "Denial of Service (DDoS)"): (4, 5),
    ("Network", "Misconfiguration"): (4, 4),
    ("HVAC / Building Management System", "Unauthorized Access"): (3, 3),
    ("HVAC / Building Management System", "Misconfiguration"): (3, 3),
    ("OT / Industrial System", "Ransomware"): (3, 5),
    ("OT / Industrial System", "Malware"): (3, 5),
}

EXAMPLE_PROMPTS = [
    "My laptop was stolen at the airport and it has client data on it",
    "An employee shared their password with a contractor over Slack",
    "Our website went down for 3 hours due to a sudden traffic spike",
    "We got a suspicious email asking us to click a link to verify payroll",
    "A vendor we share HR data with just had a data breach",
    "Someone in finance accidentally deleted last quarter's billing records",
]

TIPS = [
    "Risk is not just technical. It affects operations, trust, money, and compliance.",
    "Residual risk helps companies understand what remains after controls are applied.",
    "A good risk register should include owner, status, treatment, and review date.",
    "Zero Trust means verifying every user, device, and request continuously.",
]

GLOSSARY = {
    "Inherent Risk": "The risk before considering the effectiveness of existing controls.",
    "Residual Risk": "The remaining risk after existing controls reduce exposure.",
    "Control Effectiveness": "How well current safeguards reduce the likelihood or impact of a risk.",
    "NIST CSF": "A cybersecurity framework used to organize cybersecurity activities around Govern, Identify, Protect, Detect, Respond, and Recover.",
    "RMF": "Risk Management Framework — a structured process for managing security and privacy risk.",
    "Zero Trust": "A security model based on verify explicitly, least privilege, and assume breach.",
    "Risk Treatment": "The decision to Mitigate, Accept, Transfer, or Avoid a risk.",
}


# ---------------- CORE LOGIC ----------------
def risk_level(score: int):
    if score >= 20:
        return "CRITICAL", "🔴", "#7f1d1d"
    if score >= 13:
        return "HIGH", "🔴", "#ef4444"
    if score >= 7:
        return "MEDIUM", "🟡", "#f59e0b"
    return "LOW", "🟢", "#22c55e"


def get_formula_text():
    return {
        "inherent": "Inherent Risk = Likelihood × Impact",
        "residual": "Residual Risk = Inherent Risk × (1 - Control Effectiveness)",
        "control": "Control Effectiveness is rated from 0% to 90% based on how strong existing controls are.",
        "scale": "Likelihood and Impact are scored from 1 to 5."
    }


def calculate_auto_scores(asset, threat, matched_words=None):
    matched_words = matched_words or []

    if (asset, threat) in ASSET_THREAT_SCORES:
        base_likelihood, base_impact = ASSET_THREAT_SCORES[(asset, threat)]
        source = "asset-threat pair baseline"
    else:
        base_likelihood = THREAT_PROFILES.get(threat, {}).get("likelihood", 3)
        base_impact = THREAT_PROFILES.get(threat, {}).get("impact", 3)
        source = "threat baseline"

    keyword_boost = 1 if len(matched_words) >= 5 else 0
    likelihood = max(1, min(5, base_likelihood + keyword_boost))
    impact = max(1, min(5, base_impact))

    reasons = [
        f"Used {source}: likelihood {base_likelihood}, impact {base_impact}.",
        f"Keyword evidence adjustment: +{keyword_boost} to likelihood.",
        f"Final auto score values: likelihood {likelihood}, impact {impact}."
    ]
    return likelihood, impact, reasons


def calculate_risks(likelihood, impact, control_effectiveness):
    inherent = likelihood * impact
    residual = round(inherent * (1 - control_effectiveness / 100))
    residual = max(0, residual)
    return inherent, residual


def get_nist_mapping(threat):
    return {
        "Data Breach": "Govern, Protect, Detect, Respond",
        "Unauthorized Access": "Protect, Detect, Respond",
        "Malware": "Detect, Respond, Recover",
        "Phishing": "Protect, Detect, Respond",
        "Misconfiguration": "Identify, Protect",
        "Insider Threat": "Govern, Protect, Detect, Respond",
        "Ransomware": "Protect, Detect, Respond, Recover",
        "Supply Chain Attack": "Govern, Identify, Protect, Detect",
        "Zero-Day Exploit": "Identify, Protect, Detect, Respond",
        "Denial of Service (DDoS)": "Protect, Detect, Respond",
        "Credential Attack": "Protect, Detect, Respond",
        "Data Loss": "Protect, Recover",
        "Privilege Escalation": "Protect, Detect, Respond",
        "API Abuse": "Protect, Detect, Respond",
    }.get(threat, "Identify, Protect")


def get_rmf_mapping(threat):
    return {
        "Data Breach": "Categorize, Select, Implement, Assess, Monitor",
        "Unauthorized Access": "Select, Implement, Assess, Monitor",
        "Malware": "Implement, Assess, Monitor",
        "Phishing": "Select, Implement, Monitor",
        "Misconfiguration": "Categorize, Select, Implement, Assess",
        "Insider Threat": "Categorize, Select, Assess, Monitor",
        "Ransomware": "Select, Implement, Assess, Monitor",
        "Supply Chain Attack": "Categorize, Select, Assess, Monitor",
        "Zero-Day Exploit": "Select, Implement, Assess, Monitor",
        "Denial of Service (DDoS)": "Select, Implement, Monitor",
        "Credential Attack": "Select, Implement, Monitor",
        "Data Loss": "Categorize, Implement, Monitor",
        "Privilege Escalation": "Select, Implement, Assess, Monitor",
        "API Abuse": "Select, Implement, Monitor",
    }.get(threat, "Categorize, Select, Implement, Monitor")


def get_zero_trust_guidance(threat):
    return {
        "Data Breach": ["Enforce least-privilege access.", "Encrypt sensitive data.", "Monitor access to critical data stores."],
        "Unauthorized Access": ["Require MFA.", "Validate device trust.", "Continuously monitor sessions."],
        "Malware": ["Restrict endpoint privileges.", "Inspect device posture.", "Limit lateral movement."],
        "Phishing": ["Use phishing-resistant MFA.", "Train users.", "Validate suspicious requests."],
        "Misconfiguration": ["Use secure baselines.", "Monitor configuration drift.", "Limit admin privileges."],
        "Ransomware": ["Segment systems and backups.", "Verify privileged access.", "Test recovery procedures."],
        "Credential Attack": ["Require MFA.", "Detect abnormal login behavior.", "Apply least privilege."],
        "API Abuse": ["Authenticate every API request.", "Use token validation.", "Monitor API activity."],
    }.get(threat, ["Verify explicitly.", "Use least privilege.", "Assume breach."])


def business_impact(threat, asset, industry):
    base = {
        "Data Breach": f"Sensitive information in the {asset.lower()} may be exposed, creating legal, reputational, financial, and compliance impact.",
        "Unauthorized Access": f"Unauthorized users may access the {asset.lower()}, leading to misuse, data exposure, or operational disruption.",
        "Malware": f"Malware may disrupt the {asset.lower()}, reduce productivity, corrupt data, or spread across connected systems.",
        "Phishing": f"Employees may disclose credentials or approve fraudulent actions, increasing the chance of account compromise.",
        "Misconfiguration": f"Incorrect settings may expose systems or data without immediate detection.",
        "Insider Threat": f"An internal user may misuse trusted access, creating high business and trust impact.",
        "Ransomware": f"The {asset.lower()} may become unavailable, causing downtime, recovery costs, and business interruption.",
        "Supply Chain Attack": f"A vendor or dependency may introduce risk into the organization, affecting trust and operations.",
        "Zero-Day Exploit": f"An unknown vulnerability may be exploited before patches or detections are available.",
        "Denial of Service (DDoS)": f"The {asset.lower()} may become unavailable, causing service disruption and customer dissatisfaction.",
        "Credential Attack": f"Compromised credentials may allow attackers to access business systems and move laterally.",
        "Data Loss": f"Important information may be deleted, corrupted, or become unrecoverable.",
        "Privilege Escalation": f"An attacker may gain higher permissions and compromise sensitive systems.",
        "API Abuse": f"APIs may be misused to access data, disrupt services, or perform unauthorized activity.",
    }.get(threat, f"The {asset.lower()} may be affected, creating operational or security risk.")

    if industry == "Healthcare":
        return base + " In healthcare, this may also affect patient trust, care continuity, and privacy obligations."
    if industry == "Finance":
        return base + " In finance, this may also increase fraud, regulatory, and customer confidence risks."
    if industry == "Education":
        return base + " In education, this may affect students, faculty, research data, and institutional trust."
    if industry == "Manufacturing":
        return base + " In manufacturing, this may affect production uptime, safety, and operational continuity."
    return base


def get_recommendations(threat):
    return {
        "Data Breach": ["Encrypt sensitive data.", "Apply least privilege access.", "Enable monitoring and alerting.", "Review data retention policies."],
        "Unauthorized Access": ["Enable MFA.", "Review access permissions.", "Monitor abnormal logins.", "Apply role-based access control."],
        "Malware": ["Use endpoint protection.", "Patch systems.", "Restrict admin rights.", "Run regular scans."],
        "Phishing": ["Train users.", "Use email filtering.", "Enable MFA.", "Create a suspicious email reporting process."],
        "Misconfiguration": ["Apply secure baselines.", "Perform configuration reviews.", "Automate compliance checks.", "Restrict admin access."],
        "Insider Threat": ["Review access rights.", "Monitor unusual activity.", "Apply separation of duties.", "Create reporting channels."],
        "Ransomware": ["Maintain offline backups.", "Test recovery plans.", "Patch critical systems.", "Segment the network."],
        "Supply Chain Attack": ["Assess vendor security.", "Restrict vendor access.", "Review contracts.", "Monitor third-party dependencies."],
        "Zero-Day Exploit": ["Use layered defenses.", "Monitor anomalies.", "Segment critical systems.", "Patch quickly when fixes are released."],
        "Denial of Service (DDoS)": ["Use rate limiting.", "Deploy DDoS protection.", "Create failover plans.", "Monitor traffic spikes."],
        "Credential Attack": ["Enforce MFA.", "Monitor brute-force attempts.", "Use password hygiene controls.", "Disable stale accounts."],
        "Data Loss": ["Maintain tested backups.", "Restrict deletion rights.", "Use versioning.", "Monitor destructive actions."],
        "Privilege Escalation": ["Limit admin privileges.", "Monitor privilege changes.", "Use PAM.", "Patch privilege escalation vulnerabilities."],
        "API Abuse": ["Use authentication.", "Apply rate limits.", "Monitor API usage.", "Review exposed endpoints."]
    }.get(threat, ["Review controls.", "Monitor risk.", "Document next steps."])


def suggest_treatment(threat, residual_score):
    if residual_score >= 20:
        return "Mitigate", "Critical residual risk requires immediate reduction."
    if residual_score >= 13:
        return "Mitigate", "High residual risk should be reduced through stronger controls."
    if residual_score >= 7:
        if threat in ["Supply Chain Attack", "Denial of Service (DDoS)"]:
            return "Transfer", "Some risk may be transferred through vendors, contracts, or insurance."
        return "Mitigate", "Medium risk should be reduced within a planned remediation cycle."
    return "Accept", "Low residual risk may be accepted with monitoring and periodic review."


def get_treatment_actions(treatment, residual_score):
    actions = {
        "Mitigate": ["Assign a remediation owner.", "Implement or improve controls.", "Set a target completion date.", "Reassess residual risk after remediation."],
        "Accept": ["Document acceptance rationale.", "Get approval from the risk owner.", "Set a future review date.", "Monitor for changes."],
        "Transfer": ["Review vendor or insurance options.", "Confirm contractual responsibilities.", "Monitor remaining residual risk.", "Document transfer decision."],
        "Avoid": ["Stop or redesign the risky activity.", "Identify safer alternatives.", "Document business trade-offs.", "Seek leadership approval."]
    }
    base = actions.get(treatment, ["Document the decision."])
    if residual_score >= 13:
        base.append("Escalate to leadership or security governance committee.")
    return base


def fallback_detect_from_description(description):
    desc = description.lower()

    asset_rules = {
        "Endpoint / Laptop": ["laptop", "computer", "device", "workstation"],
        "Email System": ["email", "mail", "inbox", "message"],
        "User Credentials": ["password", "credentials", "login", "account"],
        "Customer Portal": ["website", "portal", "customer portal", "site"],
        "Finance System": ["finance", "billing", "invoice", "payroll"],
        "HR System": ["hr", "employee", "personnel"],
        "Vendor / Third Party": ["vendor", "third party", "contractor", "supplier"],
        "Database": ["database", "data", "records", "client data", "customer data"],
        "Cloud Environment": ["cloud", "aws", "azure", "gcp"],
        "API": ["api", "endpoint", "token"],
        "Backup System": ["backup", "restore", "recovery"],
        "Network": ["network", "traffic", "router", "switch", "firewall"],
    }

    threat_rules = {
        "Phishing": ["suspicious email", "clicked a link", "fake email", "verify payroll", "phishing"],
        "Data Breach": ["data breach", "exposed", "leaked", "client data", "customer data"],
        "Unauthorized Access": ["stolen", "someone accessed", "unauthorized", "shared password"],
        "Credential Attack": ["password", "login", "shared their password", "credentials"],
        "Denial of Service (DDoS)": ["traffic spike", "website went down", "outage", "ddos"],
        "Ransomware": ["encrypted", "locked", "ransomware"],
        "Data Loss": ["deleted", "lost records", "missing files"],
        "Malware": ["acting strange", "infected", "virus", "malware"],
        "Supply Chain Attack": ["vendor", "third party", "supplier had a breach"],
        "Misconfiguration": ["misconfiguration", "open access", "public bucket"],
    }

    detected_asset = next((asset for asset, words in asset_rules.items() if any(w in desc for w in words)), "Application")
    detected_threat = next((threat for threat, words in threat_rules.items() if any(w in desc for w in words)), "Unauthorized Access")

    if detected_threat not in ASSET_THREAT_MAP.get(detected_asset, []):
        detected_threat = ASSET_THREAT_MAP[detected_asset][0]

    return detected_asset, detected_threat


def ai_analyze_description(description):
    if Anthropic is None:
        return None

    try:
        client = Anthropic()
        system_prompt = f"""
You are a GRC and cybersecurity risk analyst.
Return ONLY valid JSON.

Choose asset from:
{ASSET_OPTIONS}

Choose threat from:
{THREAT_OPTIONS}

Required JSON:
{{
  "asset": "<exact asset>",
  "threat": "<exact threat>",
  "likelihood": <integer 1-5>,
  "impact": <integer 1-5>,
  "plain_english_summary": "<2-3 sentence business-friendly summary>",
  "actions": [
    {{"tag": "Do now", "text": "<immediate action>"}},
    {{"tag": "This week", "text": "<short-term action>"}},
    {{"tag": "Document", "text": "<documentation step>"}}
  ],
  "confidence": "<low|medium|high>"
}}
"""
        response = client.messages.create(
            model="claude-opus-4-5",
            max_tokens=800,
            system=system_prompt,
            messages=[{"role": "user", "content": description}]
        )
        return json.loads(response.content[0].text.strip())
    except Exception:
        return None


# ---------------- REPORTING ----------------
def add_page_header_footer(canvas, doc):
    canvas.saveState()
    canvas.setFont("Helvetica-Bold", 10)
    canvas.setFillColor(colors.HexColor("#1f3b73"))
    canvas.drawString(50, 760, "Enterprise GRC Risk Assessment Report")
    canvas.setStrokeColor(colors.HexColor("#d0d7de"))
    canvas.line(50, 755, 560, 755)
    canvas.setFont("Helvetica", 9)
    canvas.setFillColor(colors.HexColor("#6b7280"))
    canvas.drawString(50, 30, "Prepared by Saloni Bhosale | GRC & Cybersecurity Risk")
    canvas.drawRightString(560, 30, f"Page {doc.page}")
    canvas.restoreState()


def pdf_table(data, widths):
    table = Table(data, colWidths=widths)
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1f3b73")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#cbd5e1")),
        ("BACKGROUND", (0, 1), (-1, -1), colors.HexColor("#f8fafc")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("FONTSIZE", (0, 0), (-1, -1), 9.2),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))
    return table


def generate_professional_report(df):
    report = []
    report.append("ENTERPRISE GRC RISK ASSESSMENT REPORT")
    report.append("=" * 70)
    report.append(f"Generated On: {datetime.now().strftime('%B %d, %Y at %I:%M %p')}")
    report.append("Framework Alignment: NIST CSF 2.0 | RMF | Zero Trust")
    report.append("Prepared By: Saloni Bhosale")
    report.append("=" * 70)
    report.append("")

    if df.empty:
        report.append("No risk entries are available.")
        return "\n".join(report)

    report.append("1. EXECUTIVE SUMMARY")
    report.append("-" * 70)
    report.append(f"Total Risks Assessed: {len(df)}")
    report.append(f"Average Inherent Risk Score: {round(df['Inherent Risk'].mean(), 2)} / 25")
    report.append(f"Average Residual Risk Score: {round(df['Residual Risk'].mean(), 2)} / 25")
    report.append(f"Highest Residual Risk Score: {df['Residual Risk'].max()} / 25")
    report.append(f"Open Risks: {(df['Status'] != 'Closed').sum()}")
    report.append("")

    report.append("2. SCORING METHODOLOGY")
    report.append("-" * 70)
    report.append("Inherent Risk = Likelihood x Impact")
    report.append("Residual Risk = Inherent Risk adjusted by Control Effectiveness")
    report.append("Likelihood and Impact are scored on a 1 to 5 scale.")
    report.append("Control Effectiveness represents how much existing controls reduce risk.")
    report.append("")

    for i, row in df.iterrows():
        report.append(f"3.{i + 1} RISK ASSESSMENT ENTRY")
        report.append("-" * 70)

        report.append("Business Context")
        report.append(f"Company / Unit: {row['Company / Unit']}")
        report.append(f"Industry: {row['Industry']}")
        report.append(f"Department: {row['Department']}")
        report.append(f"Risk Owner: {row['Risk Owner']}")
        report.append(f"Status: {row['Status']}")
        report.append(f"Review Date: {row['Review Date']}")
        report.append("")

        report.append("Risk Overview")
        report.append(f"Asset: {row['Asset']}")
        report.append(f"Threat: {row['Threat']}")
        report.append(f"Likelihood: {row['Likelihood']} / 5")
        report.append(f"Impact: {row['Impact']} / 5")
        report.append(f"Inherent Risk: {row['Inherent Risk']} / 25 ({row['Inherent Level']})")
        report.append(f"Control Effectiveness: {row['Control Effectiveness']}%")
        report.append(f"Residual Risk: {row['Residual Risk']} / 25 ({row['Residual Level']})")
        report.append("")

        report.append("Business Impact")
        report.append(str(row["Business Impact"]))
        report.append("")

        report.append("Recommended Solution / Controls")
        for item in str(row["Recommended Controls"]).split(" | "):
            report.append(f"- {item}")
        report.append("")

        report.append("Framework Mapping")
        report.append(f"NIST CSF Mapping: {row['NIST Mapping']}")
        report.append(f"RMF Mapping: {row['RMF Mapping']}")
        report.append("Zero Trust Guidance:")
        for item in str(row["Zero Trust Guidance"]).split(" | "):
            report.append(f"- {item}")
        report.append("")

        report.append("Treatment Plan")
        report.append(f"Recommended Treatment: {row['Final Treatment']}")
        report.append(f"Treatment Reason: {row['Treatment Reason']}")
        report.append("Next Steps:")
        for item in str(row["Next Steps"]).split(" | "):
            report.append(f"- {item}")
        report.append("")

    report.append("4. CONCLUSION")
    report.append("-" * 70)
    report.append(
        "This report provides a structured cybersecurity risk assessment using business context, "
        "risk scoring, control effectiveness, residual risk, framework alignment, and practical remediation guidance."
    )
    report.append("")
    report.append("=" * 70)
    report.append("END OF REPORT")

    return "\n".join(report)


def generate_pdf_report(df):
    file_path = "enterprise_grc_risk_report.pdf"

    doc = SimpleDocTemplate(
        file_path,
        pagesize=letter,
        rightMargin=50,
        leftMargin=50,
        topMargin=80,
        bottomMargin=60
    )

    styles = getSampleStyleSheet()
    title = ParagraphStyle("Title", parent=styles["Title"], fontName="Helvetica-Bold", fontSize=24, textColor=colors.HexColor("#0B3D91"), alignment=TA_CENTER)
    subtitle = ParagraphStyle("Subtitle", parent=styles["Normal"], fontSize=11, textColor=colors.grey, alignment=TA_CENTER)
    heading = ParagraphStyle("Heading", parent=styles["Heading2"], fontName="Helvetica-Bold", fontSize=15, textColor=colors.HexColor("#1f2937"), spaceBefore=12, spaceAfter=8)
    subheading = ParagraphStyle("SubHeading", parent=styles["Heading3"], fontName="Helvetica-Bold", fontSize=12, textColor=colors.HexColor("#2563eb"), spaceBefore=8, spaceAfter=5)
    body = ParagraphStyle("Body", parent=styles["Normal"], fontSize=10.2, leading=14)

    content = [
        Paragraph("Enterprise GRC Risk Assessment Report", title),
        Spacer(1, 8),
        Paragraph("Cybersecurity Risk Intelligence Platform", subtitle),
        Paragraph("Aligned with NIST CSF • RMF • Zero Trust", subtitle),
        Spacer(1, 12),
        Paragraph(f"Generated On: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", subtitle),
        Paragraph("Prepared By: Saloni Bhosale", subtitle),
        Spacer(1, 20),
    ]

    formulas = get_formula_text()
    content.append(Paragraph("Scoring Methodology", heading))
    for item in formulas.values():
        content.append(Paragraph(f"• {item}", body))
    content.append(Spacer(1, 12))

    if df.empty:
        content.append(Paragraph("No risk entries available.", body))
        doc.build(content, onFirstPage=add_page_header_footer, onLaterPages=add_page_header_footer)
        return file_path

    content.append(Paragraph("Executive Summary", heading))
    summary = [
        ["Metric", "Value"],
        ["Total Risks", str(len(df))],
        ["Average Inherent Risk", str(round(df["Inherent Risk"].mean(), 2))],
        ["Average Residual Risk", str(round(df["Residual Risk"].mean(), 2))],
        ["Highest Residual Risk", str(df["Residual Risk"].max())],
        ["Most Recent Status", str(df.iloc[-1]["Status"])],
    ]
    content.append(pdf_table(summary, [220, 250]))
    content.append(Spacer(1, 14))

    content.append(Paragraph("Risk Assessment Details", heading))
    for i, row in df.iterrows():
        content.append(Paragraph(f"Risk Entry {i+1}: {row['Asset']} - {row['Threat']}", subheading))

        risk_data = [
            ["Field", "Value"],
            ["Company / Unit", str(row["Company / Unit"])],
            ["Industry", str(row["Industry"])],
            ["Department", str(row["Department"])],
            ["Risk Owner", str(row["Risk Owner"])],
            ["Asset", str(row["Asset"])],
            ["Threat", str(row["Threat"])],
            ["Likelihood", str(row["Likelihood"])],
            ["Impact", str(row["Impact"])],
            ["Inherent Risk", str(row["Inherent Risk"])],
            ["Control Effectiveness", f"{row['Control Effectiveness']}%"],
            ["Residual Risk", str(row["Residual Risk"])],
            ["Residual Level", str(row["Residual Level"])],
            ["Treatment", str(row["Final Treatment"])],
            ["Status", str(row["Status"])],
            ["Review Date", str(row["Review Date"])],
            ["NIST Mapping", str(row["NIST Mapping"])],
            ["RMF Mapping", str(row["RMF Mapping"])],
        ]
        content.append(pdf_table(risk_data, [180, 290]))
        content.append(Spacer(1, 8))

        content.append(Paragraph("Business Impact", subheading))
        content.append(Paragraph(str(row["Business Impact"]), body))

        content.append(Paragraph("Recommended Controls / Solution", subheading))
        for rec in str(row["Recommended Controls"]).split(" | "):
            content.append(Paragraph(f"• {rec}", body))

        content.append(Paragraph("Zero Trust Guidance", subheading))
        for zt in str(row["Zero Trust Guidance"]).split(" | "):
            content.append(Paragraph(f"• {zt}", body))

        content.append(Paragraph("Next Steps", subheading))
        for action in str(row["Next Steps"]).split(" | "):
            content.append(Paragraph(f"• {action}", body))

        content.append(Spacer(1, 14))

    content.append(Paragraph("Conclusion", heading))
    content.append(Paragraph(
        "This report provides a structured evaluation of cybersecurity risk using inherent risk, residual risk, "
        "control effectiveness, framework mapping, business impact, and recommended actions. It is designed to support "
        "security governance, risk prioritization, executive reporting, and remediation planning.",
        body
    ))

    doc.build(content, onFirstPage=add_page_header_footer, onLaterPages=add_page_header_footer)
    return file_path


def create_heatmap(likelihood, impact):
    matrix = [[i * j for i in range(1, 6)] for j in range(5, 0, -1)]
    fig, ax = plt.subplots(figsize=(5, 4))
    ax.imshow(matrix)

    for y in range(5):
        for x in range(5):
            ax.text(x, y, str(matrix[y][x]), ha="center", va="center")

    ax.scatter(likelihood - 1, 5 - impact, s=250, marker="o")
    ax.set_xticks(range(5))
    ax.set_xticklabels([1, 2, 3, 4, 5])
    ax.set_yticks(range(5))
    ax.set_yticklabels([5, 4, 3, 2, 1])
    ax.set_xlabel("Likelihood")
    ax.set_ylabel("Impact")
    ax.set_title("Risk Heatmap")
    return fig


# ---------------- SIDEBAR ----------------
with st.sidebar:
    st.markdown("## 🛡️ Enterprise Risk Platform")
    st.caption("NIST CSF • RMF • Zero Trust • Residual Risk")
    st.divider()

    st.markdown('<div class="sidebar-card">', unsafe_allow_html=True)
    st.markdown("#### 🎭 Risk Mood Meter")
    if st.session_state.history:
        avg = sum(i["Residual Risk"] for i in st.session_state.history) / len(st.session_state.history)
        lvl, emoji, _ = risk_level(avg)
        st.write(f"{emoji} Average residual risk: **{round(avg, 1)}** ({lvl})")
    else:
        st.write("😌 No risks saved yet")
    st.markdown("</div>", unsafe_allow_html=True)

    st.markdown('<div class="sidebar-card">', unsafe_allow_html=True)
    st.markdown("#### 🎲 Random Scenario")
    if st.button("Generate random risk", use_container_width=True):
        random_asset = random.choice(ASSET_OPTIONS)
        st.session_state.selected_asset = random_asset
        st.session_state.selected_threat = random.choice(ASSET_THREAT_MAP[random_asset])
        st.session_state.input_mode = "manual"
        st.rerun()
    st.markdown("</div>", unsafe_allow_html=True)

    st.markdown('<div class="sidebar-card">', unsafe_allow_html=True)
    st.markdown("#### 🧠 Tip")
    st.write(random.choice(TIPS))
    st.markdown("</div>", unsafe_allow_html=True)


# ---------------- HEADER ----------------
st.markdown("""
<div class="hero-box">
  <h1>🛡️ Enterprise GRC Risk Intelligence Platform</h1>
  <p>Translate business risk into measurable cybersecurity risk. Assess inherent risk, residual risk, business impact,
  treatment strategy, framework alignment, and executive-ready reporting.</p>
</div>
""", unsafe_allow_html=True)


main_tab, dashboard_tab = st.tabs(["📋 Risk Assessment", "📊 Risk Register & Dashboard"])


# ---------------- RISK ASSESSMENT ----------------
with main_tab:
    col_mode1, col_mode2 = st.columns(2)
    with col_mode1:
        if st.button("✨ Smart Mode — describe the risk" + (" ✓" if st.session_state.input_mode == "smart" else ""), use_container_width=True):
            st.session_state.input_mode = "smart"
            st.rerun()
    with col_mode2:
        if st.button("⚙️ Analyst Mode — use dropdowns" + (" ✓" if st.session_state.input_mode == "manual" else ""), use_container_width=True):
            st.session_state.input_mode = "manual"
            st.rerun()

    st.markdown("---")

    st.subheader("🏢 Enterprise Context")
    c1, c2, c3 = st.columns(3)
    with c1:
        company = st.text_input("Company / Business Unit", value="Demo Organization")
        industry = st.selectbox("Industry", ["General", "Education", "Healthcare", "Finance", "Retail", "Manufacturing", "Technology"])
    with c2:
        department = st.text_input("Department", value="Information Technology")
        owner = st.text_input("Risk Owner", value="Security / IT Team")
    with c3:
        status = st.selectbox("Risk Status", ["Open", "In Progress", "Accepted", "Transferred", "Closed"])
        review_date = st.date_input("Review Date", value=date.today())

    st.markdown("### 🎛️ Control Effectiveness")
    control_effectiveness = st.slider(
        "How effective are current controls?",
        min_value=0,
        max_value=90,
        value=30,
        step=5,
        help="Higher control effectiveness reduces residual risk. Example: MFA, backups, monitoring, segmentation."
    )

    st.markdown("---")

    if st.session_state.input_mode == "smart":
        st.subheader("💬 Describe the Risk")
        st.caption("Use plain English. Example: 'A vendor that stores our HR data had a breach.'")

        ex_cols = st.columns(3)
        for idx, example in enumerate(EXAMPLE_PROMPTS):
            with ex_cols[idx % 3]:
                if st.button(f"📌 {example[:42]}…", key=f"ex_{idx}", use_container_width=True):
                    st.session_state.smart_description = example
                    st.rerun()

        description = st.text_area(
            "Risk Description",
            value=st.session_state.smart_description,
            height=120,
            placeholder="Describe the risk, issue, incident, or concern..."
        )
        st.session_state.smart_description = description

        ready = len(description.strip()) > 10
        if st.button("🚀 Analyze Risk", type="primary", disabled=not ready):
            parsed = ai_analyze_description(description)
            fallback_asset, fallback_threat = fallback_detect_from_description(description)

            if parsed is None:
                asset, threat = fallback_asset, fallback_threat
                likelihood, impact, reasons = calculate_auto_scores(asset, threat, [])
                plain_summary = f"This appears to be a {threat.lower()} risk involving the {asset.lower()}."
                actions = [
                    {"tag": "Do now", "text": "Contain the issue and limit further exposure."},
                    {"tag": "This week", "text": "Review relevant controls and determine root cause."},
                    {"tag": "Document", "text": "Record the risk and track remediation actions."},
                ]
                confidence = "medium"
            else:
                asset = parsed.get("asset", fallback_asset)
                threat = parsed.get("threat", fallback_threat)
                if asset not in ASSET_OPTIONS:
                    asset = fallback_asset
                if threat not in THREAT_OPTIONS:
                    threat = fallback_threat
                if threat not in ASSET_THREAT_MAP.get(asset, []):
                    threat = ASSET_THREAT_MAP[asset][0]

                likelihood = max(1, min(5, int(parsed.get("likelihood", 3))))
                impact = max(1, min(5, int(parsed.get("impact", 3))))
                reasons = ["Smart Mode used the description to estimate likelihood and impact."]
                plain_summary = parsed.get("plain_english_summary", "")
                actions = parsed.get("actions", [])
                confidence = parsed.get("confidence", "medium")

            inherent, residual = calculate_risks(likelihood, impact, control_effectiveness)
            inherent_level, inherent_emoji, inherent_color = risk_level(inherent)
            residual_level, residual_emoji, residual_color = risk_level(residual)
            treatment, treatment_reason = suggest_treatment(threat, residual)

            impact_text = business_impact(threat, asset, industry)
            controls = get_recommendations(threat)
            zt = get_zero_trust_guidance(threat)
            next_steps = get_treatment_actions(treatment, residual)

            st.session_state.last_result = {
                "Company / Unit": company,
                "Industry": industry,
                "Department": department,
                "Risk Owner": owner,
                "Status": status,
                "Review Date": str(review_date),
                "Asset": asset,
                "Threat": threat,
                "Likelihood": likelihood,
                "Impact": impact,
                "Inherent Risk": inherent,
                "Inherent Level": inherent_level,
                "Residual Risk": residual,
                "Residual Level": residual_level,
                "Residual Emoji": residual_emoji,
                "Residual Color": residual_color,
                "Control Effectiveness": control_effectiveness,
                "Final Treatment": treatment,
                "Suggested Treatment": treatment,
                "Treatment Reason": treatment_reason,
                "Business Impact": impact_text,
                "Plain English Summary": plain_summary,
                "AI Actions": actions,
                "NIST Mapping": get_nist_mapping(threat),
                "RMF Mapping": get_rmf_mapping(threat),
                "Zero Trust Guidance": " | ".join(zt),
                "Recommended Controls": " | ".join(controls),
                "Next Steps": " | ".join(next_steps),
                "Confidence": confidence,
                "Scoring Notes": " | ".join(reasons),
            }

    else:
        st.subheader("🧾 Analyst Inputs")

        asset = st.selectbox(
            "Asset",
            ASSET_OPTIONS,
            index=ASSET_OPTIONS.index(st.session_state.selected_asset)
        )
        st.session_state.selected_asset = asset

        relevant_threats = ASSET_THREAT_MAP[asset]
        if st.session_state.selected_threat not in relevant_threats:
            st.session_state.selected_threat = relevant_threats[0]

        threat = st.selectbox(
            "Threat",
            relevant_threats,
            index=relevant_threats.index(st.session_state.selected_threat)
        )
        st.session_state.selected_threat = threat

        likelihood, impact, reasons = calculate_auto_scores(asset, threat, [])
        m1, m2 = st.columns(2)
        with m1:
            st.metric("Auto Likelihood", likelihood)
        with m2:
            st.metric("Auto Impact", impact)

        with st.expander("How scoring was calculated"):
            for r in reasons:
                st.write(f"- {r}")

        if st.button("🚀 Analyze Risk", type="primary"):
            inherent, residual = calculate_risks(likelihood, impact, control_effectiveness)
            inherent_level, inherent_emoji, inherent_color = risk_level(inherent)
            residual_level, residual_emoji, residual_color = risk_level(residual)
            treatment, treatment_reason = suggest_treatment(threat, residual)

            impact_text = business_impact(threat, asset, industry)
            controls = get_recommendations(threat)
            zt = get_zero_trust_guidance(threat)
            next_steps = get_treatment_actions(treatment, residual)

            st.session_state.last_result = {
                "Company / Unit": company,
                "Industry": industry,
                "Department": department,
                "Risk Owner": owner,
                "Status": status,
                "Review Date": str(review_date),
                "Asset": asset,
                "Threat": threat,
                "Likelihood": likelihood,
                "Impact": impact,
                "Inherent Risk": inherent,
                "Inherent Level": inherent_level,
                "Residual Risk": residual,
                "Residual Level": residual_level,
                "Residual Emoji": residual_emoji,
                "Residual Color": residual_color,
                "Control Effectiveness": control_effectiveness,
                "Final Treatment": treatment,
                "Suggested Treatment": treatment,
                "Treatment Reason": treatment_reason,
                "Business Impact": impact_text,
                "Plain English Summary": "",
                "AI Actions": [],
                "NIST Mapping": get_nist_mapping(threat),
                "RMF Mapping": get_rmf_mapping(threat),
                "Zero Trust Guidance": " | ".join(zt),
                "Recommended Controls": " | ".join(controls),
                "Next Steps": " | ".join(next_steps),
                "Confidence": "high",
                "Scoring Notes": " | ".join(reasons),
            }

    result = st.session_state.last_result

    if result:
        st.markdown("---")
        st.header("📊 Risk Results")

        card_class = result["Residual Level"].lower()
        if result["Residual Level"] == "CRITICAL":
            card_class = "critical"

        r1, r2, r3, r4 = st.columns(4)
        with r1:
            st.markdown(f"""<div class="card {card_class}">
            <h4>Inherent Risk</h4><h2>{result['Inherent Risk']}/25</h2></div>""", unsafe_allow_html=True)
        with r2:
            st.markdown(f"""<div class="card {card_class}">
            <h4>Residual Risk</h4><h2>{result['Residual Risk']}/25</h2></div>""", unsafe_allow_html=True)
        with r3:
            st.markdown(f"""<div class="card {card_class}">
            <h4>Residual Level</h4><h2>{result['Residual Emoji']} {result['Residual Level']}</h2></div>""", unsafe_allow_html=True)
        with r4:
            st.markdown(f"""<div class="card">
            <h4>Treatment</h4><h2 style="font-size:1.35rem!important;">{result['Final Treatment']}</h2></div>""", unsafe_allow_html=True)

        if result["Residual Level"] in ["CRITICAL", "HIGH"]:
            st.error("This risk needs management attention and a clear remediation plan.")
        elif result["Residual Level"] == "MEDIUM":
            st.warning("This risk should be tracked and reduced through planned controls.")
        else:
            st.success("This risk appears manageable, but it should still be monitored.")

        if result.get("Plain English Summary"):
            st.markdown(f"""
            <div class="plain-english-box">
            <strong>Plain-English Summary:</strong><br>{result["Plain English Summary"]}
            </div>
            """, unsafe_allow_html=True)

        st.subheader("💼 Business Impact")
        st.write(result["Business Impact"])

        st.subheader("✅ Recommended Solution")
        for rec in result["Recommended Controls"].split(" | "):
            st.write(f"- {rec}")

        st.subheader("🧭 Risk Heatmap")
        st.pyplot(create_heatmap(result["Likelihood"], result["Impact"]))

        with st.expander("🧠 Framework Mapping"):
            st.write(f"**NIST CSF:** {result['NIST Mapping']}")
            st.write(f"**RMF:** {result['RMF Mapping']}")
            st.write("**Zero Trust Guidance:**")
            for item in result["Zero Trust Guidance"].split(" | "):
                st.write(f"- {item}")

        with st.expander("📌 Treatment Plan"):
            st.info(f"Suggested treatment: **{result['Final Treatment']}** — {result['Treatment Reason']}")
            for action in result["Next Steps"].split(" | "):
                st.write(f"- {action}")

        with st.expander("🧮 Scoring Methodology"):
            formulas = get_formula_text()
            for formula in formulas.values():
                st.write(f"- {formula}")
            st.write(f"Control Effectiveness Applied: **{result['Control Effectiveness']}%**")
            st.write(f"Inherent Risk: **{result['Inherent Risk']}**")
            st.write(f"Residual Risk: **{result['Residual Risk']}**")

        st.subheader("🛡️ Final Risk Treatment Decision")
        treatment_options = ["Mitigate", "Accept", "Transfer", "Avoid"]
        selected_treatment = st.selectbox(
            "Override treatment if needed",
            treatment_options,
            index=treatment_options.index(result["Final Treatment"])
        )
        result["Final Treatment"] = selected_treatment

        if st.button("💾 Save to Risk Register", type="primary"):
            st.session_state.history.append(result.copy())
            st.success("Saved to risk register.")
            st.balloons()

        st.markdown("---")
        st.subheader("📖 Glossary")
        for term, definition in GLOSSARY.items():
            with st.expander(term):
                st.write(definition)


# ---------------- DASHBOARD ----------------
with dashboard_tab:
    st.header("📊 Risk Register & Dashboard")

    if not st.session_state.history:
        st.info("No risks saved yet. Save at least one risk assessment to populate the dashboard.")
    else:
        df = pd.DataFrame(st.session_state.history)

        k1, k2, k3, k4 = st.columns(4)
        with k1:
            st.metric("Total Risks", len(df))
        with k2:
            st.metric("Avg Residual Risk", round(df["Residual Risk"].mean(), 1))
        with k3:
            st.metric("Highest Residual Risk", int(df["Residual Risk"].max()))
        with k4:
            st.metric("Open Risks", int((df["Status"] != "Closed").sum()))

        st.subheader("Risk Register")
        st.dataframe(df, use_container_width=True)

        st.subheader("Visual Dashboard")
        c1, c2 = st.columns(2)
        with c1:
            st.write("Residual Risk by Level")
            st.bar_chart(df["Residual Level"].value_counts())
        with c2:
            st.write("Risk Treatment Distribution")
            st.bar_chart(df["Final Treatment"].value_counts())

        st.write("Residual Risk Trend")
        st.bar_chart(df["Residual Risk"])

        clean_csv_columns = [
            "Company / Unit",
            "Industry",
            "Department",
            "Risk Owner",
            "Status",
            "Review Date",
            "Asset",
            "Threat",
            "Likelihood",
            "Impact",
            "Inherent Risk",
            "Inherent Level",
            "Control Effectiveness",
            "Residual Risk",
            "Residual Level",
            "Final Treatment",
            "Business Impact",
            "NIST Mapping",
            "RMF Mapping",
            "Recommended Controls",
            "Next Steps"
        ]

        clean_df = df[clean_csv_columns]
        csv_data = clean_df.to_csv(index=False)

        d1, d2, d3 = st.columns(3)

        with d1:
            st.caption("Clean CSV structured for Excel, Power BI, and enterprise risk register review.")
            st.download_button(
                "📥 Download Clean Risk Register CSV",
                csv_data,
                "enterprise_risk_register.csv",
                "text/csv"
            )

        with d2:
            txt = generate_professional_report(df)
            st.download_button(
                "📄 Download Professional Text Report",
                txt,
                "enterprise_grc_report.txt",
                "text/plain"
            )

        with d3:
            pdf = generate_pdf_report(df)
            with open(pdf, "rb") as f:
                st.download_button(
                    "🧾 Download Professional PDF",
                    f,
                    "enterprise_grc_risk_report.pdf",
                    "application/pdf"
                )

        if st.button("🗑️ Clear Risk Register"):
            st.session_state.history = []
            st.rerun()


# ---------------- FOOTER ----------------
st.markdown("---")
st.markdown(f"""
<div style="text-align:center; font-size:13px; color:#64748b; padding-bottom:1rem;">
Built by <b>Saloni Bhosale</b> | Enterprise GRC & Cybersecurity Risk<br>
Aligned with NIST CSF 2.0, RMF, Zero Trust, Inherent Risk, Residual Risk, and Control Effectiveness<br>
Last updated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
</div>
""", unsafe_allow_html=True)
