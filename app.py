import random
from datetime import datetime

import matplotlib.pyplot as plt
import pandas as pd
import streamlit as st
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

# ---------------- PAGE SETUP ----------------
st.set_page_config(
    page_title="AI-Enhanced GRC Risk Intelligence Platform",
    page_icon="🛡️",
    layout="wide"
)

# ---------------- STYLE ----------------
st.markdown("""
<style>
.block-container {
    padding-top: 1rem;
    padding-bottom: 2rem;
}
.card {
    background: #161b22;
    padding: 20px;
    border-radius: 16px;
    border: 1px solid #30363d;
    text-align: center;
    margin-bottom: 10px;
}
.card h2 {
    color: #58a6ff !important;
}
.card h4 {
    color: #8b949e !important;
}
.section-box {
    background: #161b22;
    padding: 18px;
    border-radius: 14px;
    border: 1px solid #30363d;
    margin-bottom: 16px;
}
.sidebar-card {
    background: #0d1117;
    padding: 12px;
    border-radius: 12px;
    border: 1px solid #30363d;
    margin-bottom: 12px;
}
</style>
""", unsafe_allow_html=True)

# ---------------- SESSION STATE ----------------
if "history" not in st.session_state:
    st.session_state.history = []

if "last_result" not in st.session_state:
    st.session_state.last_result = None

if "selected_asset" not in st.session_state:
    st.session_state.selected_asset = "Database"

if "selected_threat" not in st.session_state:
    st.session_state.selected_threat = "Data Breach"

# ---------------- DATA ----------------
ASSET_OPTIONS = [
    "Database",
    "Application",
    "Cloud Environment",
    "Network",
    "Endpoint / Laptop",
    "Email System",
    "User Credentials",
    "Server",
    "API",
    "Backup System",
    "Identity / IAM",
    "SaaS Platform",
    "Mobile Device",
    "Vendor / Third Party",
    "HVAC / Building Management System",
    "IoT Device",
    "OT / Industrial System",
    "Building Access Control",
    "Security Camera / CCTV",
    "Finance System",
    "HR System",
    "Customer Portal"
]

THREAT_OPTIONS = [
    "Data Breach",
    "Unauthorized Access",
    "Malware",
    "Phishing",
    "Misconfiguration",
    "Insider Threat",
    "Ransomware",
    "Supply Chain Attack",
    "Zero-Day Exploit",
    "Denial of Service (DDoS)",
    "Credential Attack",
    "Data Loss",
    "Privilege Escalation",
    "API Abuse"
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

TIPS = [
    "Strong logging makes Detect and Respond much stronger.",
    "Low-risk items still need owners and review dates.",
    "Backup quality matters most before ransomware happens.",
    "Misconfigurations often create silent, high-impact exposure.",
    "Credential attacks are often stopped by MFA and monitoring."
]

FUN_FACTS = [
    "A medium risk ignored for too long can become a high risk.",
    "Good GRC work is often about prioritization, not panic.",
    "Not every risk should be mitigated — some are accepted or transferred.",
    "A good risk register helps teams act, not just document."
]

# ---------------- HELPERS ----------------
def get_nist_mapping(selected_threat: str) -> str:
    mapping = {
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
        "API Abuse": "Protect, Detect, Respond"
    }
    return mapping.get(selected_threat, "Identify, Protect")

def get_recommendations(selected_threat: str) -> list[str]:
    recommendations = {
        "Data Breach": [
            "Encrypt sensitive data at rest and in transit",
            "Apply strong access controls and least privilege",
            "Enable continuous logging and monitoring"
        ],
        "Unauthorized Access": [
            "Enable Multi-Factor Authentication (MFA)",
            "Monitor login activity and access anomalies",
            "Apply role-based access control"
        ],
        "Malware": [
            "Use endpoint protection and anti-malware tools",
            "Update systems regularly",
            "Run regular malware scans"
        ],
        "Phishing": [
            "Train users to identify phishing attempts",
            "Use email filtering and anti-phishing controls",
            "Report suspicious emails quickly"
        ],
        "Misconfiguration": [
            "Review settings and defaults regularly",
            "Use secure baselines and hardening standards",
            "Automate configuration compliance checks"
        ],
        "Insider Threat": [
            "Review access rights regularly",
            "Monitor unusual employee activity",
            "Improve reporting and awareness mechanisms"
        ],
        "Ransomware": [
            "Maintain secure and tested backups",
            "Patch vulnerable systems quickly",
            "Test incident response and recovery plans"
        ],
        "Supply Chain Attack": [
            "Assess vendor security posture regularly",
            "Restrict third-party access",
            "Monitor software and vendor dependencies"
        ],
        "Zero-Day Exploit": [
            "Use layered defenses and anomaly detection",
            "Patch quickly when fixes become available",
            "Segment critical systems to reduce blast radius"
        ],
        "Denial of Service (DDoS)": [
            "Use rate limiting and traffic filtering",
            "Deploy DDoS protection services",
            "Scale infrastructure and failover capacity"
        ],
        "Credential Attack": [
            "Enable MFA across critical systems",
            "Monitor brute-force and suspicious login attempts",
            "Use password hygiene and lockout controls"
        ],
        "Data Loss": [
            "Maintain versioned backups",
            "Restrict destructive actions",
            "Test restore procedures regularly"
        ],
        "Privilege Escalation": [
            "Limit admin rights and privileged access",
            "Monitor privilege changes",
            "Use privileged access management controls"
        ],
        "API Abuse": [
            "Use rate limits and authentication controls",
            "Monitor API calls and unusual patterns",
            "Review exposed endpoints and tokens"
        ]
    }
    return recommendations.get(selected_threat, ["Review controls", "Monitor risk", "Apply best practices"])

def suggest_treatment(selected_threat: str, score: int):
    if score >= 15:
        if selected_threat in [
            "Data Breach", "Unauthorized Access", "Malware", "Ransomware",
            "Zero-Day Exploit", "Privilege Escalation", "API Abuse"
        ]:
            return "Mitigate", "This is a high-priority risk and should usually be reduced quickly through stronger controls."
        if selected_threat in ["Denial of Service (DDoS)", "Supply Chain Attack"]:
            return "Transfer", "This high risk may benefit from shared responsibility, vendor controls, insurance, or contractual transfer."
        return "Avoid", "This is a high-risk scenario, so avoiding or redesigning the activity may be the safest path."

    if score >= 8:
        if selected_threat in ["Data Loss", "Misconfiguration", "Phishing", "Credential Attack"]:
            return "Mitigate", "This medium-risk scenario is usually best handled by reducing likelihood or impact."
        return "Transfer", "This medium-risk scenario may be suitable for transfer through insurance, outsourcing, or contracts."

    return "Accept", "This is a lower-risk scenario, so accepting and monitoring it may be reasonable."

def get_treatment_actions(option: str, score: int):
    if option == "Mitigate":
        actions = [
            "Implement technical or administrative controls",
            "Assign an owner and remediation timeline",
            "Reassess the risk after controls are applied"
        ]
        if score >= 15:
            actions.append("Escalate this as a priority remediation item.")
        return actions

    if option == "Avoid":
        actions = [
            "Stop or redesign the risky activity",
            "Evaluate safer alternatives",
            "Document the trade-offs before changing the process"
        ]
        if score >= 15:
            actions.append("Consider executive review if the asset is business-critical.")
        return actions

    if option == "Accept":
        actions = [
            "Document the acceptance decision",
            "Obtain management approval where required",
            "Review the risk periodically"
        ]
        if score >= 15:
            actions.append("High-risk acceptance should have strong business justification.")
        return actions

    actions = [
        "Use insurance, contractual transfer, or outsourcing where appropriate",
        "Verify vendor responsibilities and SLAs",
        "Monitor remaining residual risk"
    ]
    if score >= 15:
        actions.append("Ensure transfer agreements cover high-impact scenarios.")
    return actions

def risk_consequence(selected_threat: str):
    consequences = {
        "Data Breach": "Sensitive data could be exposed, leading to legal issues, trust loss, and financial penalties.",
        "Unauthorized Access": "Attackers may gain control over systems, accounts, or protected data.",
        "Malware": "Systems may be disrupted, slowed down, or corrupted.",
        "Phishing": "User credentials or internal access may be stolen.",
        "Misconfiguration": "Security gaps may quietly grow and expose systems over time.",
        "Insider Threat": "Internal misuse may bypass controls and damage trust, systems, or data.",
        "Ransomware": "Critical systems may be locked, disrupting operations and recovery.",
        "Supply Chain Attack": "A trusted vendor or dependency could introduce compromise into your environment.",
        "Zero-Day Exploit": "An unknown vulnerability may be exploited before normal defenses catch up.",
        "Denial of Service (DDoS)": "Systems may become unavailable, causing outages and possible revenue loss.",
        "Credential Attack": "Repeated login abuse may lead to account compromise and lateral movement.",
        "Data Loss": "Critical business data may be deleted, corrupted, or become unrecoverable.",
        "Privilege Escalation": "An attacker may gain more access than intended and compromise sensitive systems.",
        "API Abuse": "Public or partner-facing services may be misused, causing fraud, downtime, or data exposure."
    }
    return consequences.get(selected_threat, "Operational or security issues may increase if the risk is ignored.")

def analyze_uploaded_text(text: str):
    clean_text = text.lower()

    asset_keywords = {
        "Database": ["database", "sql", "records", "customer data", "data store"],
        "Application": ["application", "web app", "portal", "software"],
        "Cloud Environment": ["cloud", "aws", "azure", "gcp", "bucket", "s3"],
        "Network": ["network", "router", "switch", "firewall", "vpn"],
        "Endpoint / Laptop": ["laptop", "desktop", "endpoint", "workstation"],
        "Email System": ["email", "mailbox", "outlook", "smtp", "inbox"],
        "User Credentials": ["password", "credentials", "login", "account", "mfa"],
        "Server": ["server", "host", "linux server", "windows server"],
        "API": ["api", "endpoint", "token", "integration", "rest"],
        "Backup System": ["backup", "restore", "recovery copy"],
        "Identity / IAM": ["iam", "identity", "sso", "privilege", "role"],
        "SaaS Platform": ["saas", "workspace", "salesforce", "service now"],
        "Mobile Device": ["mobile", "phone", "tablet", "android", "iphone"],
        "Vendor / Third Party": ["vendor", "third party", "supplier", "outsourced"],
        "HVAC / Building Management System": ["hvac", "bms", "thermostat", "building management"],
        "IoT Device": ["iot", "sensor", "camera", "smart device", "connected device"],
        "OT / Industrial System": ["ot", "ics", "industrial", "scada", "plc"],
        "Building Access Control": ["badge", "door access", "building access", "entry system"],
        "Security Camera / CCTV": ["camera", "cctv", "video surveillance"],
        "Finance System": ["finance", "payroll", "billing", "invoice"],
        "HR System": ["hr", "employee records", "personnel", "recruitment"],
        "Customer Portal": ["customer portal", "client login", "self-service portal"]
    }

    threat_keywords = {
        "Data Breach": ["data breach", "data leak", "exposed data", "pii", "phi"],
        "Unauthorized Access": ["unauthorized access", "intrusion", "illegal access", "unapproved access"],
        "Malware": ["malware", "virus", "trojan", "infected"],
        "Phishing": ["phishing", "fake email", "spoofed", "credential theft"],
        "Misconfiguration": ["misconfiguration", "open port", "public bucket", "default settings"],
        "Insider Threat": ["insider", "internal misuse", "employee misuse"],
        "Ransomware": ["ransomware", "encrypted files", "locked system"],
        "Supply Chain Attack": ["vendor compromise", "third party compromise", "dependency attack", "supply chain"],
        "Zero-Day Exploit": ["zero-day", "unknown vulnerability", "unpatched exploit"],
        "Denial of Service (DDoS)": ["ddos", "traffic flood", "service unavailable", "overload"],
        "Credential Attack": ["brute force", "credential stuffing", "repeated login attempts"],
        "Data Loss": ["data loss", "accidental deletion", "lost files", "missing backup"],
        "Privilege Escalation": ["privilege escalation", "admin rights", "elevated access"],
        "API Abuse": ["api abuse", "endpoint misuse", "token misuse", "rate limit"]
    }

    matched_assets = {}
    matched_threats = {}
    matched_words = []

    for asset_name, words in asset_keywords.items():
        score = 0
        for word in words:
            if word in clean_text:
                score += 1
                matched_words.append(word)
        if score > 0:
            matched_assets[asset_name] = score

    for threat_name, words in threat_keywords.items():
        score = 0
        for word in words:
            if word in clean_text:
                score += 1
                matched_words.append(word)
        if score > 0:
            matched_threats[threat_name] = score

    suggested_asset = max(matched_assets, key=matched_assets.get) if matched_assets else None
    suggested_threat = max(matched_threats, key=matched_threats.get) if matched_threats else None

    total_matches = len(set(matched_words))
    if total_matches >= 6:
        suggested_likelihood, suggested_impact = 4, 4
    elif total_matches >= 3:
        suggested_likelihood, suggested_impact = 3, 3
    elif total_matches >= 1:
        suggested_likelihood, suggested_impact = 2, 2
    else:
        suggested_likelihood, suggested_impact = None, None

    return suggested_asset, suggested_threat, suggested_likelihood, suggested_impact, sorted(set(matched_words))

def generate_professional_report(df: pd.DataFrame) -> str:
    report = []
    report.append("AI-Enhanced GRC Risk Assessment Report")
    report.append("=" * 65)
    report.append(f"Generated On: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    report.append("Framework Reference: NIST CSF 2.0 informed educational prototype")
    report.append("Prepared By: Saloni Bhosale")
    report.append("")

    if df.empty:
        report.append("No risk entries available.")
        return "\n".join(report)

    report.append("Executive Summary")
    report.append("-" * 65)
    report.append(f"Total Analyses Conducted: {len(df)}")
    report.append(f"Average Risk Score: {round(df['Risk Score'].mean(), 2)}")
    report.append(f"Selected Risk Treatment (Most Recent): {df.iloc[-1]['Final Treatment']}")
    report.append("")

    for i, row in df.iterrows():
        report.append(f"Risk Entry {i + 1}")
        report.append("-" * 65)
        report.append(f"Asset: {row['Asset']}")
        report.append(f"Threat: {row['Threat']}")
        report.append(f"Likelihood: {row['Likelihood']}")
        report.append(f"Impact: {row['Impact']}")
        report.append(f"Risk Score: {row['Risk Score']}")
        report.append(f"Risk Level: {row['Risk Level']}")
        report.append(f"Suggested Treatment: {row['Suggested Treatment']}")
        report.append(f"Final Treatment: {row['Final Treatment']}")
        report.append(f"NIST Mapping: {get_nist_mapping(row['Threat'])}")

        if row["Risk Score"] >= 15:
            interpretation = "This represents a high-priority risk requiring prompt remediation and management attention."
        elif row["Risk Score"] >= 8:
            interpretation = "This represents a moderate risk that should be addressed within a planned remediation cycle."
        else:
            interpretation = "This represents a lower risk that may be accepted or monitored with periodic review."

        report.append(f"Interpretation: {interpretation}")
        report.append(f"Business Impact Summary: {risk_consequence(row['Threat'])}")

        report.append("Recommended Control Actions:")
        for recommendation in get_recommendations(row["Threat"]):
            report.append(f"- {recommendation}")

        report.append("Treatment Follow-up Actions:")
        for action in get_treatment_actions(row["Final Treatment"], int(row["Risk Score"])):
            report.append(f"- {action}")

        report.append("")

    report.append("Report Notes")
    report.append("-" * 65)
    report.append("This report is generated from user-provided scoring inputs and simplified educational risk logic.")
    report.append("The output is intended to support learning, demonstration, and early-stage portfolio review.")
    report.append("")
    report.append("Conclusion")
    report.append("-" * 65)
    report.append("This assessment highlights how selected threats can be prioritized, interpreted, and paired with control and treatment decisions using a structured GRC workflow.")
    report.append("")
    report.append("=" * 65)
    report.append("End of Report")
    return "\n".join(report)

def add_page_header_footer(canvas, doc):
    canvas.saveState()
    canvas.setFont("Helvetica-Bold", 10)
    canvas.setFillColor(colors.HexColor("#1f3b73"))
    canvas.drawString(50, 760, "AI-Enhanced GRC Risk Assessment Report")
    canvas.setStrokeColor(colors.HexColor("#d0d7de"))
    canvas.setLineWidth(0.5)
    canvas.line(50, 755, 560, 755)
    canvas.setFont("Helvetica", 9)
    canvas.setFillColor(colors.HexColor("#6b7280"))
    canvas.drawString(50, 30, "Prepared by Saloni Bhosale | GRC & Cybersecurity Risk")
    canvas.drawRightString(560, 30, f"Page {doc.page}")
    canvas.restoreState()

def make_pdf_table(table_data, col_widths):
    table = Table(table_data, colWidths=col_widths, hAlign="LEFT")
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1f3b73")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 9.5),
        ("LEADING", (0, 0), (-1, -1), 12),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
        ("BACKGROUND", (0, 1), (-1, -1), colors.HexColor("#f8fafc")),
        ("TEXTCOLOR", (0, 1), (-1, -1), colors.HexColor("#111827")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))
    return table

def generate_pdf_report(df: pd.DataFrame) -> str:
    file_path = "grc_risk_report.pdf"

    doc = SimpleDocTemplate(
        file_path,
        pagesize=letter,
        rightMargin=50,
        leftMargin=50,
        topMargin=70,
        bottomMargin=50
    )

    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        "CustomTitle",
        parent=styles["Title"],
        fontName="Helvetica-Bold",
        fontSize=22,
        leading=28,
        textColor=colors.HexColor("#1f3b73"),
        alignment=TA_CENTER,
        spaceAfter=20
    )

    subtitle_style = ParagraphStyle(
        "CustomSubtitle",
        parent=styles["BodyText"],
        fontName="Helvetica",
        fontSize=11,
        leading=14,
        textColor=colors.HexColor("#4b5563"),
        alignment=TA_CENTER,
        spaceAfter=8
    )

    heading_style = ParagraphStyle(
        "CustomHeading",
        parent=styles["Heading2"],
        fontName="Helvetica-Bold",
        fontSize=15,
        leading=18,
        textColor=colors.HexColor("#0f172a"),
        spaceBefore=10,
        spaceAfter=8
    )

    subheading_style = ParagraphStyle(
        "CustomSubHeading",
        parent=styles["Heading3"],
        fontName="Helvetica-Bold",
        fontSize=12,
        leading=14,
        textColor=colors.HexColor("#1d4ed8"),
        spaceBefore=8,
        spaceAfter=6
    )

    normal_style = ParagraphStyle(
        "CustomBody",
        parent=styles["BodyText"],
        fontName="Helvetica",
        fontSize=10.5,
        leading=14,
        textColor=colors.HexColor("#111827"),
        spaceAfter=4
    )

    note_style = ParagraphStyle(
        "CustomNote",
        parent=styles["BodyText"],
        fontName="Helvetica-Oblique",
        fontSize=9.5,
        leading=13,
        textColor=colors.HexColor("#6b7280"),
        spaceAfter=6
    )

    content = []

    content.append(Spacer(1, 43))
    content.append(Paragraph("AI-Enhanced GRC Risk Assessment Report", title_style))
    content.append(Paragraph("NIST CSF 2.0 informed educational prototype", subtitle_style))
    content.append(Spacer(1, 14))
    content.append(Paragraph(f"Generated On: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", subtitle_style))
    content.append(Paragraph("Prepared By: Saloni Bhosale", subtitle_style))
    content.append(Spacer(1, 25))
    content.append(Paragraph(
        "This report summarizes selected cyber risk scenarios, their scores, business impact, recommended control actions, and proposed treatment paths.",
        normal_style
    ))
    content.append(Spacer(1, 25))

    content.append(Paragraph("Contents", heading_style))
    content.append(Paragraph("1. Executive Summary", normal_style))
    content.append(Paragraph("2. Risk Assessment Entries", normal_style))
    content.append(Paragraph("3. Report Notes", normal_style))
    content.append(Paragraph("4. Conclusion", normal_style))
    content.append(Spacer(1, 18))

    if df.empty:
        content.append(Paragraph("No risk entries available.", normal_style))
        doc.build(content, onFirstPage=add_page_header_footer, onLaterPages=add_page_header_footer)
        return file_path

    content.append(Paragraph("1. Executive Summary", heading_style))
    summary_table_data = [
        ["Metric", "Value"],
        ["Total Analyses Conducted", str(len(df))],
        ["Average Risk Score", str(round(df["Risk Score"].mean(), 2))],
        ["Selected Risk Treatment (Most Recent)", str(df.iloc[-1]["Final Treatment"])],
        ["Highest Risk Level Observed", str(df["Risk Level"].mode()[0])]
    ]
    content.append(make_pdf_table(summary_table_data, [220, 250]))
    content.append(Spacer(1, 13))

    content.append(Paragraph("2. Risk Assessment Entries", heading_style))
    for i, row in df.iterrows():
        content.append(Paragraph(f"Risk Entry {i + 1}", subheading_style))
        risk_table_data = [
            ["Field", "Value"],
            ["Asset", str(row["Asset"])],
            ["Threat", str(row["Threat"])],
            ["Likelihood", str(row["Likelihood"])],
            ["Impact", str(row["Impact"])],
            ["Risk Score", str(row["Risk Score"])],
            ["Risk Level", str(row["Risk Level"])],
            ["Suggested Treatment", str(row["Suggested Treatment"])],
            ["Final Treatment", str(row["Final Treatment"])],
            ["NIST Mapping", str(get_nist_mapping(row["Threat"]))]
        ]
        content.append(make_pdf_table(risk_table_data, [180, 290]))
        content.append(Spacer(1, 9))

        if row["Risk Score"] >= 15:
            interpretation = "This represents a high-priority risk requiring prompt remediation and management attention."
        elif row["Risk Score"] >= 8:
            interpretation = "This represents a moderate risk that should be addressed within a planned remediation cycle."
        else:
            interpretation = "This represents a lower risk that may be accepted or monitored with periodic review."

        content.append(Paragraph("Interpretation", subheading_style))
        content.append(Paragraph(interpretation, normal_style))
        content.append(Paragraph("Business Impact Summary", subheading_style))
        content.append(Paragraph(risk_consequence(row["Threat"]), normal_style))
        content.append(Paragraph("Recommended Control Actions", subheading_style))
        for recommendation in get_recommendations(row["Threat"]):
            content.append(Paragraph(f"• {recommendation}", normal_style))
        content.append(Paragraph("Treatment Follow-up Actions", subheading_style))
        for action in get_treatment_actions(row["Final Treatment"], int(row["Risk Score"])):
            content.append(Paragraph(f"• {action}", normal_style))
        content.append(Spacer(1, 13))

    content.append(Paragraph("3. Report Notes", heading_style))
    content.append(Paragraph(
        "This report is generated from user-provided scoring inputs and simplified educational risk logic.",
        normal_style
    ))
    content.append(Paragraph(
        "It is intended to support learning, demonstration, and early-stage portfolio review rather than replace formal enterprise risk assessments.",
        note_style
    ))
    content.append(Spacer(1, 11))

    content.append(Paragraph("4. Conclusion", heading_style))
    content.append(Paragraph(
        "This assessment demonstrates how selected threats can be prioritized, interpreted, and paired with control and treatment decisions using a structured GRC workflow.",
        normal_style
    ))

    doc.build(content, onFirstPage=add_page_header_footer, onLaterPages=add_page_header_footer)
    return file_path

# ---------------- SIDEBAR ----------------
st.sidebar.title("🧭 GRC Analyst Console")
st.sidebar.write("Use this workspace to review cyber risk scenarios, treatment suggestions, and supporting clues.")

st.sidebar.markdown('<div class="sidebar-card">', unsafe_allow_html=True)
st.sidebar.markdown("### 🎲 Try Random Scenario")
if st.sidebar.button("Generate Random Risk"):
    random_asset = random.choice(ASSET_OPTIONS)
    st.session_state.selected_asset = random_asset
    st.session_state.selected_threat = random.choice(ASSET_THREAT_MAP[random_asset])
    st.rerun()
st.sidebar.markdown("</div>", unsafe_allow_html=True)

st.sidebar.markdown('<div class="sidebar-card">', unsafe_allow_html=True)
st.sidebar.markdown("### 🎭 Risk Mood Meter")
avg_score = 0
if st.session_state.history:
    avg_score = sum(item["Risk Score"] for item in st.session_state.history) / len(st.session_state.history)

if avg_score >= 15:
    st.sidebar.error("🔥 Current mood: High alert")
elif avg_score >= 8:
    st.sidebar.warning("⚠️ Current mood: Watch closely")
elif avg_score > 0:
    st.sidebar.success("✅ Current mood: Mostly stable")
else:
    st.sidebar.write("😌 Current mood: No analyses yet")
st.sidebar.markdown("</div>", unsafe_allow_html=True)

st.sidebar.markdown('<div class="sidebar-card">', unsafe_allow_html=True)
st.sidebar.markdown("### 🧠 Quick Cyber Tip")
st.sidebar.write(random.choice(TIPS))
st.sidebar.markdown("</div>", unsafe_allow_html=True)

st.sidebar.markdown('<div class="sidebar-card">', unsafe_allow_html=True)
st.sidebar.markdown("### 🎉 Fun Fact")
st.sidebar.write(random.choice(FUN_FACTS))
st.sidebar.markdown("</div>", unsafe_allow_html=True)

# ---------------- HEADER ----------------
st.title("🛡️ GRC Risk Intelligence Platform")
st.subheader("NIST CSF 2.0 Risk Analysis")
st.write("Analyze cyber risks using likelihood, impact, uploaded text clues, business impact, treatment suggestions, and actionable recommendations.")

main_tab, bi_tab = st.tabs(["Risk Assessment", "Power BI Style Dashboard"])

with main_tab:
    st.header("📄 Upload a Document for Risk Clues")

    uploaded_file = st.file_uploader(
        "Upload a text file (.txt) or CSV file (.csv)",
        type=["txt", "csv"]
    )

    uploaded_text = ""
    upload_suggestion = {}

    if uploaded_file is not None:
        if uploaded_file.name.endswith(".txt"):
            uploaded_text = uploaded_file.read().decode("utf-8", errors="ignore")
        elif uploaded_file.name.endswith(".csv"):
            try:
                temp_df = pd.read_csv(uploaded_file)
                uploaded_text = " ".join(temp_df.astype(str).fillna("").values.flatten())
            except Exception:
                uploaded_text = ""

        if uploaded_text.strip():
            sug_asset, sug_threat, sug_likelihood, sug_impact, matched_words = analyze_uploaded_text(uploaded_text)
            upload_suggestion = {
                "asset": sug_asset,
                "threat": sug_threat,
                "likelihood": sug_likelihood,
                "impact": sug_impact,
                "keywords": matched_words
            }

            st.markdown('<div class="section-box">', unsafe_allow_html=True)
            st.subheader("🔍 Upload-Based Suggestions")
            if sug_asset:
                st.write(f"**Suggested Asset:** {sug_asset}")
            if sug_threat:
                st.write(f"**Suggested Threat:** {sug_threat}")
            if sug_likelihood:
                st.write(f"**Suggested Likelihood:** {sug_likelihood}")
            if sug_impact:
                st.write(f"**Suggested Impact:** {sug_impact}")
            if matched_words:
                st.write(f"**Matched Keywords:** {', '.join(matched_words)}")
            st.caption("These are keyword-based clues to support, not replace, analyst judgment.")
            st.markdown("</div>", unsafe_allow_html=True)

    st.header("🧾 Enter Risk Details")

    asset = st.selectbox(
        "Select Asset",
        ASSET_OPTIONS,
        index=ASSET_OPTIONS.index(st.session_state.selected_asset),
        key="asset_live"
    )
    st.session_state.selected_asset = asset

    relevant_threats = ASSET_THREAT_MAP[asset]

    if st.session_state.selected_threat not in relevant_threats:
        st.session_state.selected_threat = relevant_threats[0]

    threat = st.selectbox(
        "Select Threat (Filtered by Asset)",
        relevant_threats,
        index=relevant_threats.index(st.session_state.selected_threat),
        key="threat_live"
    )
    st.session_state.selected_threat = threat

    st.caption("Threat options are dynamically filtered based on the selected asset.")

    st.header("🎯 Risk Scoring")
    col3, col4 = st.columns(2)

    default_likelihood = upload_suggestion.get("likelihood", 3) if upload_suggestion else 3
    default_impact = upload_suggestion.get("impact", 3) if upload_suggestion else 3

    with col3:
        likelihood = st.slider("Likelihood (1–5)", 1, 5, default_likelihood, key="likelihood_live")

    with col4:
        impact = st.slider("Impact (1–5)", 1, 5, default_impact, key="impact_live")

    analyze = st.button("🚀 Analyze Risk")

    if analyze:
        risk_score = likelihood * impact

        if risk_score >= 15:
            risk_level = "HIGH"
            risk_emoji = "🔴"
            risk_color = "#ff4d4f"
            business_impact = "High financial and reputational damage."
            fun_message = "This one needs urgent attention."
            priority = "🔥 Critical Priority"
            personality = "🔥 This risk is screaming for attention!"
        elif risk_score >= 8:
            risk_level = "MEDIUM"
            risk_emoji = "🟡"
            risk_color = "#f59e0b"
            business_impact = "Moderate operational impact."
            fun_message = "Worth fixing before it grows into a bigger problem."
            priority = "⚠️ Moderate Priority"
            personality = "⚖️ This one is manageable but should not be ignored."
        else:
            risk_level = "LOW"
            risk_emoji = "🟢"
            risk_color = "#22c55e"
            business_impact = "Low impact."
            fun_message = "Not a fire right now, but still worth monitoring."
            priority = "✅ Low Priority"
            personality = "😌 Pretty chill risk, just keep an eye on it."

        suggested_treatment, treatment_reason = suggest_treatment(threat, risk_score)

        st.session_state.last_result = {
            "Asset": asset,
            "Threat": threat,
            "Likelihood": likelihood,
            "Impact": impact,
            "Risk Score": risk_score,
            "Risk Level": risk_level,
            "Risk Emoji": risk_emoji,
            "Risk Color": risk_color,
            "Business Impact": business_impact,
            "Fun Message": fun_message,
            "Priority": priority,
            "Personality": personality,
            "NIST Mapping": get_nist_mapping(threat),
            "Recommendations": get_recommendations(threat),
            "Suggested Treatment": suggested_treatment,
            "Treatment Reason": treatment_reason,
        }

    result = st.session_state.last_result

    if result:
        st.header("📊 Results")

        c1, c2, c3 = st.columns(3)
        with c1:
            st.markdown(f"""
            <div class="card">
                <h4>Risk Score</h4>
                <h2>{result['Risk Score']}</h2>
            </div>
            """, unsafe_allow_html=True)
        with c2:
            st.markdown(f"""
            <div class="card">
                <h4>Risk Level</h4>
                <h2 style="color:{result['Risk Color']} !important;">{result['Risk Emoji']} {result['Risk Level']}</h2>
            </div>
            """, unsafe_allow_html=True)
        with c3:
            st.markdown(f"""
            <div class="card">
                <h4>Asset</h4>
                <h2>{result['Asset']}</h2>
            </div>
            """, unsafe_allow_html=True)

        st.progress(result["Risk Score"] / 25)

        if result["Risk Level"] == "HIGH":
            st.error(f"⚠️ {result['Fun Message']}")
        elif result["RiskLevel"] if False else False:
            pass
        elif result["Risk Level"] == "MEDIUM":
            st.warning(f"⚠️ {result['Fun Message']}")
        else:
            st.success(f"✅ {result['Fun Message']}")

        st.markdown(f"### {result['Priority']}")
        st.markdown(f"**Risk Personality:** {result['Personality']}")
        st.markdown(
            f"**Quick Summary:** A **{result['Threat'].lower()}** risk against **{result['Asset'].lower()}** currently scores "
            f"**{result['Risk Score']}/25**, which is **{result['Risk Level'].lower()}** risk."
        )

        col5, col6 = st.columns(2)

        with col5:
            st.markdown('<div class="section-box">', unsafe_allow_html=True)
            st.subheader("🧠 NIST Mapping")
            st.write(result["NIST Mapping"])
            st.caption("Relevant NIST CSF 2.0 functions for this threat scenario.")
            st.markdown("</div>", unsafe_allow_html=True)

        with col6:
            st.markdown('<div class="section-box">', unsafe_allow_html=True)
            st.subheader("💼 Business Impact")
            st.write(result["Business Impact"])
            st.markdown("**🚨 If ignored:**")
            st.write(risk_consequence(result["Threat"]))
            st.caption("Plain-English view of what this could mean for the organization.")
            st.markdown("</div>", unsafe_allow_html=True)

        st.markdown('<div class="section-box">', unsafe_allow_html=True)
        st.subheader("🛠 Recommendations")
        for rec in result["Recommendations"]:
            st.write(f"- {rec}")
        st.markdown("</div>", unsafe_allow_html=True)

        st.markdown('<div class="section-box">', unsafe_allow_html=True)
        st.subheader("🛡️ Recommended Risk Treatment")
        st.info(f"💡 Suggested Treatment Strategy: {result['Suggested Treatment']}")
        st.write(result["Treatment Reason"])

        treatment_options = ["Mitigate", "Avoid", "Accept", "Transfer"]
        default_index = treatment_options.index(result["Suggested Treatment"])
        final_treatment = st.selectbox(
            "Change treatment if needed",
            treatment_options,
            index=default_index,
            key="final_treatment_select"
        )

        st.write(f"**Final Selected Treatment:** {final_treatment}")
        st.write("**Suggested Next Steps:**")
        for action in get_treatment_actions(final_treatment, result["Risk Score"]):
            st.write(f"- {action}")
        st.markdown("</div>", unsafe_allow_html=True)

        st.markdown('<div class="section-box">', unsafe_allow_html=True)
        st.subheader("🎮 What if the risk changes over time?")
        sim_likelihood = st.slider("Simulated Likelihood", 1, 5, result["Likelihood"], key="sim_l")
        sim_impact = st.slider("Simulated Impact", 1, 5, result["Impact"], key="sim_i")
        sim_score = sim_likelihood * sim_impact
        st.write(f"🔮 Simulated Risk Score: **{sim_score}**")
        st.markdown("</div>", unsafe_allow_html=True)

        with st.expander("🎉 Why did I get this result?"):
            st.write(f"- Likelihood = **{result['Likelihood']}**")
            st.write(f"- Impact = **{result['Impact']}**")
            st.write(f"- Risk Score = **{result['Likelihood']} × {result['Impact']} = {result['Risk Score']}**")
            st.write(f"- This puts the result in the **{result['Risk Level']}** category.")
            st.write("- The treatment suggestion is based on simplified educational risk logic.")
            st.write("- Threat options are filtered by asset to keep the assessment realistic.")

        if st.button("💾 Save Analysis"):
            st.session_state.history.append({
                "Asset": result["Asset"],
                "Threat": result["Threat"],
                "Likelihood": result["Likelihood"],
                "Impact": result["Impact"],
                "Risk Score": result["Risk Score"],
                "Risk Level": result["Risk Level"],
                "Suggested Treatment": result["Suggested Treatment"],
                "Final Treatment": final_treatment
            })
            st.success("Analysis saved to Risk History.")

with bi_tab:
    st.header("📊 Power BI Style Dashboard")

    if st.session_state.history:
        df = pd.DataFrame(st.session_state.history)

        k1, k2, k3, k4 = st.columns(4)
        with k1:
            st.metric("Total Analyses", len(df))
        with k2:
            st.metric("Average Risk Score", round(df["Risk Score"].mean(), 1))
        with k3:
            st.metric("Most Recent Treatment", df.iloc[-1]["Final Treatment"])
        with k4:
            st.metric("Highest Risk Score", int(df["Risk Score"].max()))

        st.markdown("### Risk History Table")
        st.dataframe(df, use_container_width=True)

        dashboard_view = st.selectbox(
            "Choose Dashboard View",
            ["Bar Chart", "Pie Chart", "Both", "Table Only"],
            key="dashboard_view_select"
        )

        risk_counts = df["Risk Level"].value_counts()
        treatment_counts = df["Final Treatment"].value_counts()

        if dashboard_view in ["Bar Chart", "Both"]:
            st.markdown("### 📈 Bar Chart View")
            chart_col1, chart_col2 = st.columns(2)

            with chart_col1:
                st.markdown("**Risk Level Distribution**")
                st.bar_chart(risk_counts)

            with chart_col2:
                st.markdown("**Treatment Distribution**")
                st.bar_chart(treatment_counts)

            st.markdown("**Risk Score Trend**")
            st.bar_chart(df["Risk Score"])

        if dashboard_view in ["Pie Chart", "Both"]:
            st.markdown("### 🥧 Pie Chart View")
            chart_col3, chart_col4 = st.columns(2)

            with chart_col3:
                fig1, ax1 = plt.subplots(figsize=(4, 4))
                ax1.pie(
                    risk_counts,
                    labels=risk_counts.index,
                    autopct="%1.1f%%",
                    startangle=90
                )
                ax1.set_title("Risk Level Distribution")
                ax1.axis("equal")
                st.pyplot(fig1)

            with chart_col4:
                fig2, ax2 = plt.subplots(figsize=(4, 4))
                ax2.pie(
                    treatment_counts,
                    labels=treatment_counts.index,
                    autopct="%1.1f%%",
                    startangle=90
                )
                ax2.set_title("Treatment Distribution")
                ax2.axis("equal")
                st.pyplot(fig2)

        if dashboard_view == "Table Only":
            st.info("Table-only view selected. Use the metrics and risk history table for review.")

        csv_data = df.to_csv(index=False)
        st.download_button(
            label="📥 Download CSV Risk Report",
            data=csv_data,
            file_name="risk_report.csv",
            mime="text/csv"
        )

        professional_report = generate_professional_report(df)
        st.download_button(
            label="📄 Download Professional Text Report",
            data=professional_report,
            file_name="grc_risk_assessment_report.txt",
            mime="text/plain"
        )

        pdf_file = generate_pdf_report(df)
        with open(pdf_file, "rb") as f:
            st.download_button(
                label="🧾 Download Professional PDF Report",
                data=f,
                file_name="grc_risk_report.pdf",
                mime="application/pdf"
            )

        if st.button("🗑️ Clear History", key="clear_history_button"):
            st.session_state.history = []
            st.rerun()
    else:
        st.info("No history yet. Save at least one analysis from the Risk Assessment tab to populate the dashboard.")

# ---------------- FOOTER ----------------
st.markdown("---")
st.markdown(f"""
<div style="text-align:center; font-size:14px; color:#8b949e;">
Built by <b>Saloni Bhosale</b> | GRC & Cybersecurity Risk
<br>Aligned with NIST CSF 2.0 | Interactive Risk Intelligence Platform
<br>Last updated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
</div>
""", unsafe_allow_html=True)
