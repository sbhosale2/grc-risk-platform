import json
import os
import random
import hashlib
import tempfile
from datetime import datetime, date
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import plotly.graph_objects as go
import plotly.express as px
import pandas as pd
import streamlit as st

try:
    from anthropic import Anthropic
    _ANTHROPIC_AVAILABLE = True
except ImportError:
    _ANTHROPIC_AVAILABLE = False
    Anthropic = None

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import (
    Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle,
    Image, HRFlowable, KeepTogether
)


# ─────────────────────────────────────────────────────────────
# PAGE CONFIG
# ─────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="GRC Risk Intelligence Platform",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)


# ─────────────────────────────────────────────────────────────
# CONSTANTS & LOOKUPS
# ─────────────────────────────────────────────────────────────
MODEL_ID = "claude-opus-4-5"   # Verified Anthropic model string

ASSET_OPTIONS = [
    "Database", "Application", "Cloud Environment", "Network",
    "Endpoint / Laptop", "Email System", "User Credentials", "Server",
    "API", "Backup System", "Identity / IAM", "SaaS Platform",
    "Mobile Device", "Vendor / Third Party",
    "HVAC / Building Management System", "IoT Device",
    "OT / Industrial System", "Building Access Control",
    "Security Camera / CCTV", "Finance System", "HR System",
    "Customer Portal",
]

THREAT_OPTIONS = [
    "Data Breach", "Unauthorized Access", "Malware", "Phishing",
    "Misconfiguration", "Insider Threat", "Ransomware",
    "Supply Chain Attack", "Zero-Day Exploit",
    "Denial of Service (DDoS)", "Credential Attack",
    "Data Loss", "Privilege Escalation", "API Abuse",
]

ASSET_THREAT_MAP: dict[str, list[str]] = {
    "Database":                       ["Data Breach", "Unauthorized Access", "Ransomware", "Misconfiguration", "Privilege Escalation", "Data Loss"],
    "Application":                    ["Unauthorized Access", "Phishing", "Misconfiguration", "Denial of Service (DDoS)", "Zero-Day Exploit"],
    "Cloud Environment":              ["Misconfiguration", "Data Breach", "Unauthorized Access", "Denial of Service (DDoS)", "Zero-Day Exploit", "Supply Chain Attack"],
    "Network":                        ["Denial of Service (DDoS)", "Unauthorized Access", "Malware", "Misconfiguration"],
    "Endpoint / Laptop":              ["Malware", "Phishing", "Ransomware", "Unauthorized Access", "Data Loss"],
    "Email System":                   ["Phishing", "Data Breach", "Unauthorized Access", "Malware"],
    "User Credentials":               ["Credential Attack", "Unauthorized Access", "Phishing", "Privilege Escalation"],
    "Server":                         ["Malware", "Ransomware", "Privilege Escalation", "Unauthorized Access", "Zero-Day Exploit"],
    "API":                            ["API Abuse", "Unauthorized Access", "Denial of Service (DDoS)", "Zero-Day Exploit"],
    "Backup System":                  ["Data Loss", "Ransomware", "Unauthorized Access"],
    "Identity / IAM":                 ["Privilege Escalation", "Unauthorized Access", "Credential Attack"],
    "SaaS Platform":                  ["Data Breach", "Unauthorized Access", "Phishing", "Supply Chain Attack", "Credential Attack"],
    "Mobile Device":                  ["Malware", "Phishing", "Unauthorized Access", "Data Loss"],
    "Vendor / Third Party":           ["Supply Chain Attack", "Data Breach", "Unauthorized Access"],
    "HVAC / Building Management System": ["Unauthorized Access", "Misconfiguration", "Denial of Service (DDoS)", "Insider Threat"],
    "IoT Device":                     ["Unauthorized Access", "Malware", "Denial of Service (DDoS)", "Misconfiguration"],
    "OT / Industrial System":         ["Unauthorized Access", "Malware", "Denial of Service (DDoS)", "Insider Threat", "Ransomware"],
    "Building Access Control":        ["Unauthorized Access", "Insider Threat", "Misconfiguration"],
    "Security Camera / CCTV":         ["Unauthorized Access", "Data Breach", "Misconfiguration"],
    "Finance System":                 ["Data Breach", "Unauthorized Access", "Insider Threat", "Data Loss", "Ransomware"],
    "HR System":                      ["Data Breach", "Unauthorized Access", "Insider Threat", "Phishing", "Data Loss"],
    "Customer Portal":                ["Phishing", "API Abuse", "Data Breach", "Denial of Service (DDoS)", "Credential Attack"],
}

ASSET_THREAT_SCORES: dict[tuple[str, str], tuple[int, int]] = {
    ("Endpoint / Laptop",  "Malware"):                  (4, 3),
    ("Endpoint / Laptop",  "Phishing"):                 (4, 3),
    ("Endpoint / Laptop",  "Ransomware"):               (3, 4),
    ("Endpoint / Laptop",  "Data Loss"):                (3, 4),
    ("Email System",       "Phishing"):                 (5, 4),
    ("Email System",       "Malware"):                  (4, 3),
    ("Email System",       "Unauthorized Access"):      (3, 4),
    ("Database",           "Data Breach"):              (4, 5),
    ("Database",           "Unauthorized Access"):      (4, 5),
    ("Database",           "Data Loss"):                (3, 5),
    ("Database",           "Ransomware"):               (3, 5),
    ("Cloud Environment",  "Misconfiguration"):         (5, 5),
    ("Cloud Environment",  "Data Breach"):              (4, 5),
    ("Cloud Environment",  "Supply Chain Attack"):      (3, 5),
    ("API",                "API Abuse"):                (5, 4),
    ("API",                "Denial of Service (DDoS)"): (4, 5),
    ("API",                "Unauthorized Access"):      (4, 4),
    ("Finance System",     "Data Breach"):              (3, 5),
    ("Finance System",     "Insider Threat"):           (3, 5),
    ("Finance System",     "Data Loss"):                (3, 5),
    ("HR System",          "Data Breach"):              (3, 5),
    ("HR System",          "Phishing"):                 (4, 4),
    ("Vendor / Third Party", "Supply Chain Attack"):    (4, 5),
    ("Vendor / Third Party", "Data Breach"):            (3, 5),
    ("Network",            "Denial of Service (DDoS)"): (4, 5),
    ("Network",            "Misconfiguration"):         (4, 4),
    ("OT / Industrial System", "Ransomware"):          (3, 5),
    ("OT / Industrial System", "Malware"):             (3, 5),
    ("Security Camera / CCTV", "Misconfiguration"):    (2, 2),
    ("Security Camera / CCTV", "Unauthorized Access"): (2, 3),
    ("HVAC / Building Management System", "Misconfiguration"): (2, 3),
    ("HVAC / Building Management System", "Insider Threat"):    (2, 3),
    ("Mobile Device",      "Data Loss"):                (3, 3),
    ("Mobile Device",      "Phishing"):                 (3, 2),
    ("Building Access Control", "Misconfiguration"):    (2, 3),
    ("Building Access Control", "Insider Threat"):      (2, 4),
    ("Backup System",      "Data Loss"):                (2, 5),
    ("Backup System",      "Ransomware"):               (3, 5),
    ("SaaS Platform",      "Credential Attack"):        (4, 4),
    ("SaaS Platform",      "Phishing"):                 (4, 3),
    ("Customer Portal",    "API Abuse"):                (4, 4),
    ("Customer Portal",    "Phishing"):                 (3, 3),
}

THREAT_PROFILES: dict[str, dict[str, int]] = {
    "Data Breach":              {"likelihood": 4, "impact": 5},
    "Unauthorized Access":      {"likelihood": 4, "impact": 4},
    "Malware":                  {"likelihood": 4, "impact": 4},
    "Phishing":                 {"likelihood": 5, "impact": 3},
    "Misconfiguration":         {"likelihood": 4, "impact": 4},
    "Insider Threat":           {"likelihood": 3, "impact": 5},
    "Ransomware":               {"likelihood": 4, "impact": 5},
    "Supply Chain Attack":      {"likelihood": 3, "impact": 5},
    "Zero-Day Exploit":         {"likelihood": 3, "impact": 5},
    "Denial of Service (DDoS)": {"likelihood": 4, "impact": 4},
    "Credential Attack":        {"likelihood": 5, "impact": 4},
    "Data Loss":                {"likelihood": 3, "impact": 5},
    "Privilege Escalation":     {"likelihood": 3, "impact": 5},
    "API Abuse":                {"likelihood": 4, "impact": 4},
}

DEMO_SCENARIOS: list[tuple[str, str, int, int]] = [
    # Deliberately span all four risk levels: LOW · MEDIUM · HIGH · CRITICAL
    # (Asset, Threat, Asset_Value, Control_Effectiveness)
    ("Security Camera / CCTV",              "Misconfiguration",         1, 5),  # LOW   residual ≈ 1
    ("Mobile Device",                       "Phishing",                 2, 5),  # LOW   residual ≈ 1
    ("HVAC / Building Management System",   "Misconfiguration",         3, 4),  # LOW   residual ≈ 2
    ("Endpoint / Laptop",                   "Malware",                  3, 3),  # MEDIUM residual ≈ 7
    ("SaaS Platform",                       "Credential Attack",        4, 3),  # MEDIUM residual ≈ 11
    ("Backup System",                       "Data Loss",                5, 3),  # MEDIUM residual ≈ 9
    ("Email System",                        "Phishing",                 4, 3),  # HIGH  residual ≈ 14
    ("Finance System",                      "Insider Threat",           5, 2),  # HIGH  residual ≈ 19
    ("Database",                            "Data Breach",              5, 1),  # CRITICAL residual ≈ 24
    ("Cloud Environment",                   "Misconfiguration",         5, 1),  # CRITICAL residual ≈ 24
]

EXAMPLE_PROMPTS: list[str] = [
    "My laptop was stolen at the airport and it has client data on it",
    "An employee shared their password with a contractor over Slack",
    "Our website went down for 3 hours due to a sudden traffic spike",
    "We got a suspicious email asking us to click a link to verify payroll",
    "A vendor we share HR data with just had a data breach",
    "Someone in finance accidentally deleted last quarter's billing records",
]

TIPS: list[str] = [
    "Risk becomes more actionable when linked to an owner, evidence, control, and a review date.",
    "Vulnerabilities should be connected to business risk, not viewed only as technical findings.",
    "Residual risk explains what remains after controls are applied - always document it.",
    "Evidence upload and audit status bring this tool closer to a real GRC audit workflow.",
    "Control effectiveness scoring is subjective - calibrate it against actual test results when possible.",
    "Treat your risk register as a living document: review it quarterly or after major incidents.",
]

GLOSSARY: dict[str, str] = {
    "Risk Formula":           "Risk Score = (Likelihood × Impact × Asset Value) ÷ Control Effectiveness, normalized to 1–25.",
    "Asset Value":            "Business criticality of the asset (1–5). A customer-facing database is typically 4–5.",
    "Control Effectiveness":  "Strength of current controls (1–5). Higher = stronger controls = lower residual risk.",
    "Residual Risk":          "Risk remaining after applying existing controls. The primary driver for treatment decisions.",
    "Evidence":               "Proof for audit validation: scan output, screenshots, tickets, policies, or logs.",
    "Nessus":                 "Vulnerability scanner. Link findings by plugin ID, severity, and affected asset.",
    "Splunk":                 "SIEM/log analytics. Use alerts and log searches as supporting evidence.",
    "NIST CSF 2.0":           "NIST Cybersecurity Framework 2.0 - six functions: Govern, Identify, Protect, Detect, Respond, Recover.",
    "RMF":                    "NIST Risk Management Framework - six steps: Categorize, Select, Implement, Assess, Authorize, Monitor.",
    "ISO 27001":              "International standard for information security management systems (ISMS).",
    "Zero Trust":             "Security model that assumes no implicit trust - verify every user, device, and session explicitly.",
}


# ─────────────────────────────────────────────────────────────
# CSS - VIBRANT, MODERN, EASY TO NAVIGATE
# ─────────────────────────────────────────────────────────────
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;500&display=swap');

/* ── Base ── */
html, body, [class*="css"] {
    font-family: 'Inter', system-ui, sans-serif;
}
.block-container {
    padding-top: 0.5rem;
    padding-bottom: 2rem;
    max-width: 1440px;
}

/* ── Hero header ── */
.platform-header {
    background: linear-gradient(135deg, #0F172A 0%, #1E3A5F 50%, #1D4ED8 100%);
    border-radius: 16px;
    padding: 32px 36px;
    margin-bottom: 0;
    display: flex;
    align-items: center;
    gap: 20px;
    position: relative;
    overflow: hidden;
    box-shadow: 0 8px 32px rgba(29,78,216,0.25);
}
.platform-header::before {
    content: '';
    position: absolute;
    top: -60px; right: -60px;
    width: 220px; height: 220px;
    background: rgba(99,179,237,0.12);
    border-radius: 50%;
}
.platform-header::after {
    content: '';
    position: absolute;
    bottom: -40px; left: 40%;
    width: 160px; height: 160px;
    background: rgba(165,180,252,0.08);
    border-radius: 50%;
}
.platform-header-icon { font-size: 2.6rem; line-height: 1; z-index:1; }
.platform-header-title {
    color: #FFFFFF !important;
    font-size: 1.65rem !important;
    font-weight: 800 !important;
    letter-spacing: -0.03em;
    margin: 0 !important; padding: 0 !important;
    z-index:1;
}
.platform-header-sub {
    color: #93C5FD !important;
    font-size: 0.83rem !important;
    margin: 4px 0 0 0 !important;
    font-family: 'JetBrains Mono', monospace;
    z-index:1;
}
.platform-header-badge {
    margin-left: auto;
    background: rgba(255,255,255,0.12);
    border: 1px solid rgba(255,255,255,0.2);
    border-radius: 20px;
    padding: 6px 14px;
    color: #E0F2FE !important;
    font-size: 0.75rem;
    font-weight: 600;
    white-space: nowrap;
    z-index:1;
}

/* ── Sticky header support ── */
[data-testid="stHeader"] {
    position: sticky !important;
    top: 0 !important;
    z-index: 999 !important;
    background: #0F172A !important;
}

/* ── Sidebar nav menu ── */
.sb-nav-item {
    display: flex;
    align-items: center;
    gap: 12px;
    padding: 12px 14px;
    border-radius: 10px;
    cursor: pointer;
    margin-bottom: 6px;
    border: 1px solid transparent;
}
.sb-nav-item.active {
    background: #1D4ED8 !important;
    border-color: #1D4ED8 !important;
}
.sb-nav-item:not(.active) {
    background: #1E293B;
    border-color: #334155;
}
.sb-nav-icon { font-size: 1.3rem; width: 28px; text-align: center; flex-shrink: 0; }
.sb-nav-label { font-size: 0.88rem; font-weight: 700; color: white !important; margin-bottom: 1px; }
.sb-nav-desc  { font-size: 0.7rem;  color: #94A3B8 !important; line-height: 1.3; }
.sb-nav-item.active .sb-nav-desc { color: #BFDBFE !important; }
.sb-divider { border:none; border-top:1px solid #334155; margin:14px 0; }

/* ── Remove old nav-grid (replaced by sidebar nav) ── */
.nav-grid, .nav-card, .nav-card-icon, .nav-card-title,
.nav-card-desc, .nav-card-step { display: none !important; }

/* ── Workflow progress bar ── */
.workflow-bar {
    display: flex;
    align-items: center;
    background: #F8FAFC;
    border: 1px solid #E2E8F0;
    border-radius: 10px;
    padding: 12px 20px;
    margin-bottom: 16px;
    gap: 0;
}
.wf-step {
    display: flex;
    align-items: center;
    gap: 8px;
    flex: 1;
}
.wf-dot {
    width: 28px; height: 28px;
    border-radius: 50%;
    background: #E2E8F0;
    color: #94A3B8;
    font-size: 0.75rem;
    font-weight: 700;
    display: flex; align-items: center; justify-content: center;
    flex-shrink: 0;
}
.wf-dot.done   { background: #059669; color: white; }
.wf-dot.active { background: #1D4ED8; color: white; box-shadow: 0 0 0 3px #DBEAFE; }
.wf-label { font-size: 0.78rem; font-weight: 600; color: #94A3B8; }
.wf-label.active { color: #1D4ED8; }
.wf-label.done   { color: #059669; }
.wf-arrow { color: #CBD5E1; font-size: 1rem; padding: 0 8px; }

/* ── Next step callout ── */
.next-step-banner {
    background: linear-gradient(135deg, #059669 0%, #047857 100%);
    border-radius: 10px;
    padding: 14px 20px;
    margin: 16px 0;
    display: flex;
    align-items: center;
    gap: 14px;
    box-shadow: 0 4px 12px rgba(5,150,105,0.25);
}
.next-step-banner-icon { font-size: 1.6rem; }
.next-step-banner-text { color: white; font-size: 0.92rem; font-weight: 500; }
.next-step-banner-text strong { font-weight: 700; }

/* ── Simulation panel ── */
.sim-panel {
    background: linear-gradient(135deg, #1E1B4B 0%, #312E81 100%);
    border-radius: 12px;
    padding: 20px 24px;
    margin-bottom: 16px;
    border: 1px solid #4338CA;
}
.sim-step-indicator {
    display: flex;
    gap: 6px;
    margin-bottom: 14px;
}
.sim-dot {
    width: 8px; height: 8px;
    border-radius: 50%;
    background: rgba(255,255,255,0.25);
    transition: background 0.2s;
}
.sim-dot.active { background: #818CF8; }
.sim-dot.done   { background: #34D399; }
.sim-title { color: #E0E7FF; font-size: 1rem; font-weight: 700; margin-bottom: 4px; }
.sim-desc  { color: #A5B4FC; font-size: 0.84rem; line-height: 1.5; }

/* ── KPI cards ── */
.kpi-grid {
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 12px;
    margin-bottom: 1.2rem;
}
.kpi-card {
    background: #FFFFFF;
    border: 1px solid #E2E8F0;
    border-radius: 10px;
    padding: 16px 18px;
    border-top: 3px solid #2563EB;
    box-shadow: 0 1px 4px rgba(0,0,0,0.04);
}
.kpi-card.critical { border-top-color: #DC2626; }
.kpi-card.high     { border-top-color: #EA580C; }
.kpi-card.medium   { border-top-color: #D97706; }
.kpi-card.low      { border-top-color: #16A34A; }
.kpi-label {
    font-size: 0.69rem; font-weight: 600;
    text-transform: uppercase; letter-spacing: 0.08em;
    color: #64748B; margin-bottom: 4px;
    font-family: 'JetBrains Mono', monospace;
}
.kpi-value { font-size: 1.9rem; font-weight: 800; color: #0F172A; line-height: 1.1; }
.kpi-sub   { font-size: 0.73rem; color: #94A3B8; margin-top: 3px; }

/* ── Section containers ── */
.section-panel {
    background: #F8FAFC;
    border: 1px solid #E2E8F0;
    border-radius: 10px;
    padding: 18px 20px;
    margin-bottom: 14px;
}
.section-title {
    font-size: 0.74rem; font-weight: 700;
    text-transform: uppercase; letter-spacing: 0.1em;
    color: #475569; margin-bottom: 12px;
    font-family: 'JetBrains Mono', monospace;
    display: flex; align-items: center; gap: 6px;
}

/* ── Plain-English box ── */
.summary-box {
    background: linear-gradient(135deg, #EFF6FF 0%, #F0F9FF 100%);
    border-left: 4px solid #2563EB;
    border-radius: 0 10px 10px 0;
    padding: 14px 18px;
    margin: 10px 0;
    font-size: 0.95rem;
    line-height: 1.65;
    color: #1E3A5F;
}

/* ── Risk level badges ── */
.badge {
    display: inline-block; padding: 3px 10px;
    border-radius: 20px; font-size: 0.72rem;
    font-weight: 700; letter-spacing: 0.05em;
    font-family: 'JetBrains Mono', monospace;
}
.badge-critical { background: #FEF2F2; color: #991B1B; border: 1px solid #FECACA; }
.badge-high     { background: #FFF7ED; color: #9A3412; border: 1px solid #FED7AA; }
.badge-medium   { background: #FEFCE8; color: #854D0E; border: 1px solid #FEF08A; }
.badge-low      { background: #F0FDF4; color: #166534; border: 1px solid #BBF7D0; }

/* ── Onboarding panel ── */
.onboarding-panel {
    background: linear-gradient(135deg, #1E3A5F 0%, #1E40AF 100%) !important;
    border: 1px solid #3B82F6;
    border-radius: 12px;
    padding: 20px 24px;
    margin-bottom: 16px;
    color: #E2F0FF !important;
    box-shadow: 0 4px 16px rgba(30,64,175,0.2);
}
.onboarding-panel * { color: #E2F0FF !important; }
.onboarding-panel strong { color: #93C5FD !important; }
.onboarding-panel ol { margin: 8px 0 0 20px; padding: 0; line-height: 2.0; }

/* ── Sidebar ── */
[data-testid="stSidebar"] { background: #0F172A; }
[data-testid="stSidebar"] * { color: #CBD5E1 !important; }
[data-testid="stSidebar"] .sidebar-section {
    background: #1E293B;
    border: 1px solid #334155;
    border-radius: 10px;
    padding: 12px 14px;
    margin-bottom: 10px;
}
[data-testid="stSidebar"] h2,
[data-testid="stSidebar"] h3,
[data-testid="stSidebar"] h4 {
    color: #94B8D4 !important;
    font-size: 0.73rem !important;
    text-transform: uppercase;
    letter-spacing: 0.1em;
}
[data-testid="stSidebar"] .status-ok   { background: #052E16; border: 1px solid #166534; color: #86EFAC !important; padding: 6px 10px; border-radius: 6px; margin-bottom: 5px; font-size: 0.8rem; }
[data-testid="stSidebar"] .status-warn { background: #451A03; border: 1px solid #92400E; color: #FDE68A !important; padding: 6px 10px; border-radius: 6px; margin-bottom: 5px; font-size: 0.8rem; }

/* ── Tabs - make them look like navigation ── */
.stTabs [data-baseweb="tab-list"] {
    background: #F1F5F9;
    border-radius: 10px;
    padding: 4px;
    gap: 2px;
    border: 1px solid #E2E8F0;
}
.stTabs [data-baseweb="tab"] {
    border-radius: 7px !important;
    font-weight: 600 !important;
    font-size: 0.88rem !important;
    padding: 10px 20px !important;
    color: #475569 !important;
    transition: all 0.15s !important;
}
.stTabs [aria-selected="true"] {
    background: white !important;
    color: #1D4ED8 !important;
    box-shadow: 0 1px 4px rgba(0,0,0,0.1) !important;
}
.stTabs [data-baseweb="tab-highlight"] { display: none !important; }
.stTabs [data-baseweb="tab-border"]    { display: none !important; }

/* ── Buttons ── */
.stButton button {
    font-family: 'Inter', sans-serif !important;
    font-weight: 600 !important;
    border-radius: 8px !important;
    transition: all 0.15s !important;
}
.stButton button[kind="primary"] {
    background: linear-gradient(135deg, #1D4ED8, #2563EB) !important;
    border: none !important;
    color: #FFFFFF !important;
    box-shadow: 0 2px 8px rgba(29,78,216,0.3) !important;
}
.stButton button[kind="primary"]:hover {
    box-shadow: 0 4px 16px rgba(29,78,216,0.4) !important;
    transform: translateY(-1px) !important;
}

/* ── Audit / formula / dup styles ── */
.audit-warn {
    background: #FFF7ED; border: 1px solid #FED7AA;
    border-radius: 8px; padding: 10px 14px; color: #7C2D12; font-size: 0.88rem;
}
.formula-strip {
    background: #0F172A; color: #7DD3FC;
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.8rem; padding: 10px 16px;
    border-radius: 8px; margin: 8px 0; letter-spacing: 0.02em;
}
.dup-warn {
    background: #FEFCE8; border: 1px solid #FDE047;
    border-radius: 8px; padding: 10px 14px; color: #713F12; font-size: 0.88rem;
}

/* ── Footer ── */
.platform-footer {
    text-align: center; font-size: 0.76rem; color: #94A3B8;
    padding: 20px 0 8px 0;
    font-family: 'JetBrains Mono', monospace;
    border-top: 1px solid #E2E8F0; margin-top: 24px;
}

/* ── Slider legend ── */
.slider-legend {
    display: flex; flex-wrap: wrap; gap: 6px 12px;
    margin-top: 6px; padding: 8px 10px;
    background: #F8FAFC; border: 1px solid #E2E8F0;
    border-radius: 8px;
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.7rem; color: #475569; line-height: 1.5;
}
.slider-legend span { white-space: nowrap; }
.field-note {
    font-size: 0.74rem; color: #64748B;
    margin: -4px 0 10px 2px; line-height: 1.4; font-style: italic;
}

/* ── Feature highlight cards ── */
.feature-card {
    background: white;
    border: 1px solid #E2E8F0;
    border-radius: 12px;
    padding: 20px;
    text-align: center;
    transition: box-shadow 0.15s, transform 0.15s;
}
.feature-card:hover {
    box-shadow: 0 4px 20px rgba(0,0,0,0.08);
    transform: translateY(-2px);
}
.feature-card-icon { font-size: 2rem; margin-bottom: 10px; }
.feature-card-title { font-size: 0.95rem; font-weight: 700; color: #0F172A; margin-bottom: 4px; }
.feature-card-desc  { font-size: 0.78rem; color: #64748B; line-height: 1.5; }

/* ── Responsive ── */
@media (max-width: 900px) {
    .kpi-grid { grid-template-columns: repeat(2, 1fr); }
    .nav-grid { grid-template-columns: 1fr; }
    .platform-header-title { font-size: 1.2rem !important; }
    .slider-legend { font-size: 0.66rem; gap: 4px 8px; }
}
</style>
""", unsafe_allow_html=True)




# ─────────────────────────────────────────────────────────────
# SESSION STATE
# ─────────────────────────────────────────────────────────────
DEFAULT_RISK_APPETITE = 12   # MEDIUM/HIGH boundary - users can adjust in sidebar

_DEFAULTS: dict = {
    "history": [],
    "last_result": None,
    "selected_asset": "Database",
    "selected_threat": "Data Breach",
    "smart_description": "",
    "input_mode": "smart",
    "demo_role": "Admin",
    "demo_user": "Demo Admin",
    "show_onboarding": True,
    "random_asset_value": 3,
    "random_control_effectiveness": 3,
    "_temp_files": [],
    "scanner_findings": None,
    "alert_findings":   None,
    # ── Onboarding wizard ──
    "wizard_complete":  False,
    "wizard_company":   "",
    "wizard_industry":  "Technology",
    "wizard_size":      "11–50 people",
    "wizard_frameworks": ["SOC 2", "NIST CSF"],
    "wizard_concern":   "Data breach / unauthorized access",
    "active_tab":      0,
    "active_section":  "auto_discovery",  # tree nav active leaf
    "landing_visited": False,
    "risk_appetite":   DEFAULT_RISK_APPETITE,
}
for _k, _v in _DEFAULTS.items():
    if _k not in st.session_state:
        st.session_state[_k] = _v


# ─────────────────────────────────────────────────────────────
# UTILITY HELPERS
# ─────────────────────────────────────────────────────────────
def risk_level(score: int | float) -> tuple[str, str, str]:
    s = float(score)
    if s >= 20: return "CRITICAL", "🔴", "#991B1B"
    if s >= 13: return "HIGH",     "🔴", "#DC2626"
    if s >=  7: return "MEDIUM",   "🟡", "#D97706"
    return             "LOW",      "🟢", "#16A34A"


def level_css_class(level: str) -> str:
    return level.lower()   # "critical", "high", "medium", "low"


def _risk_fingerprint(asset: str, threat: str) -> str:
    """Stable fingerprint for deduplication check."""
    return hashlib.md5(f"{asset}::{threat}".encode()).hexdigest()[:8]


def safe_threats_for_asset(asset: str) -> list[str]:
    return ASSET_THREAT_MAP.get(asset, THREAT_OPTIONS[:3])


def cleanup_temp_files() -> None:
    for path in st.session_state.get("_temp_files", []):
        try:
            Path(path).unlink(missing_ok=True)
        except Exception:
            pass
    st.session_state["_temp_files"] = []


# ─────────────────────────────────────────────────────────────
# LIKELIHOOD DEFINITIONS WITH TIME HORIZON
# Aligned with NIST SP 800-30 Rev 1 Table G-2
# ─────────────────────────────────────────────────────────────
LIKELIHOOD_DEFINITIONS: dict[int, dict] = {
    1: {"label": "Rare",           "freq": "Unlikely in the next 5 years",
        "desc": "The threat has no known history of occurring in similar organisations and would require significant effort or unusual circumstances."},
    2: {"label": "Unlikely",       "freq": "May occur once every 2–5 years",
        "desc": "The threat has occurred in the industry but your organisation has not experienced it. Controls are likely to prevent it."},
    3: {"label": "Possible",       "freq": "May occur once per year",
        "desc": "The threat occurs periodically in similar organisations. You may have experienced near-misses. Controls are partially effective."},
    4: {"label": "Likely",         "freq": "Expected at least once per year",
        "desc": "The threat is common in your industry and sector. Controls exist but are not fully preventing occurrence."},
    5: {"label": "Almost Certain", "freq": "Expected multiple times per year",
        "desc": "The threat is actively observed in your environment or the sector. Controls are minimal or not working."},
}

IMPACT_DEFINITIONS: dict[int, dict] = {
    1: {"label": "Negligible",  "desc": "Minimal disruption. No customer impact, no regulatory obligation, cost < $1K."},
    2: {"label": "Minor",       "desc": "Limited disruption, recoverable within hours. Minimal customer impact, cost $1K–$10K."},
    3: {"label": "Moderate",    "desc": "Noticeable disruption, recovery within days. Some customer impact, regulatory notice possible, cost $10K–$100K."},
    4: {"label": "Significant", "desc": "Major disruption, recovery within weeks. Customer churn, regulatory action likely, cost $100K–$1M."},
    5: {"label": "Severe",      "desc": "Critical disruption, extended recovery or permanent damage. Large-scale customer impact, enforcement action, cost > $1M."},
}

# Default risk appetite threshold - residual risks at or above this score
# require active treatment regardless of asset value. Users can customise in sidebar.


# Methodology: aligned with NIST SP 800-30 Rev 1 and ISO 27005:2022
#
# Step 1 - Inherent Risk
#   Impact is weighted by asset criticality before multiplying by likelihood.
#   Asset Value uses a log-like weight so high-criticality assets aren't
#   linearly over-penalised and low-criticality assets aren't ignored.
#
#   Impact_Adjusted = Impact × AV_WEIGHT[Asset_Value]
#   Inherent_Risk   = Likelihood × Impact_Adjusted   → clamped to [1, 25]
#
# Step 2 - Residual Risk
#   Controls are modelled as a percentage reduction of inherent risk, not
#   a divisor. A divisor (old formula) produces near-zero effect at high
#   control scores (CE=5 vs CE=1 differed by only 2 points). A calibrated
#   S-curve reduction reflects real-world control maturity:
#
#   CE = 1 (minimal / absent controls)  →  5% reduction
#   CE = 2 (basic hygiene only)         → 20% reduction
#   CE = 3 (standard, partially tested) → 45% reduction
#   CE = 4 (mature, regularly tested)   → 70% reduction
#   CE = 5 (best-in-class, evidenced)   → 90% reduction
#
#   Residual_Risk = Inherent_Risk × (1 - CE_REDUCTION[CE])  → rounded, [1, 25]
#
# Why this is better than the old formula:
#   • Asset value affects impact (not the raw score directly)
#   • CE=5 vs CE=1 produces a 22-point swing, not a 2-point swing
#   • Scores are monotone: lower CE always means higher residual risk
#   • The full 1–24 output range is utilised with no arbitrary multiplier
#   • Separates inherent risk (threat exposure) from residual risk (post-control)
# ─────────────────────────────────────────────────────────────

# Asset Value criticality weights (log-like, not linear)
AV_WEIGHT: dict[int, float] = {
    1: 0.60,   # negligible business value
    2: 0.75,   # low business value
    3: 1.00,   # moderate - baseline
    4: 1.30,   # high business value
    5: 1.60,   # mission-critical
}

# Control Effectiveness percentage reduction (calibrated S-curve)
CE_REDUCTION: dict[int, float] = {
    1: 0.05,   # minimal / no controls
    2: 0.20,   # basic hygiene
    3: 0.45,   # standard, partially tested
    4: 0.70,   # mature, regularly tested
    5: 0.90,   # best-in-class, evidenced
}


def calculate_auto_scores(
    asset: str,
    threat: str,
    matched_words: list[str] | None = None,
) -> tuple[int, int, list[str]]:
    matched_words = matched_words or []
    if (asset, threat) in ASSET_THREAT_SCORES:
        base_l, base_i = ASSET_THREAT_SCORES[(asset, threat)]
        source = f"asset–threat pair baseline ({asset} + {threat})"
    else:
        profile = THREAT_PROFILES.get(threat, {"likelihood": 3, "impact": 3})
        base_l, base_i = profile["likelihood"], profile["impact"]
        source = f"threat-level baseline ({threat})"

    kw_boost   = 1 if len(matched_words) >= 5 else 0
    likelihood = max(1, min(5, base_l + kw_boost))
    impact     = max(1, min(5, base_i))

    reasons = [
        f"Source: {source} → likelihood {base_l}/5, impact {base_i}/5.",
        f"Keyword evidence adjustment: +{kw_boost} to likelihood ({len(matched_words)} matched terms).",
        f"Final likelihood: {likelihood}/5, impact: {impact}/5.",
    ]
    return likelihood, impact, reasons


def calculate_risks(
    likelihood: int,
    impact: int,
    asset_value: int,
    control_effectiveness: int,
) -> tuple[float, int]:
    """
    Returns (inherent_risk, residual_risk).

    Inherent risk  = Likelihood × (Impact × AV_WEIGHT[asset_value]), clamped to [1, 25].
    Residual risk  = Inherent × (1 − CE_REDUCTION[control_effectiveness]), rounded, [1, 25].

    Aligned with NIST SP 800-30 Rev 1 (Table I-2, I-3) and ISO 27005:2022 §9.
    """
    av_w         = AV_WEIGHT.get(max(1, min(5, asset_value)), 1.0)
    ce_r         = CE_REDUCTION.get(max(1, min(5, control_effectiveness)), 0.45)
    impact_adj   = impact * av_w
    inherent     = round(min(25.0, max(1.0, likelihood * impact_adj)), 1)
    residual     = round(min(25.0, max(1.0, inherent * (1.0 - ce_r))))
    return inherent, residual


def get_priority_flag(score: int) -> tuple[str, str]:
    if score >= 20: return "Immediate", "Executive escalation required - treat as a critical priority."
    if score >= 13: return "Immediate", "High-priority remediation should begin without delay."
    if score >=  7: return "Planned",   "Address through a planned remediation cycle with a named owner."
    return                 "Monitor",   "Continue monitoring and review periodically - no urgent action required."


# ─────────────────────────────────────────────────────────────
# FRAMEWORK MAPPINGS
# ─────────────────────────────────────────────────────────────
def get_nist_mapping(threat: str) -> str:
    m = {
        "Data Breach":              "Govern, Protect, Detect, Respond",
        "Unauthorized Access":      "Protect, Detect, Respond",
        "Malware":                  "Detect, Respond, Recover",
        "Phishing":                 "Protect, Detect, Respond",
        "Misconfiguration":         "Identify, Protect",
        "Insider Threat":           "Govern, Protect, Detect, Respond",
        "Ransomware":               "Protect, Detect, Respond, Recover",
        "Supply Chain Attack":      "Govern, Identify, Protect, Detect",
        "Zero-Day Exploit":         "Identify, Protect, Detect, Respond",
        "Denial of Service (DDoS)": "Protect, Detect, Respond",
        "Credential Attack":        "Protect, Detect, Respond",
        "Data Loss":                "Protect, Recover",
        "Privilege Escalation":     "Protect, Detect, Respond",
        "API Abuse":                "Protect, Detect, Respond",
    }
    return m.get(threat, "Identify, Protect")


def get_rmf_mapping(threat: str) -> str:
    m = {
        "Data Breach":              "Categorize, Select, Implement, Assess, Monitor",
        "Unauthorized Access":      "Select, Implement, Assess, Monitor",
        "Malware":                  "Implement, Assess, Monitor",
        "Phishing":                 "Select, Implement, Monitor",
        "Misconfiguration":         "Categorize, Select, Implement, Assess",
        "Insider Threat":           "Categorize, Select, Assess, Monitor",
        "Ransomware":               "Select, Implement, Assess, Monitor",
        "Supply Chain Attack":      "Categorize, Select, Assess, Monitor",
        "Zero-Day Exploit":         "Select, Implement, Assess, Monitor",
        "Denial of Service (DDoS)": "Select, Implement, Monitor",
        "Credential Attack":        "Select, Implement, Monitor",
        "Data Loss":                "Categorize, Implement, Monitor",
        "Privilege Escalation":     "Select, Implement, Assess, Monitor",
        "API Abuse":                "Select, Implement, Monitor",
    }
    return m.get(threat, "Categorize, Select, Implement, Monitor")


def get_iso27001_mapping(threat: str) -> str:
    m = {
        "Data Breach":              "A.8 Asset Mgmt · A.9 Access Control · A.10 Cryptography · A.16 Incident Mgmt",
        "Unauthorized Access":      "A.9 Access Control · A.12 Operations · A.13 Communications",
        "Malware":                  "A.12.2 Malware Controls · A.12.6 Vulnerability Mgmt · A.16 Incident Mgmt",
        "Phishing":                 "A.7.2.2 Awareness Training · A.9 Access Control · A.12 Operations",
        "Misconfiguration":         "A.12.1 Operational Procedures · A.14 System Acquisition · Change Mgmt",
        "Insider Threat":           "A.7 HR Security · A.9 Access Control · A.12.4 Logging · A.6.1.2 Duties",
        "Ransomware":               "A.12.3 Backup · A.16 Incident Mgmt · A.17 Business Continuity",
        "Supply Chain Attack":      "A.15 Supplier Relationships · A.9 Access Control · Third-Party Risk",
        "Zero-Day Exploit":         "A.12.6 Vulnerability Mgmt · A.16 Incident Response · A.12.4 Monitoring",
        "Denial of Service (DDoS)": "A.13 Communications · A.17 Business Continuity · A.12.4 Monitoring",
        "Credential Attack":        "A.9 Access Control · A.9.4.3 Password Mgmt · A.12.4 Monitoring",
        "Data Loss":                "A.12.3 Backup · A.8 Asset Mgmt · A.17 Business Continuity",
        "Privilege Escalation":     "A.9.2.3 Privileged Access · A.9 Access Control · A.12.4 Monitoring",
        "API Abuse":                "A.9 Access Control · A.13 Communications · A.14 Secure Development",
    }
    return m.get(threat, "A.5 Policies · A.8 Asset Mgmt · A.12 Operations Security")


def get_zero_trust_guidance(threat: str) -> list[str]:
    m = {
        "Data Breach":              ["Enforce least-privilege data access.", "Encrypt all sensitive data at rest and in transit.", "Monitor and alert on abnormal data access patterns."],
        "Unauthorized Access":      ["Require phishing-resistant MFA for all access.", "Validate device trust posture before granting sessions.", "Continuously monitor and re-evaluate session trust."],
        "Malware":                  ["Restrict endpoint local admin rights.", "Inspect device security posture at every connection.", "Limit lateral movement through micro-segmentation."],
        "Phishing":                 ["Deploy phishing-resistant MFA (FIDO2/passkeys).", "Train users to report suspicious requests.", "Validate all out-of-band requests through a secondary channel."],
        "Misconfiguration":         ["Apply and enforce secure configuration baselines.", "Monitor continuously for configuration drift.", "Limit admin privilege access with just-in-time provisioning."],
        "Insider Threat":           ["Apply least privilege to all internal accounts.", "Monitor user behaviour for anomalies.", "Use session recording for privileged access."],
        "Ransomware":               ["Segment systems and keep backups air-gapped.", "Verify privileged access with MFA and PAM.", "Test recovery procedures at least quarterly."],
        "Supply Chain Attack":      ["Assess vendor security posture before onboarding.", "Limit third-party access to minimum required scope.", "Monitor vendor activity and data flows continuously."],
        "Zero-Day Exploit":         ["Apply compensating controls when patches are unavailable.", "Segment critical assets to limit blast radius.", "Use threat intelligence feeds to detect novel exploits early."],
        "Denial of Service (DDoS)": ["Deploy DDoS mitigation at the network edge.", "Implement rate limiting on all public-facing endpoints.", "Maintain and test failover / redundancy plans."],
        "Credential Attack":        ["Enforce MFA on all accounts.", "Detect and alert on abnormal login behaviour.", "Apply least privilege and rotate credentials regularly."],
        "Data Loss":                ["Maintain tested, versioned, and immutable backups.", "Restrict bulk data deletion with approval workflows.", "Monitor and alert on destructive operations."],
        "Privilege Escalation":     ["Limit standing admin privileges - use just-in-time access.", "Alert on privilege changes within minutes.", "Patch privilege escalation vulnerabilities on priority schedule."],
        "API Abuse":                ["Authenticate every API request with scoped tokens.", "Apply rate limiting and quota controls per consumer.", "Monitor API usage patterns and alert on anomalies."],
    }
    return m.get(threat, ["Verify every user, device, and session explicitly.", "Apply least privilege throughout.", "Assume breach and design for containment."])



# ─────────────────────────────────────────────────────────────
# EXTENDED FRAMEWORK MAPPINGS - HIPAA, PCI DSS, GDPR, CCPA
# ─────────────────────────────────────────────────────────────
def get_hipaa_mapping(threat: str) -> str:
    """Map threat to relevant HIPAA safeguard categories (45 CFR §164)."""
    m = {
        "Data Breach":              "§164.312(a)(2)(iv) Encryption · §164.308(a)(6) Incident Response · §164.312(b) Audit Controls",
        "Unauthorized Access":      "§164.308(a)(4) Access Management · §164.312(a)(1) Access Control · §164.308(a)(3) Workforce Security",
        "Malware":                  "§164.308(a)(5) Security Awareness · §164.312(a)(2)(i) Unique User IDs · §164.306 Security Standards",
        "Phishing":                 "§164.308(a)(5) Security Awareness Training · §164.308(a)(6) Incident Procedures",
        "Misconfiguration":         "§164.308(a)(8) Evaluation · §164.310(d) Device & Media Controls · §164.306 Security Standards",
        "Insider Threat":           "§164.308(a)(3) Workforce Security · §164.308(a)(4) Information Access Mgmt · §164.312(b) Audit Controls",
        "Ransomware":               "§164.308(a)(7) Contingency Plan · §164.312(a)(2)(ii) Emergency Access · §164.308(a)(6) Incident Response",
        "Supply Chain Attack":      "§164.308(b) Business Associate Contracts · §164.314(a) Business Associate Provisions",
        "Zero-Day Exploit":         "§164.308(a)(1) Risk Analysis · §164.308(a)(6) Response & Reporting · §164.306 Security Standards",
        "Denial of Service (DDoS)": "§164.308(a)(7) Contingency Plan · §164.310(a)(2)(i) Facility Contingency",
        "Credential Attack":        "§164.312(a)(2)(i) Unique User IDs · §164.312(a)(2)(iii) Automatic Logoff · §164.308(a)(5) Training",
        "Data Loss":                "§164.308(a)(7) Contingency Plan · §164.312(c)(1) Integrity Controls · §164.312(d) Authentication",
        "Privilege Escalation":     "§164.312(a)(1) Access Control · §164.308(a)(4) Information Access Mgmt · §164.312(b) Audit Controls",
        "API Abuse":                "§164.312(a)(1) Access Control · §164.312(b) Audit Controls · §164.308(a)(6) Incident Response",
    }
    return m.get(threat, "§164.306 Security Standards · §164.308 Administrative Safeguards · §164.312 Technical Safeguards")


def get_pci_mapping(threat: str) -> str:
    """Map threat to PCI DSS v4.0 requirements."""
    m = {
        "Data Breach":              "Req 3 (Protect stored data) · Req 4 (Encrypt transmission) · Req 10 (Log & monitor access)",
        "Unauthorized Access":      "Req 7 (Restrict access by need) · Req 8 (Identify & authenticate) · Req 10 (Log & monitor)",
        "Malware":                  "Req 5 (Protect against malware) · Req 6 (Secure systems & software) · Req 12 (Security policy)",
        "Phishing":                 "Req 5 (Anti-malware) · Req 8 (Strong authentication) · Req 12.6 (Security awareness)",
        "Misconfiguration":         "Req 2 (Secure configs) · Req 6 (Secure systems) · Req 11 (Test security systems)",
        "Insider Threat":           "Req 7 (Restrict access) · Req 8 (Unique IDs) · Req 10 (Log & monitor all access)",
        "Ransomware":               "Req 5 (Anti-malware) · Req 10 (Logging) · Req 12.10 (Incident response)",
        "Supply Chain Attack":      "Req 6.3 (Manage security vulnerabilities) · Req 12.8 (Third-party risk management)",
        "Zero-Day Exploit":         "Req 6 (Secure development) · Req 11 (Penetration testing) · Req 12.10 (Incident response)",
        "Denial of Service (DDoS)": "Req 1 (Network controls) · Req 12.10 (Incident response plan)",
        "Credential Attack":        "Req 8 (Identify & authenticate users) · Req 8.3 (MFA) · Req 10 (Track & monitor)",
        "Data Loss":                "Req 3 (Protect stored data) · Req 9 (Restrict physical access) · Req 10 (Logging)",
        "Privilege Escalation":     "Req 7 (Restrict by business need) · Req 8 (Auth management) · Req 10 (Audit logs)",
        "API Abuse":                "Req 6 (Secure software) · Req 8 (Authentication) · Req 10 (Monitor & log)",
    }
    return m.get(threat, "Req 1 (Network controls) · Req 6 (Secure systems) · Req 12 (Security policy)")


def get_gdpr_mapping(threat: str) -> str:
    """Map threat to GDPR articles most relevant for small businesses with EU customers."""
    m = {
        "Data Breach":              "Art 32 (Security measures) · Art 33 (72hr breach notification) · Art 34 (Notify affected individuals)",
        "Unauthorized Access":      "Art 5(1)(f) Integrity & confidentiality · Art 32 (Security measures) · Art 25 (Privacy by design)",
        "Malware":                  "Art 32 (Security of processing) · Art 33 (Breach notification) · Art 5(1)(f) Confidentiality",
        "Phishing":                 "Art 32 (Appropriate security measures) · Art 5(1)(f) Integrity & confidentiality",
        "Misconfiguration":         "Art 25 (Data protection by design & default) · Art 32 (Technical measures)",
        "Insider Threat":           "Art 5(1)(f) Integrity & confidentiality · Art 32 (Security) · Art 29 (Processor instructions)",
        "Ransomware":               "Art 32 (Security measures) · Art 33 (Breach notification ≤72 hrs) · Art 34 (Communication to data subjects)",
        "Supply Chain Attack":      "Art 28 (Processor agreements) · Art 32 (Security) · Art 44 (International transfers)",
        "Zero-Day Exploit":         "Art 32 (Security of processing) · Art 33 (Breach notification) · Art 25 (Privacy by design)",
        "Denial of Service (DDoS)": "Art 32(1)(b) Ensure ongoing availability · Art 5(1)(f) Integrity & confidentiality",
        "Credential Attack":        "Art 32 (Technical security measures) · Art 5(1)(f) Confidentiality · Art 25 (Privacy by design)",
        "Data Loss":                "Art 5(1)(e) Storage limitation · Art 32 (Security) · Art 33 (Breach notification)",
        "Privilege Escalation":     "Art 5(1)(f) Integrity & confidentiality · Art 32 (Security) · Art 25 (Privacy by design)",
        "API Abuse":                "Art 32 (Security measures) · Art 25 (Data protection by design) · Art 5(1)(f) Confidentiality",
    }
    return m.get(threat, "Art 5 (Principles) · Art 25 (Privacy by design) · Art 32 (Security measures)")


def get_ccpa_mapping(threat: str) -> str:
    """Map threat to CCPA/CPRA obligations relevant for small businesses with CA customers."""
    m = {
        "Data Breach":              "§1798.150 Private right of action for data breach · §1798.81.5 Reasonable security · Breach notification",
        "Unauthorized Access":      "§1798.100 Right to know · §1798.81.5 Reasonable security procedures",
        "Malware":                  "§1798.81.5 Reasonable security · §1798.150 Statutory damages for breach",
        "Phishing":                 "§1798.81.5 Reasonable security measures · §1798.150 Data breach liability",
        "Misconfiguration":         "§1798.81.5 Reasonable security · §1798.100 Transparency about data collected",
        "Insider Threat":           "§1798.81.5 Reasonable security · §1798.100 Right to know what data is collected",
        "Ransomware":               "§1798.150 Private right of action · §1798.81.5 Reasonable security · Breach notification",
        "Supply Chain Attack":      "§1798.140 Service provider agreements · §1798.100 Disclosure of third parties",
        "Zero-Day Exploit":         "§1798.81.5 Reasonable security measures · §1798.150 Breach liability",
        "Denial of Service (DDoS)": "§1798.81.5 Reasonable security · Business continuity for consumer services",
        "Credential Attack":        "§1798.81.5 Reasonable security · §1798.150 Statutory damages",
        "Data Loss":                "§1798.81.5 Reasonable security · §1798.100 Right to access data held",
        "Privilege Escalation":     "§1798.81.5 Reasonable security procedures · §1798.150 Breach liability",
        "API Abuse":                "§1798.81.5 Reasonable security · §1798.100 Right to know about data sharing",
    }
    return m.get(threat, "§1798.81.5 Reasonable security · §1798.100 Right to know · §1798.105 Right to delete")


def get_framework_plain_english(threat: str, framework: str) -> str:
    """Return a plain-English sentence explaining what this framework requires for this threat.
    Written for a non-specialist small business owner, not a compliance expert."""
    explanations: dict[str, dict[str, str]] = {
        "HIPAA": {
            "Data Breach":         "If health info leaks, you must notify patients and the government within 60 days - and possibly pay fines.",
            "Unauthorized Access": "Only staff who need patient data to do their job should be able to see it.",
            "Malware":             "You need to protect systems that hold health records from viruses and hacking tools.",
            "Phishing":            "Staff must be trained to spot fake emails that could expose patient data.",
            "Misconfiguration":    "Health record systems must be set up securely - default settings are often not enough.",
            "Ransomware":          "You must have a recovery plan so patient care isn't disrupted if systems are locked.",
            "Supply Chain Attack": "Every vendor who touches patient data must sign a Business Associate Agreement.",
            "Insider Threat":      "You must monitor who accesses patient records and flag unusual access patterns.",
            "Data Loss":           "You must back up patient data and be able to recover it quickly.",
            "Credential Attack":   "Every person accessing health records needs a unique login - no shared passwords.",
        },
        "PCI DSS": {
            "Data Breach":         "If card data leaks, you face heavy fines and may lose the ability to accept card payments.",
            "Unauthorized Access": "Only staff who need card data to do their job should ever see it.",
            "Malware":             "All systems that touch card payments must have up-to-date anti-malware protection.",
            "Phishing":            "Staff must be trained to avoid phishing attempts that could expose payment systems.",
            "Misconfiguration":    "Payment systems must use secure settings - never leave them with factory defaults.",
            "Ransomware":          "Card payment systems need a tested recovery plan if they're locked by ransomware.",
            "Supply Chain Attack": "Any third party that handles card data must meet PCI DSS standards too.",
            "Credential Attack":   "All accounts with access to payment systems must use strong, unique passwords and MFA.",
            "Data Loss":           "Card data must be backed up and recoverable - but only kept as long as legally necessary.",
            "Insider Threat":      "Log and monitor all access to card data systems to catch misuse early.",
        },
        "GDPR": {
            "Data Breach":         "If EU customer data leaks, you must notify the regulator within 72 hours - and the customer if they're at high risk.",
            "Unauthorized Access": "You must ensure only authorised people can access personal data about EU customers.",
            "Phishing":            "You must have appropriate security so staff don't inadvertently expose EU customer data.",
            "Misconfiguration":    "Systems holding EU customer data must be configured with privacy as the default, not an afterthought.",
            "Supply Chain Attack": "Any supplier who processes EU customer data on your behalf must sign a Data Processing Agreement.",
            "Ransomware":          "Ransomware that makes personal data unavailable counts as a breach - notify within 72 hours.",
            "Data Loss":           "You must not keep EU customer data longer than necessary and must be able to recover it.",
            "Insider Threat":      "You're responsible for how your staff handles EU customer data - this includes accidents.",
            "Credential Attack":   "Weak passwords exposing EU customer accounts may trigger breach notification obligations.",
            "Unauthorized Access": "You must be able to demonstrate that personal data is only accessed by authorised staff.",
        },
        "CCPA": {
            "Data Breach":         "If California customer data leaks without reasonable security, you can be sued directly - $100–$750 per person per incident.",
            "Unauthorized Access": "California customers can ask what data you hold on them at any time - you must be able to answer.",
            "Data Loss":           "California customers can ask you to delete their data - you must have a process to comply within 45 days.",
            "Supply Chain Attack": "If a vendor causes a breach of California customer data, you're still liable.",
            "Misconfiguration":    "You must implement reasonable security - vague but if you're breached without it, you face liability.",
            "Credential Attack":   "A breach caused by weak security exposes you to CCPA private right of action lawsuits.",
            "Phishing":            "Reasonable security includes training staff - a phishing breach can trigger CCPA claims.",
            "Ransomware":          "Ransomware exposing California customer data triggers CCPA breach notification and liability.",
        },
    }
    fw_map = explanations.get(framework, {})
    return fw_map.get(threat,
        f"Ensure your {framework} obligations are met for this risk area. Review with a compliance professional.")


def get_all_frameworks(threat: str) -> dict[str, str]:
    """Return all 8 framework mappings for a given threat in one call."""
    return {
        "NIST CSF 2.0":  get_nist_mapping(threat),
        "NIST RMF":      get_rmf_mapping(threat),
        "ISO 27001":     get_iso27001_mapping(threat),
        "Zero Trust":    " | ".join(get_zero_trust_guidance(threat)),
        "HIPAA":         get_hipaa_mapping(threat),
        "PCI DSS":       get_pci_mapping(threat),
        "GDPR":          get_gdpr_mapping(threat),
        "CCPA":          get_ccpa_mapping(threat),
    }


# ─────────────────────────────────────────────────────────────
# COMPLIANCE CHECKLISTS - all 8 frameworks
# ─────────────────────────────────────────────────────────────
HIPAA_CONTROLS: dict[str, list[str]] = {
    "Administrative Safeguards": [
        "Risk analysis completed and documented",
        "Risk management plan implemented",
        "Sanctions policy for workforce violations in place",
        "Security awareness and training programme active",
        "Security incident procedures documented and tested",
        "Contingency plan (backup, DR, emergency access) documented",
        "Business Associate Agreements signed with all relevant vendors",
        "Designated Security Officer assigned",
    ],
    "Physical Safeguards": [
        "Facility access controls documented",
        "Workstation use policy in place",
        "Workstations with PHI are in restricted areas",
        "Device and media controls documented (disposal, re-use policy)",
    ],
    "Technical Safeguards": [
        "Unique user identification enforced for all PHI system access",
        "Automatic logoff implemented on PHI systems",
        "Encryption of PHI at rest implemented",
        "Encryption of PHI in transit implemented",
        "Audit controls in place - logs of PHI access retained",
        "Integrity controls in place to prevent unauthorised PHI alteration",
    ],
}

PCI_CONTROLS: dict[str, list[str]] = {
    "Network & Access": [
        "Firewall configured and protecting cardholder data environment",
        "Default vendor passwords changed on all system components",
        "Cardholder data encrypted in transit (TLS 1.2+)",
        "Access to cardholder data restricted to staff with business need",
        "Unique IDs assigned to each person with computer access",
        "Multi-factor authentication on all access to cardholder data environment",
        "Physical access to cardholder data restricted and logged",
    ],
    "Data Protection": [
        "Cardholder data stored only where necessary, with documented retention policy",
        "Primary account numbers (PANs) masked when displayed",
        "Encryption or tokenisation applied to stored cardholder data",
        "Cryptographic key management procedures documented",
    ],
    "Monitoring & Testing": [
        "Anti-malware deployed and actively running on all applicable systems",
        "Security patches applied within one month of release",
        "All access to cardholder data logged and monitored",
        "Logs reviewed at least daily",
        "Quarterly vulnerability scans performed",
        "Annual penetration test completed",
        "Intrusion detection / prevention system in place",
    ],
    "Policy & Incidents": [
        "Information security policy documented, distributed, and reviewed annually",
        "Incident response plan in place and tested",
        "Security awareness training delivered to all staff",
        "Third-party / vendor risk management process in place",
    ],
}

GDPR_CONTROLS: dict[str, list[str]] = {
    "Lawfulness & Transparency": [
        "Privacy notice is published, current, and accessible",
        "Lawful basis documented for each category of personal data processing",
        "Consent records maintained where consent is the lawful basis",
        "Data subjects informed of their rights in the privacy notice",
    ],
    "Data Minimisation & Retention": [
        "Only personal data necessary for the stated purpose is collected",
        "Retention periods defined and enforced for all personal data categories",
        "Deletion process in place and tested",
        "Record of processing activities (RoPA) maintained",
    ],
    "Individual Rights": [
        "Process in place to respond to Subject Access Requests within 1 month",
        "Process in place to action erasure requests within 1 month",
        "Process in place for data portability requests",
        "Process in place to handle objections to processing",
    ],
    "Security & Breach": [
        "Technical and organisational measures documented (encryption, access controls, etc.)",
        "Data breach response procedure documented",
        "Breach notification to supervisory authority within 72 hours of discovery",
        "Process to notify affected individuals when breach poses high risk",
        "Data Protection Officer designated (if required)",
    ],
    "Third Parties & Transfers": [
        "Data Processing Agreements signed with all processors",
        "International data transfers documented with appropriate safeguards",
        "Third-party processor assessments completed",
    ],
    "Privacy by Design": [
        "Data Protection Impact Assessment (DPIA) completed for high-risk processing",
        "Privacy by design applied to new systems and processes",
    ],
}

CCPA_CONTROLS: dict[str, list[str]] = {
    "Disclosures & Rights": [
        "Privacy notice includes all required CCPA disclosures",
        "'Do Not Sell or Share My Personal Information' option available",
        "Process to respond to consumer requests within 45 days",
        "Process to respond to Right to Know requests",
        "Process to respond to Right to Delete requests",
        "Process to respond to Right to Correct requests",
        "Process to respond to Right to Portability requests",
        "Non-discrimination policy in place for consumers exercising rights",
    ],
    "Data & Security": [
        "Categories of personal information collected documented",
        "Categories of third parties data is shared with documented",
        "Reasonable security measures implemented (documented)",
        "Service provider agreements include required CCPA contractual terms",
        "Employee personal information handling procedures documented",
    ],
}



def get_control_mapping(threat: str) -> list[str]:
    m = {
        "Data Breach":              ["Data encryption (at rest & in transit)", "DLP monitoring", "Access reviews & recertification", "Data classification policy"],
        "Unauthorized Access":      ["Multi-factor authentication (MFA)", "Role-based access control (RBAC)", "Access logging & alerting", "Account lifecycle management"],
        "Malware":                  ["Endpoint Detection & Response (EDR)", "Patch management programme", "Application allowlisting", "Regular malware scans"],
        "Phishing":                 ["Email filtering & anti-spoofing (DMARC/DKIM/SPF)", "Security awareness training", "MFA on all accounts", "Phishing simulation & reporting process"],
        "Misconfiguration":         ["Secure configuration baseline (CIS Benchmarks)", "Cloud Security Posture Management (CSPM)", "Peer-reviewed change management", "Periodic configuration review"],
        "Insider Threat":           ["Least-privilege access controls", "User & Entity Behaviour Analytics (UEBA)", "Separation of duties", "Quarterly access recertification"],
        "Ransomware":               ["Immutable / air-gapped backups", "Network micro-segmentation", "EDR with ransomware behavioural detection", "Tested incident response plan"],
        "Supply Chain Attack":      ["Vendor security assessments (questionnaire + evidence)", "Contractual security requirements", "Third-party access control & monitoring", "Software bill of materials (SBOM) review"],
        "Zero-Day Exploit":         ["Threat intelligence programme", "Compensating controls while patch is unavailable", "Network segmentation to limit blast radius", "Rapid patch deployment process"],
        "Denial of Service (DDoS)": ["DDoS scrubbing / CDN protection", "Rate limiting on public endpoints", "Failover and redundancy planning", "Traffic anomaly monitoring"],
        "Credential Attack":        ["Phishing-resistant MFA (FIDO2)", "Password policy & breach-credential checks", "Abnormal login monitoring & lockout", "Disable stale & service accounts"],
        "Data Loss":                ["Tested and versioned backups", "Retention and deletion policies", "Bulk-delete approval workflow", "Recovery testing schedule"],
        "Privilege Escalation":     ["Privileged Access Management (PAM)", "Just-in-time privilege provisioning", "Privilege change alerting", "Timely patching of escalation CVEs"],
        "API Abuse":                ["API authentication & authorisation (OAuth2/OIDC)", "Rate limiting & quota enforcement", "API token governance and rotation", "API activity monitoring & anomaly detection"],
    }
    return m.get(threat, ["Risk review", "Control owner assignment", "Periodic monitoring"])


def business_impact(threat: str, asset: str, industry: str) -> str:
    base: dict[str, str] = {
        "Data Breach":              f"Sensitive information held in the {asset.lower()} may be exposed, creating legal liability, reputational harm, financial penalties, and compliance consequences.",
        "Unauthorized Access":      f"Unauthorised users may gain entry to the {asset.lower()}, leading to data misuse, operational disruption, or further lateral compromise.",
        "Malware":                  f"Malicious software may disrupt the {asset.lower()}, reduce productivity, corrupt data, or propagate across connected systems.",
        "Phishing":                 f"Employees may unwittingly disclose credentials or approve fraudulent requests, significantly increasing the probability of account compromise.",
        "Misconfiguration":         f"Incorrect settings on the {asset.lower()} may expose systems or data without detection, often for extended periods.",
        "Insider Threat":           f"A trusted internal user may misuse legitimate access to the {asset.lower()}, producing high business, reputational, and legal impact.",
        "Ransomware":               f"The {asset.lower()} may become encrypted and unavailable, causing downtime, recovery costs, and potential business interruption.",
        "Supply Chain Attack":      f"A vendor or software dependency supplying the {asset.lower()} may introduce malicious code or a backdoor, affecting trust and operations across the supply chain.",
        "Zero-Day Exploit":         f"An unknown vulnerability may be exploited in the {asset.lower()} before any patch or detection signature is available.",
        "Denial of Service (DDoS)": f"The {asset.lower()} may become unavailable during an attack, causing service disruption, customer dissatisfaction, and potential SLA breach.",
        "Credential Attack":        f"Compromised credentials may allow attackers to access the {asset.lower()} and move laterally through the environment.",
        "Data Loss":                f"Critical information held in the {asset.lower()} may be permanently deleted, corrupted, or become unrecoverable.",
        "Privilege Escalation":     f"An attacker may gain elevated permissions within the {asset.lower()}, enabling access to sensitive systems and data.",
        "API Abuse":                f"APIs exposed by the {asset.lower()} may be misused to exfiltrate data, disrupt services, or perform unauthorised operations.",
    }
    desc = base.get(threat, f"The {asset.lower()} may be affected, creating operational or security risk to the organisation.")

    industry_suffix: dict[str, str] = {
        "Healthcare":      " In healthcare, this may also affect patient safety, care continuity, and HIPAA/IG compliance obligations.",
        "Finance":         " In financial services, this may increase fraud exposure, regulatory censure (PCI DSS, SOX), and customer confidence risk.",
        "Education":       " In education, this may affect student/faculty data, research integrity, and institutional trust under FERPA.",
        "Manufacturing":   " In manufacturing, this may affect production uptime, worker safety, and OT/ICS operational continuity.",
        "Technology":      " In a technology firm, this may also undermine customer trust, product SLAs, and competitive advantage.",
        "Retail":          " In retail, this may affect PCI DSS compliance, customer PII, and brand reputation at scale.",
    }
    return desc + industry_suffix.get(industry, "")


def build_business_impact_analysis(
    base: str,
    financial: str,
    operational: str,
    compliance: str,
    process: str,
) -> str:
    return (
        f"{base}\n\n"
        f"Business Impact Analysis - affected process: '{process}'. "
        f"Financial impact: {financial}. "
        f"Operational impact: {operational}. "
        f"Compliance / regulatory impact: {compliance}."
    )


def get_recommendations(threat: str) -> list[str]:
    m = {
        "Data Breach":              ["Encrypt all sensitive data at rest and in transit.", "Apply and audit least-privilege access.", "Enable real-time monitoring and alerting on data stores.", "Review and enforce data retention policies."],
        "Unauthorized Access":      ["Enable phishing-resistant MFA across all accounts.", "Audit and tighten access permissions.", "Monitor for abnormal login patterns.", "Enforce role-based access control (RBAC)."],
        "Malware":                  ["Deploy endpoint detection and response (EDR).", "Maintain a patching cadence for all systems.", "Restrict local administrator rights.", "Run regular scheduled malware scans."],
        "Phishing":                 ["Deliver targeted security awareness training.", "Implement email filtering with DMARC/DKIM/SPF.", "Enable MFA on all user accounts.", "Create and publicise a phishing report process."],
        "Misconfiguration":         ["Apply CIS Benchmark secure configuration baselines.", "Perform scheduled configuration review and drift detection.", "Automate compliance checks in CI/CD pipelines.", "Restrict administrative access to configuration tools."],
        "Insider Threat":           ["Conduct quarterly access rights reviews.", "Monitor unusual or off-hours data access.", "Apply separation of duties on sensitive processes.", "Establish anonymous reporting channels."],
        "Ransomware":               ["Maintain tested, air-gapped, and versioned backups.", "Exercise and document a ransomware response playbook.", "Patch critical and internet-facing systems urgently.", "Segment the network to limit lateral spread."],
        "Supply Chain Attack":      ["Perform security assessments on all key vendors.", "Restrict third-party access to minimum required scope.", "Embed security requirements into supplier contracts.", "Monitor dependencies for known vulnerabilities (SCA)."],
        "Zero-Day Exploit":         ["Deploy layered defences - no single point of failure.", "Monitor for anomalous behaviour that may indicate exploitation.", "Segment critical systems to contain blast radius.", "Establish an emergency patch deployment process."],
        "Denial of Service (DDoS)": ["Implement DDoS scrubbing or CDN-based protection.", "Apply rate limiting on all public-facing endpoints.", "Develop and test a failover and recovery plan.", "Monitor traffic anomalies in real time."],
        "Credential Attack":        ["Mandate phishing-resistant MFA (FIDO2/passkeys).", "Monitor and block brute-force and credential-stuffing attempts.", "Enforce a strong password policy with breach-credential checks.", "Disable dormant and stale accounts promptly."],
        "Data Loss":                ["Maintain automated, tested, and versioned backups.", "Restrict bulk-delete operations with approval workflows.", "Use data versioning and soft-delete where available.", "Schedule and document recovery testing quarterly."],
        "Privilege Escalation":     ["Remove standing admin rights - use just-in-time access.", "Deploy a Privileged Access Management (PAM) solution.", "Alert immediately on any privilege-change events.", "Prioritise patching of privilege escalation CVEs."],
        "API Abuse":                ["Require authentication and authorisation on every API call.", "Enforce rate limits and quotas per API consumer.", "Audit and rotate API tokens on a defined schedule.", "Monitor API request patterns for anomalies."],
    }
    return m.get(threat, ["Conduct a full risk review.", "Assign a named control owner.", "Implement monitoring and set a review date."])


def suggest_treatment(threat: str, score: int) -> tuple[str, str]:
    if score >= 20:
        return "Mitigate",  "Critical residual risk demands immediate control improvements."
    if score >= 13:
        return "Mitigate",  "High residual risk should be reduced through prioritised remediation."
    if score >= 7:
        if threat in ("Supply Chain Attack", "Denial of Service (DDoS)"):
            return "Transfer", "Residual risk may be partially transferred through vendor contracts or cyber insurance."
        return "Mitigate",    "Medium risk should be addressed within a planned remediation cycle."
    return "Accept",          "Low residual risk may be accepted - document rationale and monitor."


def get_treatment_actions(treatment: str, score: int) -> list[str]:
    base: dict[str, list[str]] = {
        "Mitigate": ["Assign a named remediation owner with a due date.", "Implement or improve the mapped controls.", "Schedule a risk re-assessment after remediation.", "Track progress in the risk register."],
        "Accept":   ["Document the acceptance rationale formally.", "Obtain written sign-off from the risk owner.", "Set a future review date (no longer than 12 months).", "Continue monitoring for changes in the threat landscape."],
        "Transfer": ["Evaluate vendor, insurance, and contractual risk transfer options.", "Confirm contractual security obligations are legally binding.", "Monitor the remaining residual risk after transfer.", "Document the transfer decision and responsible parties."],
        "Avoid":    ["Cease or redesign the risky business activity.", "Identify and implement safer alternative approaches.", "Document the business trade-offs and decision rationale.", "Obtain leadership approval for the change in approach."],
    }
    actions = list(base.get(treatment, ["Document the risk decision."]))
    if score >= 13:
        actions.append("Escalate to the security governance committee or CISO.")
    return actions


def get_audit_recommendation(audit_status: str) -> str:
    m = {
        "Evidence Missing":         "Evidence is missing. Request screenshots, scan output, ticket references, policy documents, or log extracts before scheduling audit review.",
        "Needs Review":             "Evidence exists but requires validation by the control owner or an internal auditor before the risk can be closed.",
        "Remediation In Progress":  "Track remediation progress, target completion date, and any compensating controls in place during the remediation window.",
        "Audit Ready":              "Evidence appears complete. Confirm version currency, named owner, and review date before presenting to the auditor.",
    }
    return m.get(audit_status, "Audit status should be reviewed and updated to reflect the current state of evidence and control testing.")


def get_maturity_hint(threat: str, asset: str, control_effectiveness: int) -> str:
    if control_effectiveness <= 2:
        maturity = "low control maturity - foundational controls are missing or ineffective"
    elif control_effectiveness == 3:
        maturity = "moderate control maturity - baseline controls exist but are not consistently applied or tested"
    else:
        maturity = "stronger control maturity - controls are in place and demonstrate evidence of effectiveness"
    return (
        f"The {asset.lower()} currently shows {maturity}. "
        f"Strengthening the mapped controls and improving audit evidence quality will directly reduce the residual risk score."
    )


def get_heatmap_summary(likelihood: int, impact: int) -> str:
    raw = likelihood * impact
    zone = "Critical" if raw >= 20 else "High" if raw >= 13 else "Medium" if raw >= 7 else "Low"
    return f"Likelihood {likelihood}/5 × Impact {impact}/5 = {raw}/25 - positioned in the {zone} Zone."


def get_assumptions_limitations() -> list[str]:
    return [
        "This platform is a decision-support tool and does not replace formal audit, legal, or compliance review.",
        "Risk scoring uses a two-stage model (Inherent Risk → Residual Risk) aligned with NIST SP 800-30 Rev 1 and ISO 27005:2022. It does not perform live threat intelligence queries.",
        "Final decisions should be reviewed and approved by security, compliance, IT, and business stakeholders.",
        "Smart Mode AI analysis should be validated for high-impact or regulated environments before acting on it.",
        "Risk scores should be reviewed periodically as threats, assets, controls, regulations, and business context change.",
        "Asset value and control effectiveness ratings are subjective - calibrate them against internal standards and test results.",
    ]


# ─────────────────────────────────────────────────────────────
# FALLBACK & AI ANALYSIS
# ─────────────────────────────────────────────────────────────
def fallback_detect(description: str) -> tuple[str, str]:
    desc = description.lower()

    asset_rules: list[tuple[str, list[str]]] = [
        ("Endpoint / Laptop",  ["laptop", "computer", "device", "workstation", "stolen laptop"]),
        ("Email System",       ["email", "mail", "inbox", "message", "phishing email"]),
        ("User Credentials",   ["password", "credentials", "login", "account", "shared their password"]),
        ("Customer Portal",    ["website", "portal", "customer portal", "site"]),
        ("Finance System",     ["finance", "billing", "invoice", "payroll"]),
        ("HR System",          ["hr", "employee", "personnel"]),
        ("Vendor / Third Party", ["vendor", "third party", "contractor", "supplier", "third-party"]),
        ("Database",           ["database", "records", "client data", "customer data"]),
        ("Cloud Environment",  ["cloud", "aws", "azure", "gcp", "s3", "bucket"]),
        ("API",                ["api", "endpoint", "token", "rest"]),
        ("Backup System",      ["backup", "restore", "recovery"]),
        ("Network",            ["network", "traffic", "router", "firewall"]),
        ("Server",             ["server", "host", "vm", "virtual machine"]),
    ]
    threat_rules: list[tuple[str, list[str]]] = [
        ("Phishing",                ["suspicious email", "clicked a link", "fake email", "verify payroll", "phishing"]),
        ("Data Breach",             ["data breach", "exposed", "leaked", "client data", "customer data", "sensitive"]),
        ("Unauthorized Access",     ["stolen", "someone accessed", "unauthorized", "shared password", "shared their password"]),
        ("Credential Attack",       ["brute force", "password spray", "login attempt", "credential"]),
        ("Denial of Service (DDoS)",["traffic spike", "website went down", "outage", "ddos", "flood"]),
        ("Ransomware",              ["encrypted", "locked", "ransomware", "ransom"]),
        ("Data Loss",               ["deleted", "lost records", "missing files", "accidentally deleted"]),
        ("Malware",                 ["acting strange", "infected", "virus", "malware", "trojan"]),
        ("Supply Chain Attack",     ["vendor", "third party", "supplier had a breach", "dependency"]),
        ("Misconfiguration",        ["misconfiguration", "open access", "public bucket", "exposed port"]),
        ("Insider Threat",          ["insider", "employee misuse", "internal user", "rogue employee"]),
    ]

    detected_asset  = next((a for a, kws in asset_rules  if any(kw in desc for kw in kws)), "Application")
    detected_threat = next((t for t, kws in threat_rules if any(kw in desc for kw in kws)), "Unauthorized Access")

    valid_threats = safe_threats_for_asset(detected_asset)
    if detected_threat not in valid_threats:
        detected_threat = valid_threats[0]

    return detected_asset, detected_threat


def ai_analyze_description(description: str) -> dict | None:
    """
    Call Claude via Anthropic API. Returns parsed dict or None on any failure.
    Uses the correct model string and handles all error paths explicitly.
    """
    if not _ANTHROPIC_AVAILABLE:
        return None
    if not os.environ.get("ANTHROPIC_API_KEY"):
        return None

    system_prompt = f"""You are a senior GRC and cybersecurity risk analyst.
Analyse the user's description and return ONLY a single valid JSON object - no markdown, no backticks, no preamble.

Select asset from this exact list:
{json.dumps(ASSET_OPTIONS)}

Select threat from this exact list:
{json.dumps(THREAT_OPTIONS)}

Required JSON schema:
{{
  "asset": "<exact string from asset list>",
  "threat": "<exact string from threat list>",
  "likelihood": <integer 1-5>,
  "impact": <integer 1-5>,
  "plain_english_summary": "<2-3 sentence business-friendly summary for a non-technical audience>",
  "actions": [
    {{"tag": "Do now",    "text": "<specific immediate action>"}},
    {{"tag": "This week", "text": "<specific short-term action>"}},
    {{"tag": "Document",  "text": "<what should be formally documented>"}}
  ],
  "confidence": "<low|medium|high>"
}}"""

    try:
        client = Anthropic()
        response = client.messages.create(
            model=MODEL_ID,
            max_tokens=900,
            system=system_prompt,
            messages=[{"role": "user", "content": description[:2000]}],  # cap input
        )
        raw_text = response.content[0].text.strip()
        # Strip any accidental markdown fences
        if raw_text.startswith("```"):
            raw_text = raw_text.split("```")[1]
            if raw_text.startswith("json"):
                raw_text = raw_text[4:]
        return json.loads(raw_text)
    except json.JSONDecodeError:
        return None
    except Exception:
        return None


# ─────────────────────────────────────────────────────────────
# VALIDATION
# ─────────────────────────────────────────────────────────────
def validate_inputs(
    asset_value: int,
    control_effectiveness: int,
    audit_status: str,
    evidence_name: str,
    vulnerability_severity: str,
) -> list[str]:
    warnings: list[str] = []
    if not 1 <= asset_value <= 5:
        warnings.append("Asset Value must be between 1 and 5.")
    if not 1 <= control_effectiveness <= 5:
        warnings.append("Control Effectiveness must be between 1 and 5.")
    if audit_status == "Audit Ready" and evidence_name == "No evidence uploaded":
        warnings.append("'Audit Ready' selected but no evidence file has been uploaded. Attach evidence before claiming audit readiness.")
    if vulnerability_severity == "Critical" and asset_value <= 2:
        warnings.append("A Critical vulnerability is linked to an asset with low business value. Confirm the asset value rating is accurate.")
    return warnings


def check_for_duplicate(asset: str, threat: str) -> bool:
    fp = _risk_fingerprint(asset, threat)
    return any(_risk_fingerprint(r["Asset"], r["Threat"]) == fp for r in st.session_state.history)


# ─────────────────────────────────────────────────────────────
# PERMISSIONS
# ─────────────────────────────────────────────────────────────
ROLE_PERMISSIONS: dict[str, dict] = {
    "Admin":   {"can_edit": True,  "can_save": True,  "can_export": True,  "can_clear": True,  "description": "Full access: create, edit, export, and clear risks."},
    "Manager": {"can_edit": True,  "can_save": True,  "can_export": True,  "can_clear": False, "description": "Can assess, save, and export - cannot clear the register."},
    "Viewer":  {"can_edit": False, "can_save": False, "can_export": True,  "can_clear": False, "description": "Read-only: dashboards and export only."},
}

def get_role_permissions(role: str) -> dict:
    return ROLE_PERMISSIONS.get(role, ROLE_PERMISSIONS["Viewer"])


# ─────────────────────────────────────────────────────────────
# INTEGRATION HEALTH
# ─────────────────────────────────────────────────────────────
def get_integration_health() -> dict[str, tuple[str, str]]:
    has_key = bool(os.environ.get("ANTHROPIC_API_KEY"))
    smart_ok = _ANTHROPIC_AVAILABLE and has_key
    return {
        "Smart AI Analysis": (
            "Ready" if smart_ok else "Fallback Mode",
            "Claude AI is active." if smart_ok else "Rule-based fallback active. Set ANTHROPIC_API_KEY to enable AI."
        ),
        "Nessus": ("Manual Link", "Link findings manually by CVE/plugin ID, severity, and asset name."),
        "Splunk":  ("Manual Evidence", "Upload Splunk alert exports or log extracts as evidence files."),
    }


# ─────────────────────────────────────────────────────────────
# HEATMAP
# ─────────────────────────────────────────────────────────────
def create_heatmap_plotly(likelihood: int, impact: int) -> go.Figure:
    """
    Native Plotly heatmap - vector-quality at any resolution, matches app design system.
    Returns a go.Figure that renders inline via st.plotly_chart().
    """
    # 5×5 matrix: rows = impact 5→1, cols = likelihood 1→5
    z = [[i * j for j in range(1, 6)] for i in range(5, 0, -1)]
    text = [[str(i * j) for j in range(1, 6)] for i in range(5, 0, -1)]

    # Colour scale: green → yellow → red (matches risk levels)
    colorscale = [
        [0.0,  "#DCFCE7"],  # 1  - Low green
        [0.24, "#86EFAC"],  # 6
        [0.28, "#FEF9C3"],  # 7  - Medium yellow
        [0.52, "#FDE047"],  # 13
        [0.52, "#FEE2E2"],  # 13 - High red
        [0.80, "#FCA5A5"],  # 20
        [0.80, "#991B1B"],  # 20 - Critical dark red
        [1.0,  "#7F1D1D"],  # 25
    ]

    # Marker: current risk position (col = L-1, row = 5-I from top)
    marker_x = likelihood - 1
    marker_y = 5 - impact  # row index from top (impact 5 = row 0)

    fig = go.Figure()

    # Heatmap layer
    fig.add_trace(go.Heatmap(
        z=z,
        text=text,
        texttemplate="%{text}",
        textfont={"size": 13, "family": "IBM Plex Mono, monospace", "color": "white"},
        colorscale=colorscale,
        zmin=1, zmax=25,
        showscale=False,
        xgap=2, ygap=2,
        hovertemplate="Likelihood: %{x}<br>Impact: %{y}<br>Score: %{text}<extra></extra>",
    ))

    # Cell text colour: white for dark cells, dark for light cells
    for row_i in range(5):
        for col_i in range(5):
            val = z[row_i][col_i]
            txt_color = "white" if val >= 7 else "#1E293B"
            fig.add_annotation(
                x=col_i, y=row_i, text=str(val),
                showarrow=False, font=dict(size=13, family="IBM Plex Mono, monospace", color=txt_color),
                xref="x", yref="y"
            )

    # Risk position marker
    fig.add_trace(go.Scatter(
        x=[marker_x], y=[marker_y],
        mode="markers",
        marker=dict(
            symbol="circle",
            size=28,
            color="rgba(0,0,0,0)",
            line=dict(color="#0F172A", width=3),
        ),
        hovertemplate=f"Current risk<br>L={likelihood}, I={impact}<extra></extra>",
        showlegend=False,
    ))
    fig.add_trace(go.Scatter(
        x=[marker_x], y=[marker_y],
        mode="markers",
        marker=dict(symbol="circle", size=10, color="#0F172A"),
        showlegend=False,
        hoverinfo="skip",
    ))

    fig.update_layout(
        height=320,
        margin=dict(l=60, r=20, t=50, b=60),
        plot_bgcolor="#F8FAFC",
        paper_bgcolor="#F8FAFC",
        title=dict(text="Risk Heatmap", font=dict(family="IBM Plex Sans, sans-serif", size=14, color="#0F172A"), x=0.5, xanchor="center"),
        xaxis=dict(
            tickvals=list(range(5)),
            ticktext=["1", "2", "3", "4", "5"],
            title=dict(text="Likelihood →", font=dict(size=12, family="IBM Plex Sans, sans-serif")),
            fixedrange=True, showgrid=False, zeroline=False,
        ),
        yaxis=dict(
            tickvals=list(range(5)),
            ticktext=["5", "4", "3", "2", "1"],
            title=dict(text="← Impact", font=dict(size=12, family="IBM Plex Sans, sans-serif")),
            fixedrange=True, showgrid=False, zeroline=False, autorange="reversed",
        ),
        font=dict(family="IBM Plex Sans, sans-serif"),
    )
    return fig


def create_heatmap(likelihood: int, impact: int) -> plt.Figure:
    """Kept for PDF export only - not used in UI."""
    matrix = [[i * j for i in range(1, 6)] for j in range(5, 0, -1)]
    fig, ax = plt.subplots(figsize=(5.5, 4.0), dpi=200)
    ax.imshow(matrix, cmap="RdYlGn_r", interpolation="nearest", aspect="auto", vmin=1, vmax=25)
    for y in range(5):
        for x in range(5):
            val = matrix[y][x]
            txt_color = "white" if val >= 7 else "#111827"
            ax.text(x, y, str(val), ha="center", va="center",
                    fontsize=10, fontweight="bold", color=txt_color, fontfamily="monospace")
    px_m, py_m = likelihood - 1, 5 - impact
    ax.scatter(px_m, py_m, s=350, marker="o", facecolors="none", edgecolors="#111827", linewidths=2.5, zorder=5)
    ax.scatter(px_m, py_m, s=75, marker="o", color="#111827", zorder=6)
    ax.set_xticks(range(5)); ax.set_xticklabels(["1","2","3","4","5"], fontsize=10)
    ax.set_yticks(range(5)); ax.set_yticklabels(["5","4","3","2","1"], fontsize=10)
    ax.set_xlabel("Likelihood →", fontsize=10, fontweight="bold")
    ax.set_ylabel("← Impact", fontsize=10, fontweight="bold")
    ax.set_title("Risk Heatmap", fontsize=11, fontweight="bold", pad=8)
    ax.set_xticks([x-0.5 for x in range(1,5)], minor=True)
    ax.set_yticks([y-0.5 for y in range(1,5)], minor=True)
    ax.grid(which="minor", color="white", linestyle="-", linewidth=1.2)
    ax.tick_params(which="minor", bottom=False, left=False)
    for spine in ax.spines.values(): spine.set_visible(False)
    fig.patch.set_facecolor("#F8FAFC")
    fig.tight_layout()
    return fig


def create_heatmap_image(likelihood: int, impact: int) -> str:
    fig = create_heatmap(likelihood, impact)
    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".png", prefix="grc_heatmap_")
    fig.savefig(tmp.name, bbox_inches="tight", dpi=200)
    plt.close(fig)
    st.session_state["_temp_files"].append(tmp.name)
    return tmp.name


# ─────────────────────────────────────────────────────────────
# DEMO DATA
# ─────────────────────────────────────────────────────────────
def build_demo_risk() -> dict:
    asset, threat = "Email System", "Phishing"
    av, ce = 4, 3
    likelihood, impact, reasons = calculate_auto_scores(asset, threat)
    inherent, residual = calculate_risks(likelihood, impact, av, ce)
    level, emoji, color = risk_level(residual)
    priority, p_reason = get_priority_flag(residual)
    treatment, t_reason = suggest_treatment(threat, residual)
    return {
        "Company / Unit":       "Demo Organisation",
        "Report Type":          "Enterprise GRC Risk Assessment",
        "Industry":             "General",
        "Department":           "Information Technology",
        "Risk Owner":           "Security / IT Team",
        "Status":               "Open",
        "Review Date":          str(date.today()),
        "Asset":                asset,
        "Threat":               threat,
        "Likelihood":           likelihood,
        "Impact":               impact,
        "Asset Value":          av,
        "Control Effectiveness": ce,
        "Inherent Risk":        inherent,
        "Residual Risk":        residual,
        "Residual Level":       level,
        "Heatmap Summary":      get_heatmap_summary(likelihood, impact),
        "Residual Emoji":       emoji,
        "Residual Color":       color,
        "Priority":             priority,
        "Priority Rationale":   p_reason,
        "Final Treatment":      treatment,
        "Suggested Treatment":  treatment,
        "Treatment Reason":     t_reason,
        "Business Impact":      build_business_impact_analysis(
                                    business_impact(threat, asset, "General"),
                                    "Medium", "Medium", "Medium",
                                    "Employee communication and operations"
                                ),
        "Financial Impact":     "Medium",
        "Operational Impact":   "Medium",
        "Compliance Impact":    "Medium",
        "Affected Business Process": "Employee communication and operations",
        "Plain English Summary": (
            "Phishing attacks targeting the email system are a high-frequency, medium-impact threat. "
            "Employees may be tricked into revealing credentials or approving fraudulent transactions. "
            "Strengthening email filtering, enabling phishing-resistant MFA, and running regular training are the highest-value controls."
        ),
        "AI Actions": [
            {"tag": "Do now",    "text": "Verify all accounts at risk have MFA enabled."},
            {"tag": "This week", "text": "Run a phishing simulation and review fail rates."},
            {"tag": "Document",  "text": "Record control effectiveness and evidence in the risk register."},
        ],
        "NIST Mapping":         get_nist_mapping(threat),
        "RMF Mapping":          get_rmf_mapping(threat),
        "ISO 27001 Mapping":    get_iso27001_mapping(threat),
        "Mapped Controls":      " | ".join(get_control_mapping(threat)),
        "Zero Trust Guidance":  " | ".join(get_zero_trust_guidance(threat)),
        "Recommended Controls": " | ".join(get_recommendations(threat)),
        "Next Steps":           " | ".join(get_treatment_actions(treatment, residual)),
        "Vulnerability / Finding": "Phishing simulation failure rate above 15% threshold",
        "Vulnerability Severity":  "Medium",
        "Finding Source":          "Phishing Simulation Platform",
        "Evidence File":           "phishing_sim_q1_results.csv (demo)",
        "Evidence Owner":          "Security Awareness Lead",
        "Audit Status":            "Needs Review",
        "Audit Recommendation":    get_audit_recommendation("Needs Review"),
        "Maturity Hint":           get_maturity_hint(threat, asset, ce),
        "Confidence":              "high",
        "Scoring Notes":           " | ".join(reasons),
    }


# ─────────────────────────────────────────────────────────────
# REPORTING
# ─────────────────────────────────────────────────────────────
def _page_decoration(canvas, doc):
    canvas.saveState()
    canvas.setFont("Helvetica-Bold", 9.5)
    canvas.setFillColor(colors.HexColor("#1E3A5F"))
    canvas.drawString(50, 762, "Enterprise GRC Risk Intelligence Platform")
    canvas.setStrokeColor(colors.HexColor("#CBD5E1"))
    canvas.setLineWidth(0.5)
    canvas.line(50, 758, 562, 758)
    canvas.setFont("Helvetica", 8.5)
    canvas.setFillColor(colors.HexColor("#64748B"))
    canvas.drawString(50, 28, f"Confidential - Generated {datetime.now().strftime('%Y-%m-%d %H:%M')} UTC")
    canvas.drawRightString(562, 28, f"Page {doc.page}")
    canvas.line(50, 38, 562, 38)
    canvas.restoreState()


def _pdf_table(data: list, widths: list) -> Table:
    t = Table(data, colWidths=widths)
    t.setStyle(TableStyle([
        ("BACKGROUND",   (0, 0), (-1, 0),  colors.HexColor("#1E3A5F")),
        ("TEXTCOLOR",    (0, 0), (-1, 0),  colors.white),
        ("FONTNAME",     (0, 0), (-1, 0),  "Helvetica-Bold"),
        ("FONTSIZE",     (0, 0), (-1, -1), 9),
        ("GRID",         (0, 0), (-1, -1), 0.35, colors.HexColor("#CBD5E1")),
        ("BACKGROUND",   (0, 1), (-1, -1), colors.HexColor("#F8FAFC")),
        ("ROWBACKGROUNDS",(0, 1), (-1, -1), [colors.white, colors.HexColor("#F1F5F9")]),
        ("VALIGN",       (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING",  (0, 0), (-1, -1), 7),
        ("RIGHTPADDING", (0, 0), (-1, -1), 7),
        ("TOPPADDING",   (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING",(0, 0), (-1, -1), 5),
    ]))
    return t


# ─────────────────────────────────────────────────────────────
# UNIFIED REPORT - combines Risk Register + Scanner + SOC 2 + Alerts
# ─────────────────────────────────────────────────────────────
def _unified_exec_summary(
    df: pd.DataFrame,
    scanner_df,
    alert_df,
    soc2_state: dict,
) -> list:
    """Return a list of [label, value] rows for the unified executive summary table."""
    rows = [["Metric", "Value"]]

    # Risk register
    rows.append(["── Risk Register ──", ""])
    rows.append(["Total risk entries", str(len(df))])
    if not df.empty:
        rows.append(["Average residual risk", f"{round(df['Residual Risk'].mean(), 2)} / 25"])
        rows.append(["Highest residual risk", f"{df['Residual Risk'].max()} / 25"])
        critical_count = (df["Residual Level"] == "Critical").sum()
        high_count     = (df["Residual Level"] == "High").sum()
        rows.append(["Critical / High risks", f"{critical_count} Critical · {high_count} High"])
        rows.append(["Open risks",            str((df["Status"] != "Closed").sum())])
        rows.append(["Audit-ready entries",   str((df.get("Audit Status", pd.Series()) == "Audit Ready").sum())])

    # Scanner findings
    rows.append(["── Vulnerability Scanner ──", ""])
    if scanner_df is not None and not scanner_df.empty:
        sev_counts = scanner_df["Severity"].value_counts()
        rows.append(["Total findings imported", str(len(scanner_df))])
        for sev in ["Critical", "High", "Medium", "Low", "Informational"]:
            if sev in sev_counts:
                rows.append([f"  {sev} findings", str(sev_counts[sev])])
    else:
        rows.append(["Findings imported", "None in this session"])

    # SOC 2
    rows.append(["── SOC 2 Readiness ──", ""])
    if soc2_state:
        pct, band = soc2_readiness_score(soc2_state)
        total = len(soc2_state)
        done  = sum(1 for v in soc2_state.values() if v)
        rows.append(["Overall readiness", f"{pct}%  ({band})"])
        rows.append(["Controls evidenced", f"{done} of {total}"])
        rows.append(["Controls with gaps", str(total - done)])
    else:
        rows.append(["Readiness assessment", "Not completed in this session"])

    # Alerts
    rows.append(["── SOC Alert Import ──", ""])
    if alert_df is not None and not alert_df.empty:
        aev = alert_df["Severity"].value_counts()
        rows.append(["Total alerts imported", str(len(alert_df))])
        for sev in ["Critical", "High", "Medium", "Low"]:
            if sev in aev:
                rows.append([f"  {sev} alerts", str(aev[sev])])
    else:
        rows.append(["Alerts imported", "None in this session"])

    return rows


def generate_txt_unified(
    df: pd.DataFrame,
    scanner_df,
    alert_df,
    soc2_state: dict,
) -> str:
    """Generate a plain-text unified report covering all four data sources."""
    lines = [
        "ENTERPRISE GRC RISK INTELLIGENCE PLATFORM",
        "UNIFIED ASSESSMENT REPORT",
        "Built by Saloni Bhosale",
        "=" * 72,
        f"Generated  : {datetime.now().strftime('%B %d, %Y at %I:%M %p UTC')}",
        f"Frameworks : NIST CSF 2.0 | ISO 27001 | NIST RMF | Zero Trust",
        "Sections   : Risk Register | Vulnerability Scanner | SOC 2 Readiness | SOC Alerts",
        "=" * 72, "",
    ]

    # Executive summary
    lines += ["EXECUTIVE SUMMARY", "-" * 72]
    for label, value in _unified_exec_summary(df, scanner_df, alert_df, soc2_state)[1:]:
        if value == "":
            lines += ["", f"  {label}"]
        else:
            lines.append(f"  {label:<35}: {value}")
    lines.append("")

    # Scoring methodology
    lines += ["SCORING METHODOLOGY", "-" * 72,
              "  Stage 1 - Inherent Risk = Likelihood × (Impact × AV_Weight), clamped to [1–25]",
              "  Stage 2 - Residual Risk = Inherent × (1 − CE_Reduction%), rounded to [1–25]",
              "  AV weights: 1=0.60 2=0.75 3=1.00 4=1.30 5=1.60 (log-like, per ISO 27005:2022)",
              "  CE reductions: 1=5% 2=20% 3=45% 4=70% 5=90% (S-curve, per NIST SP 800-30 Rev 1)", ""]

    # Scanner section
    lines += ["=" * 72, "SECTION 1 - VULNERABILITY SCANNER FINDINGS", "=" * 72, ""]
    if scanner_df is not None and not scanner_df.empty:
        lines.append(f"  {len(scanner_df)} finding(s) imported from vulnerability scanner export.")
        lines.append("")
        for i, row in scanner_df.iterrows():
            lines.append(f"  Finding {i+1}: [{row['Severity']}] {row['Finding']}")
            lines.append(f"    Asset  : {row['Asset']}  |  Threat: {row['Threat']}")
            if row.get("Host"):  lines.append(f"    Host   : {row['Host']}")
            if row.get("CVE"):   lines.append(f"    CVE    : {row['CVE']}")
            lines.append("")
    else:
        lines += ["  No vulnerability scanner data was imported in this session.", ""]

    # SOC 2 section
    lines += ["=" * 72, "SECTION 2 - SOC 2 READINESS ASSESSMENT", "=" * 72, ""]
    if soc2_state:
        pct, band = soc2_readiness_score(soc2_state)
        lines += [f"  Overall Readiness : {pct}% - {band}", ""]
        # Group by category
        by_cat: dict[str, list] = {}
        for ctrl_key, evidenced in soc2_state.items():
            parts = ctrl_key.split(": ", 1)
            cat   = parts[0] if len(parts) == 2 else "General"
            ctrl  = parts[1] if len(parts) == 2 else ctrl_key
            by_cat.setdefault(cat, []).append((ctrl, evidenced))
        for cat, ctrls in by_cat.items():
            done = sum(1 for _, v in ctrls if v)
            lines.append(f"  {cat} ({done}/{len(ctrls)} evidenced)")
            for ctrl, evidenced in ctrls:
                mark = "✓" if evidenced else "✗"
                lines.append(f"    [{mark}] {ctrl}")
            lines.append("")
    else:
        lines += ["  SOC 2 readiness checklist was not completed in this session.", ""]

    # Alert section
    lines += ["=" * 72, "SECTION 3 - SOC ALERT BATCH IMPORT", "=" * 72, ""]
    if alert_df is not None and not alert_df.empty:
        lines.append(f"  {len(alert_df)} alert(s) imported from SOC/SIEM batch export.")
        lines.append("  Note: this is a point-in-time batch import, not live monitoring.")
        lines.append("")
        for i, row in alert_df.iterrows():
            lines.append(f"  Alert {i+1}: [{row['Severity']}] {row['Alert']}")
            lines.append(f"    Asset  : {row['Asset']}  |  Threat: {row['Threat']}")
            if row.get("Host / Source"): lines.append(f"    Source : {row['Host / Source']}")
            lines.append("")
    else:
        lines += ["  No SOC alert data was imported in this session.", ""]

    # Risk register section (existing per-entry detail)
    lines += ["=" * 72, "SECTION 4 - RISK REGISTER DETAIL", "=" * 72, ""]
    if df.empty:
        lines += ["  No risk entries in register.", ""]
    else:
        for i, row in df.iterrows():
            lines += [f"  RISK {i+1} - {row.get('Asset','')} / {row.get('Threat','')}", "  " + "-"*68]
            for fld in ["Company / Unit","Industry","Department","Risk Owner","Status","Review Date",
                        "Asset","Threat","Likelihood","Impact","Asset Value","Control Effectiveness",
                        "Inherent Risk","Residual Risk","Residual Level","Priority","Final Treatment"]:
                lines.append(f"    {fld:<30}: {row.get(fld,'')}")
            lines += ["", f"    Business Impact: {row.get('Business Impact','')}",
                      "", "    Framework Mapping:",
                      f"      NIST CSF : {row.get('NIST Mapping','')}",
                      f"      RMF      : {row.get('RMF Mapping','')}",
                      f"      ISO27001 : {row.get('ISO 27001 Mapping','')}",
                      "", "    Audit:",
                      f"      Status   : {row.get('Audit Status','')}",
                      f"      File     : {row.get('Evidence File','')}",
                      f"      Action   : {row.get('Audit Recommendation','')}", ""]

    lines += ["=" * 72,
              "This unified report covers vulnerability findings, SOC 2 readiness, SOC alert",
              "triage, and scored risk entries from the Enterprise GRC Risk Intelligence Platform.",
              "All content should be reviewed by qualified security and compliance stakeholders.",
              "=" * 72]
    return "\n".join(lines)


def generate_pdf_unified(
    df: pd.DataFrame,
    scanner_df,
    alert_df,
    soc2_state: dict,
) -> str:
    """Generate a unified PDF report covering all four data sources."""
    path = tempfile.NamedTemporaryFile(delete=False, suffix=".pdf", prefix="grc_unified_").name
    st.session_state["_temp_files"].append(path)

    doc = SimpleDocTemplate(path, pagesize=letter,
                            rightMargin=50, leftMargin=50, topMargin=85, bottomMargin=55)
    styles = getSampleStyleSheet()
    S = {
        "title":  ParagraphStyle("T",  parent=styles["Title"],
                                 fontName="Helvetica-Bold", fontSize=22,
                                 textColor=colors.HexColor("#0A1628"), alignment=TA_CENTER, spaceAfter=4),
        "sub":    ParagraphStyle("S",  parent=styles["Normal"],
                                 fontSize=10, textColor=colors.HexColor("#475569"),
                                 alignment=TA_CENTER, spaceAfter=2),
        "h1":     ParagraphStyle("H1", parent=styles["Heading2"],
                                 fontName="Helvetica-Bold", fontSize=14,
                                 textColor=colors.HexColor("#0A1628"), spaceBefore=14, spaceAfter=7),
        "h2":     ParagraphStyle("H2", parent=styles["Heading3"],
                                 fontName="Helvetica-Bold", fontSize=11,
                                 textColor=colors.HexColor("#1D4ED8"), spaceBefore=9, spaceAfter=4),
        "h3":     ParagraphStyle("H3", parent=styles["Heading3"],
                                 fontName="Helvetica-Bold", fontSize=10,
                                 textColor=colors.HexColor("#0E7C7B"), spaceBefore=6, spaceAfter=3),
        "body":   ParagraphStyle("B",  parent=styles["Normal"],
                                 fontSize=9.5, leading=14, textColor=colors.HexColor("#1E293B")),
        "mono":   ParagraphStyle("M",  parent=styles["Normal"],
                                 fontName="Courier", fontSize=9,
                                 textColor=colors.HexColor("#334155"), leading=13),
        "note":   ParagraphStyle("N",  parent=styles["Normal"],
                                 fontSize=8.5, leading=12,
                                 textColor=colors.HexColor("#64748B"), italics=True),
    }

    c = []

    # ── Cover ──
    c += [
        Paragraph("Enterprise GRC Risk Intelligence Platform", S["title"]),
        Paragraph("Unified Assessment Report", S["sub"]),
        Paragraph("Risk Register · Vulnerability Scanner · SOC 2 Readiness · SOC Alerts", S["sub"]),
        Paragraph(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M UTC')}", S["sub"]),
        Paragraph("Built by Saloni Bhosale · ", S["sub"]),
        Spacer(1, 18),
        HRFlowable(width="100%", thickness=2, color=colors.HexColor("#1D4ED8")),
        Spacer(1, 12),
    ]

    # ── Executive Summary ──
    c.append(Paragraph("Executive Summary", S["h1"]))
    c.append(_pdf_table(_unified_exec_summary(df, scanner_df, alert_df, soc2_state), [265, 195]))
    c.append(Spacer(1, 14))

    # ── Scoring Methodology ──
    c.append(Paragraph("Scoring Methodology", S["h1"]))
    for v in [
        "Stage 1 - Inherent Risk = Likelihood × (Impact × AV_Weight), clamped to [1–25].",
        "Stage 2 - Residual Risk = Inherent × (1 − CE_Reduction%), rounded to [1–25].",
        "AV weights: 1→0.60 | 2→0.75 | 3→1.00 | 4→1.30 | 5→1.60 (log-like, ISO 27005:2022).",
        "CE reductions: 1→5% | 2→20% | 3→45% | 4→70% | 5→90% (S-curve, NIST SP 800-30 Rev 1).",
    ]:
        c.append(Paragraph(f"• {v}", S["body"]))
    c.append(Spacer(1, 10))

    # ── Section 1: Scanner ──
    c.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#CBD5E1")))
    c.append(Paragraph("Section 1 - Vulnerability Scanner Findings", S["h1"]))
    if scanner_df is not None and not scanner_df.empty:
        c.append(Paragraph(
            f"{len(scanner_df)} finding(s) imported from a vulnerability scanner export (Nessus/Qualys format). "
            "Each finding has been mapped to the platform's asset-threat taxonomy. "
            "High and Critical findings should be prioritised for conversion to scored risk register entries.",
            S["body"]
        ))
        c.append(Spacer(1, 8))

        # Severity summary bar
        sev_order = ["Critical", "High", "Medium", "Low", "Informational"]
        sev_counts = scanner_df["Severity"].value_counts()
        sev_summary = [["Severity", "Count"]]
        for sev in sev_order:
            if sev in sev_counts:
                sev_summary.append([sev, str(sev_counts[sev])])
        c.append(_pdf_table(sev_summary, [200, 120]))
        c.append(Spacer(1, 10))

        # Finding detail table
        tbl_data = [["#", "Finding", "Severity", "Asset", "Threat", "Host", "CVE"]]
        for i, row in scanner_df.iterrows():
            tbl_data.append([
                str(i+1),
                (row["Finding"] or "")[:55],
                row["Severity"],
                row["Asset"],
                row["Threat"],
                (row.get("Host") or "")[:18],
                (row.get("CVE") or "")[:16],
            ])
        tbl = Table(tbl_data, colWidths=[22, 145, 55, 75, 80, 55, 50], repeatRows=1)
        tbl.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (-1, 0), colors.HexColor("#1E3A5F")),
            ("TEXTCOLOR",     (0, 0), (-1, 0), colors.white),
            ("FONTNAME",      (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE",      (0, 0), (-1, -1), 7.5),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1),
             [colors.HexColor("#F4F7FB"), colors.white]),
            ("GRID",          (0, 0), (-1, -1), 0.4, colors.HexColor("#CBD5E1")),
            ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING",    (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ]))
        c.append(tbl)
    else:
        c.append(Paragraph("No vulnerability scanner data was imported in this session.", S["note"]))
    c.append(Spacer(1, 14))

    # ── Section 2: SOC 2 ──
    c.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#CBD5E1")))
    c.append(Paragraph("Section 2 - SOC 2 Readiness Assessment", S["h1"]))
    if soc2_state:
        pct, band = soc2_readiness_score(soc2_state)
        total = len(soc2_state)
        done  = sum(1 for v in soc2_state.values() if v)
        c.append(Paragraph(
            f"Overall readiness: <b>{pct}% - {band}</b>. "
            f"{done} of {total} controls are marked as evidenced.",
            S["body"]
        ))
        c.append(Spacer(1, 8))

        # Controls table grouped by category
        by_cat: dict[str, list] = {}
        for ctrl_key, evidenced in soc2_state.items():
            parts = ctrl_key.split(": ", 1)
            cat   = parts[0] if len(parts) == 2 else "General"
            ctrl  = parts[1] if len(parts) == 2 else ctrl_key
            by_cat.setdefault(cat, []).append((ctrl, evidenced))

        for cat, ctrls in by_cat.items():
            cat_done = sum(1 for _, v in ctrls if v)
            c.append(Paragraph(f"{cat}  ({cat_done}/{len(ctrls)} evidenced)", S["h3"]))
            tbl_data = [["Control", "Evidenced"]]
            for ctrl, ev in ctrls:
                tbl_data.append([ctrl, "✓ Yes" if ev else "✗ No"])
            tbl = Table(tbl_data, colWidths=[360, 70], repeatRows=1)
            tbl.setStyle(TableStyle([
                ("BACKGROUND",    (0, 0), (-1, 0), colors.HexColor("#0E7C7B")),
                ("TEXTCOLOR",     (0, 0), (-1, 0), colors.white),
                ("FONTNAME",      (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE",      (0, 0), (-1, -1), 8.5),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1),
                 [colors.HexColor("#F4F7FB"), colors.white]),
                ("GRID",          (0, 0), (-1, -1), 0.4, colors.HexColor("#CBD5E1")),
                ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
                ("TOPPADDING",    (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ]))
            c.append(tbl)
            c.append(Spacer(1, 6))
        c.append(Paragraph(
            "Note: This is a self-assessment aid, not a substitute for a licensed SOC 2 auditor's examination.",
            S["note"]
        ))
    else:
        c.append(Paragraph("SOC 2 readiness checklist was not completed in this session.", S["note"]))
    c.append(Spacer(1, 14))

    # ── Section 3: SOC Alerts ──
    c.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#CBD5E1")))
    c.append(Paragraph("Section 3 - SOC Alert Batch Import", S["h1"]))
    if alert_df is not None and not alert_df.empty:
        c.append(Paragraph(
            f"{len(alert_df)} alert(s) imported from a SOC/SIEM batch export. "
            "This is a point-in-time import of already-triaged alerts, not a live monitoring feed. "
            "Critical and High alerts should be converted to scored risk register entries.",
            S["body"]
        ))
        c.append(Spacer(1, 8))
        tbl_data = [["#", "Alert", "Severity", "Asset", "Threat", "Source"]]
        for i, row in alert_df.iterrows():
            tbl_data.append([
                str(i+1),
                (row["Alert"] or "")[:65],
                row["Severity"],
                row["Asset"],
                row["Threat"],
                (row.get("Host / Source") or "")[:20],
            ])
        tbl = Table(tbl_data, colWidths=[22, 170, 55, 75, 80, 60], repeatRows=1)
        tbl.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (-1, 0), colors.HexColor("#1E3A5F")),
            ("TEXTCOLOR",     (0, 0), (-1, 0), colors.white),
            ("FONTNAME",      (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE",      (0, 0), (-1, -1), 7.5),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1),
             [colors.HexColor("#F4F7FB"), colors.white]),
            ("GRID",          (0, 0), (-1, -1), 0.4, colors.HexColor("#CBD5E1")),
            ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING",    (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ]))
        c.append(tbl)
    else:
        c.append(Paragraph("No SOC alert data was imported in this session.", S["note"]))
    c.append(Spacer(1, 14))

    # ── Section 4: Risk Register ──
    c.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#CBD5E1")))
    c.append(Paragraph("Section 4 - Risk Register Detail", S["h1"]))
    if df.empty:
        c.append(Paragraph("No risk entries in the register.", S["note"]))
    else:
        for i, row in df.iterrows():
            block = []
            block.append(Paragraph(f"Risk {i+1}: {row['Asset']} - {row['Threat']}", S["h2"]))
            block.append(_pdf_table([
                ["Field", "Value"],
                *[[fld, str(row.get(fld, ""))] for fld in [
                    "Company / Unit","Industry","Department","Risk Owner","Status","Review Date",
                    "Asset","Threat","Likelihood","Impact","Asset Value","Control Effectiveness",
                    "Inherent Risk","Residual Risk","Residual Level","Priority","Final Treatment",
                    "NIST Mapping","RMF Mapping","ISO 27001 Mapping",
                    "Vulnerability / Finding","Vulnerability Severity","Finding Source",
                    "Evidence File","Audit Status",
                ]]
            ], [185, 290]))
            block.append(Spacer(1, 6))
            block.append(Paragraph("Business Impact", S["h3"]))
            block.append(Paragraph(str(row.get("Business Impact", "")), S["body"]))
            block.append(Spacer(1, 6))

            hm_path = create_heatmap_image(int(row["Likelihood"]), int(row["Impact"]))
            block.append(Paragraph("Risk Heatmap", S["h3"]))
            block.append(Image(hm_path, width=200, height=155))
            block.append(Spacer(1, 6))

            block.append(Paragraph("Recommended Controls", S["h3"]))
            for rec in str(row.get("Recommended Controls", "")).split(" | "):
                if rec: block.append(Paragraph(f"• {rec}", S["body"]))

            block.append(Paragraph("Next Steps", S["h3"]))
            for step in str(row.get("Next Steps", "")).split(" | "):
                if step: block.append(Paragraph(f"• {step}", S["body"]))

            block.append(Spacer(1, 12))
            block.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#E2E8F0")))
            block.append(Spacer(1, 8))
            c.append(KeepTogether(block[:4]))
            c.extend(block[4:])

    # ── Conclusion ──
    c.append(Spacer(1, 10))
    c.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#CBD5E1")))
    c.append(Paragraph("Conclusion", S["h1"]))
    c.append(Paragraph(
        "This unified report integrates vulnerability scanner findings, SOC 2 readiness evidence, "
        "SOC alert triage, and two-stage scored risk register entries into a single deliverable. "
        "Frameworks covered: NIST CSF 2.0, ISO 27001, NIST RMF, and Zero Trust. "
        "All content should be reviewed by qualified security, compliance, and business stakeholders "
        "before formal acceptance, escalation, or presentation to a board.",
        S["body"]
    ))

    doc.build(c, onFirstPage=_page_decoration, onLaterPages=_page_decoration)
    return path


def generate_txt_report(df: pd.DataFrame) -> str:
    lines = []
    lines += [
        "ENTERPRISE GRC RISK INTELLIGENCE PLATFORM",
        "RISK ASSESSMENT REPORT",
        "Built by Saloni Bhosale",
        "=" * 72,
        f"Generated : {datetime.now().strftime('%B %d, %Y at %I:%M %p UTC')}",
        f"Entries   : {len(df)}",
        "Frameworks: NIST CSF 2.0 | ISO 27001 | NIST RMF | Zero Trust",
        "=" * 72, "",
    ]

    lines += ["SCORING METHODOLOGY", "-" * 72,
              "  Stage 1 - Inherent Risk = Likelihood × (Impact × AV_Weight), clamped to [1–25]",
              "  Stage 2 - Residual Risk = Inherent × (1 − CE_Reduction%), rounded to [1–25]",
              "  AV weights: 1=0.60 2=0.75 3=1.00 4=1.30 5=1.60 (log-like, per ISO 27005)",
              "  CE reductions: 1=5% 2=20% 3=45% 4=70% 5=90% (S-curve, per NIST SP 800-30)",
              "  Source: NIST SP 800-30 Rev 1 (Table I-2/I-3) and ISO 27005:2022 §9.", ""]

    lines += ["ASSUMPTIONS AND LIMITATIONS", "-" * 72]
    for item in get_assumptions_limitations():
        lines.append(f"  • {item}")
    lines.append("")

    if df.empty:
        lines.append("No risk entries available.")
        return "\n".join(lines)

    lines += ["EXECUTIVE SUMMARY", "-" * 72,
              f"  Total risks     : {len(df)}",
              f"  Avg residual    : {round(df['Residual Risk'].mean(), 2)} / 25",
              f"  Max residual    : {df['Residual Risk'].max()} / 25",
              f"  Open risks      : {(df['Status'] != 'Closed').sum()}", ""]

    for i, row in df.iterrows():
        lines += [f"RISK ENTRY {i+1} - {row.get('Asset','')} / {row.get('Threat','')}",
                  "-" * 72]
        for fld in ["Company / Unit","Industry","Department","Risk Owner","Status","Review Date",
                    "Asset","Threat","Likelihood","Impact","Asset Value","Control Effectiveness",
                    "Inherent Risk","Residual Risk","Residual Level","Priority","Final Treatment"]:
            lines.append(f"  {fld:<28}: {row.get(fld,'')}")
        lines += ["", "  Business Impact:", f"  {row.get('Business Impact','')}", ""]
        lines += ["  Vulnerability & Audit:"]
        for fld in ["Vulnerability / Finding","Vulnerability Severity","Finding Source",
                    "Evidence File","Audit Status","Audit Recommendation"]:
            lines.append(f"  {fld:<28}: {row.get(fld,'')}")
        lines += ["", "  Framework Mapping:",
                  f"  NIST CSF  : {row.get('NIST Mapping','')}",
                  f"  RMF       : {row.get('RMF Mapping','')}",
                  f"  ISO 27001 : {row.get('ISO 27001 Mapping','')}",
                  "  Mapped Controls:"]
        for c in str(row.get("Mapped Controls","")).split(" | "):
            if c: lines.append(f"    - {c}")
        lines += ["", "  Recommended Controls:"]
        for c in str(row.get("Recommended Controls","")).split(" | "):
            if c: lines.append(f"    - {c}")
        lines += ["", "  Next Steps:"]
        for c in str(row.get("Next Steps","")).split(" | "):
            if c: lines.append(f"    - {c}")
        lines.append("")

    lines += ["=" * 72, "END OF REPORT", "=" * 72]
    return "\n".join(lines)


def generate_pdf_report(df: pd.DataFrame) -> str:
    path = tempfile.NamedTemporaryFile(delete=False, suffix=".pdf", prefix="grc_report_").name
    st.session_state["_temp_files"].append(path)

    doc = SimpleDocTemplate(path, pagesize=letter,
                            rightMargin=50, leftMargin=50, topMargin=85, bottomMargin=55)
    styles = getSampleStyleSheet()
    S = {
        "title":  ParagraphStyle("T", parent=styles["Title"],
                                 fontName="Helvetica-Bold", fontSize=22,
                                 textColor=colors.HexColor("#0A1628"), alignment=TA_CENTER, spaceAfter=4),
        "sub":    ParagraphStyle("S", parent=styles["Normal"],
                                 fontSize=10, textColor=colors.HexColor("#475569"),
                                 alignment=TA_CENTER, spaceAfter=2),
        "h1":     ParagraphStyle("H1", parent=styles["Heading2"],
                                 fontName="Helvetica-Bold", fontSize=14,
                                 textColor=colors.HexColor("#0A1628"), spaceBefore=14, spaceAfter=7),
        "h2":     ParagraphStyle("H2", parent=styles["Heading3"],
                                 fontName="Helvetica-Bold", fontSize=11,
                                 textColor=colors.HexColor("#1D4ED8"), spaceBefore=9, spaceAfter=4),
        "body":   ParagraphStyle("B", parent=styles["Normal"],
                                 fontSize=9.5, leading=14, textColor=colors.HexColor("#1E293B")),
        "mono":   ParagraphStyle("M", parent=styles["Normal"],
                                 fontName="Courier", fontSize=9,
                                 textColor=colors.HexColor("#334155"), leading=13),
    }

    c = []
    c += [
        Paragraph("Enterprise GRC Risk Intelligence Platform", S["title"]),
        Paragraph("Risk Assessment Report", S["sub"]),
        Paragraph(f"NIST CSF 2.0 · ISO 27001 · RMF · Zero Trust", S["sub"]),
        Paragraph(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M UTC')}", S["sub"]),
        Paragraph("Built by Saloni Bhosale", S["sub"]),
        Spacer(1, 18),
        HRFlowable(width="100%", thickness=1, color=colors.HexColor("#CBD5E1")),
        Spacer(1, 12),
    ]

    c.append(Paragraph("Scoring Methodology", S["h1"]))
    for v in [
        "Stage 1 - Inherent Risk = Likelihood × (Impact × AV_Weight), clamped to [1–25].",
        "Stage 2 - Residual Risk = Inherent × (1 − CE_Reduction%), rounded to [1–25].",
        "AV weights: 1→0.60 | 2→0.75 | 3→1.00 | 4→1.30 | 5→1.60 (log-like scale, ISO 27005:2022).",
        "CE reductions: 1→5% | 2→20% | 3→45% | 4→70% | 5→90% (S-curve, NIST SP 800-30 Rev 1).",
    ]:
        c.append(Paragraph(f"• {v}", S["body"]))
    c.append(Spacer(1, 10))

    c.append(Paragraph("Assumptions & Limitations", S["h1"]))
    for item in get_assumptions_limitations():
        c.append(Paragraph(f"• {item}", S["body"]))
    c.append(Spacer(1, 10))

    if not df.empty:
        c.append(Paragraph("Executive Summary", S["h1"]))
        c.append(_pdf_table([
            ["Metric", "Value"],
            ["Total Risks",           str(len(df))],
            ["Average Residual Risk", f"{round(df['Residual Risk'].mean(), 2)} / 25"],
            ["Highest Residual Risk", f"{df['Residual Risk'].max()} / 25"],
            ["Open Risks",            str((df["Status"] != "Closed").sum())],
        ], [260, 200]))
        c.append(Spacer(1, 14))

        c.append(Paragraph("Risk Assessment Details", S["h1"]))
        for i, row in df.iterrows():
            block = []
            block.append(Paragraph(f"Entry {i+1}: {row['Asset']} - {row['Threat']}", S["h2"]))
            block.append(_pdf_table([
                ["Field", "Value"],
                *[[fld, str(row.get(fld, ""))] for fld in [
                    "Company / Unit","Industry","Department","Risk Owner","Status","Review Date",
                    "Asset","Threat","Likelihood","Impact","Asset Value","Control Effectiveness",
                    "Inherent Risk","Residual Risk","Residual Level","Priority","Final Treatment",
                    "NIST Mapping","RMF Mapping","ISO 27001 Mapping",
                    "Vulnerability / Finding","Vulnerability Severity","Finding Source",
                    "Evidence File","Audit Status",
                ]]
            ], [185, 290]))
            block.append(Spacer(1, 7))
            block.append(Paragraph("Business Impact", S["h2"]))
            block.append(Paragraph(str(row.get("Business Impact", "")), S["body"]))
            block.append(Spacer(1, 7))

            hm_path = create_heatmap_image(int(row["Likelihood"]), int(row["Impact"]))
            block.append(Paragraph("Risk Heatmap", S["h2"]))
            block.append(Image(hm_path, width=230, height=175))
            block.append(Paragraph(str(row.get("Heatmap Summary", "")), S["mono"]))
            block.append(Spacer(1, 7))

            block.append(Paragraph("Mapped Controls", S["h2"]))
            for ctrl in str(row.get("Mapped Controls", "")).split(" | "):
                if ctrl: block.append(Paragraph(f"• {ctrl}", S["body"]))

            block.append(Paragraph("Recommended Controls", S["h2"]))
            for rec in str(row.get("Recommended Controls", "")).split(" | "):
                if rec: block.append(Paragraph(f"• {rec}", S["body"]))

            block.append(Paragraph("Audit Tracking", S["h2"]))
            block.append(Paragraph(str(row.get("Audit Recommendation", "")), S["body"]))

            block.append(Paragraph("Next Steps", S["h2"]))
            for step in str(row.get("Next Steps", "")).split(" | "):
                if step: block.append(Paragraph(f"• {step}", S["body"]))

            block.append(Spacer(1, 16))
            block.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#E2E8F0")))
            block.append(Spacer(1, 10))
            c.append(KeepTogether(block[:6]))   # keep header + table together
            c.extend(block[6:])

    c.append(Paragraph("Conclusion", S["h1"]))
    c.append(Paragraph(
        "This report integrates vulnerability context, asset criticality, control effectiveness, evidence tracking, "
        "audit readiness, and multi-framework alignment into a single risk register workflow. "
        "All findings should be reviewed by qualified security, compliance, and business stakeholders before formal acceptance or escalation.",
        S["body"]
    ))

    doc.build(c, onFirstPage=_page_decoration, onLaterPages=_page_decoration)
    return path


# ─────────────────────────────────────────────────────────────
# RESULT BUILDER
# ─────────────────────────────────────────────────────────────
def build_result(
    asset: str, threat: str,
    likelihood: int, impact: int,
    asset_value: int, control_effectiveness: int,
    reasons: list[str],
    plain_summary: str, actions: list, confidence: str,
    # context fields
    company: str, industry: str, department: str, owner: str,
    status: str, review_date,
    financial_impact: str, operational_impact: str,
    compliance_impact: str, business_process: str,
    vulnerability_name: str, vulnerability_severity: str,
    vulnerability_source: str, evidence_name: str,
    evidence_owner: str, audit_status: str,
    # new: treatment plan fields
    treatment_owner: str = "",
    treatment_target_date: str = "",
    treatment_notes: str = "",
    # new: accepted risk review date
    accept_review_date: str = "",
) -> dict:
    inherent, residual = calculate_risks(likelihood, impact, asset_value, control_effectiveness)
    level, emoji, color = risk_level(residual)
    priority, p_reason = get_priority_flag(residual)
    treatment, t_reason = suggest_treatment(threat, residual)

    # ── CE evidence gate warning ───────────────────────────────
    ce_gate_warning = ""
    if control_effectiveness >= 4 and audit_status in ("Evidence Missing", "Remediation In Progress"):
        ce_gate_warning = (
            f"⚠️ Control Effectiveness is rated {control_effectiveness}/5 "
            f"but Audit Status is '{audit_status}'. "
            f"High CE scores should be supported by uploaded evidence. "
            f"Without evidence, auditors may challenge this rating."
        )

    # ── Target risk (+1 CE scenario) ──────────────────────────
    target_ce     = min(5, control_effectiveness + 1)
    _, target_res = calculate_risks(likelihood, impact, asset_value, target_ce)
    target_level, _, target_color = risk_level(target_res)
    target_delta  = residual - target_res
    ce_desc       = CE_REDUCTION.get(target_ce, 0.70)
    target_note   = (
        f"If controls improve from CE={control_effectiveness} to CE={target_ce} "
        f"({int(ce_desc*100)}% reduction), residual risk drops from "
        f"{residual}/25 ({level}) to {target_res}/25 ({target_level}) - "
        f"a {target_delta}-point improvement."
    ) if target_delta > 0 else "Controls are already at best-in-class (CE=5)."

    # ── Risk appetite check ────────────────────────────────────
    appetite      = st.session_state.get("risk_appetite", DEFAULT_RISK_APPETITE)
    exceeds_app   = residual >= appetite
    appetite_note = (
        f"Residual risk {residual}/25 EXCEEDS your risk appetite threshold of {appetite}/25. "
        f"Treatment is required before this risk can be accepted."
        if exceeds_app else
        f"Residual risk {residual}/25 is within your risk appetite threshold of {appetite}/25."
    )

    # ── Accept expiry check ───────────────────────────────────
    accept_expiry_warning = ""
    if treatment == "Accept" and not accept_review_date:
        accept_expiry_warning = (
            "⚠️ Accepted risks must have a review date (max 12 months). "
            "Without a review date, this acceptance has no expiry and creates open-ended liability."
        )

    return {
        "Company / Unit":           company,
        "Report Type":              "Enterprise GRC Risk Assessment",
        "Industry":                 industry,
        "Department":               department,
        "Risk Owner":               owner,
        "Status":                   status,
        "Review Date":              str(review_date),
        "Asset":                    asset,
        "Threat":                   threat,
        "Likelihood":               likelihood,
        "Likelihood Definition":    LIKELIHOOD_DEFINITIONS.get(likelihood, {}).get("desc", ""),
        "Likelihood Frequency":     LIKELIHOOD_DEFINITIONS.get(likelihood, {}).get("freq", ""),
        "Impact":                   impact,
        "Impact Definition":        IMPACT_DEFINITIONS.get(impact, {}).get("desc", ""),
        "Asset Value":              asset_value,
        "Control Effectiveness":    control_effectiveness,
        "CE Gate Warning":          ce_gate_warning,
        "Inherent Risk":            inherent,
        "Residual Risk":            residual,
        "Residual Level":           level,
        "Heatmap Summary":          get_heatmap_summary(likelihood, impact),
        "Residual Emoji":           emoji,
        "Residual Color":           color,
        "Priority":                 priority,
        "Priority Rationale":       p_reason,
        "Exceeds Risk Appetite":    exceeds_app,
        "Risk Appetite Note":       appetite_note,
        "Target CE":                target_ce,
        "Target Residual Risk":     target_res,
        "Target Residual Level":    target_level,
        "Target Risk Note":         target_note,
        "Final Treatment":          treatment,
        "Suggested Treatment":      treatment,
        "Treatment Reason":         t_reason,
        "Treatment Owner":          treatment_owner or owner,
        "Treatment Target Date":    treatment_target_date,
        "Treatment Notes":          treatment_notes,
        "Accept Review Date":       accept_review_date,
        "Accept Expiry Warning":    accept_expiry_warning,
        "Business Impact":          build_business_impact_analysis(
                                        business_impact(threat, asset, industry),
                                        financial_impact, operational_impact,
                                        compliance_impact, business_process,
                                    ),
        "Financial Impact":         financial_impact,
        "Operational Impact":       operational_impact,
        "Compliance Impact":        compliance_impact,
        "Affected Business Process": business_process,
        "Plain English Summary":    plain_summary,
        "AI Actions":               actions,
        "NIST Mapping":             get_nist_mapping(threat),
        "RMF Mapping":              get_rmf_mapping(threat),
        "ISO 27001 Mapping":        get_iso27001_mapping(threat),
        "HIPAA Mapping":            get_hipaa_mapping(threat),
        "PCI DSS Mapping":          get_pci_mapping(threat),
        "GDPR Mapping":             get_gdpr_mapping(threat),
        "CCPA Mapping":             get_ccpa_mapping(threat),
        "Mapped Controls":          " | ".join(get_control_mapping(threat)),
        "Zero Trust Guidance":      " | ".join(get_zero_trust_guidance(threat)),
        "Recommended Controls":     " | ".join(get_recommendations(threat)),
        "Next Steps":               " | ".join(get_treatment_actions(treatment, residual)),
        "Vulnerability / Finding":  vulnerability_name or "Not linked",
        "Vulnerability Severity":   vulnerability_severity,
        "Finding Source":           vulnerability_source,
        "Evidence File":            evidence_name,
        "Evidence Owner":           evidence_owner,
        "Audit Status":             audit_status,
        "Audit Recommendation":     get_audit_recommendation(audit_status),
        "Maturity Hint":            get_maturity_hint(threat, asset, control_effectiveness),
        "Confidence":               confidence,
        "Scoring Notes":            " | ".join(reasons),
    }

    inherent, residual = calculate_risks(likelihood, impact, asset_value, control_effectiveness)
    level, emoji, color = risk_level(residual)
    priority, p_reason = get_priority_flag(residual)
    treatment, t_reason = suggest_treatment(threat, residual)

    return {
        "Company / Unit":           company,
        "Report Type":              "Enterprise GRC Risk Assessment",
        "Industry":                 industry,
        "Department":               department,
        "Risk Owner":               owner,
        "Status":                   status,
        "Review Date":              str(review_date),
        "Asset":                    asset,
        "Threat":                   threat,
        "Likelihood":               likelihood,
        "Impact":                   impact,
        "Asset Value":              asset_value,
        "Control Effectiveness":    control_effectiveness,
        "Inherent Risk":            inherent,
        "Residual Risk":            residual,
        "Residual Level":           level,
        "Heatmap Summary":          get_heatmap_summary(likelihood, impact),
        "Residual Emoji":           emoji,
        "Residual Color":           color,
        "Priority":                 priority,
        "Priority Rationale":       p_reason,
        "Final Treatment":          treatment,
        "Suggested Treatment":      treatment,
        "Treatment Reason":         t_reason,
        "Business Impact":          build_business_impact_analysis(
                                        business_impact(threat, asset, industry),
                                        financial_impact, operational_impact,
                                        compliance_impact, business_process,
                                    ),
        "Financial Impact":         financial_impact,
        "Operational Impact":       operational_impact,
        "Compliance Impact":        compliance_impact,
        "Affected Business Process": business_process,
        "Plain English Summary":    plain_summary,
        "AI Actions":               actions,
        "NIST Mapping":             get_nist_mapping(threat),
        "RMF Mapping":              get_rmf_mapping(threat),
        "ISO 27001 Mapping":        get_iso27001_mapping(threat),
        "HIPAA Mapping":            get_hipaa_mapping(threat),
        "PCI DSS Mapping":          get_pci_mapping(threat),
        "GDPR Mapping":             get_gdpr_mapping(threat),
        "CCPA Mapping":             get_ccpa_mapping(threat),
        "Mapped Controls":          " | ".join(get_control_mapping(threat)),
        "Zero Trust Guidance":      " | ".join(get_zero_trust_guidance(threat)),
        "Recommended Controls":     " | ".join(get_recommendations(threat)),
        "Next Steps":               " | ".join(get_treatment_actions(treatment, residual)),
        "Vulnerability / Finding":  vulnerability_name or "Not linked",
        "Vulnerability Severity":   vulnerability_severity,
        "Finding Source":           vulnerability_source,
        "Evidence File":            evidence_name,
        "Evidence Owner":           evidence_owner,
        "Audit Status":             audit_status,
        "Audit Recommendation":     get_audit_recommendation(audit_status),
        "Maturity Hint":            get_maturity_hint(threat, asset, control_effectiveness),
        "Confidence":               confidence,
        "Scoring Notes":            " | ".join(reasons),
    }


# ─────────────────────────────────────────────────────────────
# VULNERABILITY SCANNER IMPORT (Nessus / Qualys CSV)
# ─────────────────────────────────────────────────────────────
# Maps common scanner severity labels to the platform's 1-5 vulnerability
# severity scale used elsewhere in the app.
SCANNER_SEVERITY_MAP: dict[str, str] = {
    "critical": "Critical", "high": "High", "medium": "Medium",
    "moderate": "Medium", "low": "Low", "informational": "Informational",
    "info": "Informational",
}

# Rough CVSS-band fallback if the file gives a numeric score instead of a label.
def _cvss_to_severity(score: float) -> str:
    if score >= 9.0:
        return "Critical"
    if score >= 7.0:
        return "High"
    if score >= 4.0:
        return "Medium"
    if score > 0:
        return "Low"
    return "Informational"


# Keyword map from scanner plugin/finding text to the platform's existing
# asset and threat taxonomy, reusing the same fallback approach as Smart Mode.
SCANNER_ASSET_KEYWORDS: dict[str, list[str]] = {
    "Database":            ["sql", "mysql", "postgres", "oracle db", "mongodb", "database"],
    "Server":               ["windows server", "linux", "rhel", "ubuntu server", "ssh", "rdp"],
    "Network":              ["router", "switch", "firewall", "snmp", "vpn"],
    "Cloud Environment":    ["s3 bucket", "azure", "aws", "gcp", "cloud storage"],
    "Application":          ["web application", "http", "apache", "nginx", "tomcat", "iis"],
    "Endpoint / Laptop":    ["workstation", "endpoint", "laptop", "desktop"],
    "API":                  ["api", "rest endpoint", "graphql"],
}

SCANNER_THREAT_KEYWORDS: dict[str, list[str]] = {
    "Misconfiguration":     ["misconfigur", "default credential", "default password", "open port", "unnecessary service"],
    "Zero-Day Exploit":     ["zero-day", "0-day"],
    "Unauthorized Access":  ["authentication bypass", "broken access", "privilege", "unauthorized"],
    "Data Breach":          ["information disclosure", "data exposure", "sensitive data"],
    "Malware":              ["malware", "trojan", "backdoor"],
    "Credential Attack":    ["weak password", "brute force", "credential"],
    "Denial of Service (DDoS)": ["denial of service", "dos vulnerab"],
}


def scanner_text_to_asset_threat(text: str) -> tuple[str, str]:
    """Map a scanner finding's plugin/name/description text to the platform's
    asset and threat taxonomy using simple keyword matching. Falls back to
    generic categories when no keyword matches, consistent with the
    Smart Mode fallback philosophy used elsewhere in the app.

    If the asset keyword match and threat keyword match land on a pair that
    isn't in the platform's defined ASSET_THREAT_MAP, the threat match is
    treated as more informative (it reflects what the finding actually is)
    and the asset is adjusted to the first asset type that legitimately
    pairs with that threat, rather than silently discarding the threat."""
    low = (text or "").lower()
    asset = "Server"
    threat = "Misconfiguration"
    asset_matched = False
    for a, kws in SCANNER_ASSET_KEYWORDS.items():
        if any(k in low for k in kws):
            asset = a
            asset_matched = True
            break
    for t, kws in SCANNER_THREAT_KEYWORDS.items():
        if any(k in low for k in kws):
            threat = t
            break

    if threat not in ASSET_THREAT_MAP.get(asset, []):
        # Find an asset type that both (a) legitimately pairs with this
        # threat per the existing taxonomy and (b) was not contradicted by
        # an explicit asset keyword match.
        compatible_assets = [a for a, threats in ASSET_THREAT_MAP.items() if threat in threats]
        if compatible_assets:
            asset = compatible_assets[0]
        elif not asset_matched:
            # No asset keyword matched and the threat has no compatible
            # asset in the map (shouldn't normally happen) - fall back to
            # the asset's own first valid threat instead of a wrong pairing.
            valid = ASSET_THREAT_MAP.get(asset, [])
            if valid:
                threat = valid[0]
    return asset, threat


def parse_scanner_csv(file) -> pd.DataFrame:
    """Parse an uploaded vulnerability scanner export (Nessus or Qualys CSV).
    Returns a normalized DataFrame with columns: Finding, Severity, Asset,
    Threat, Host, CVE. Handles the two most common column-naming
    conventions; unrecognized columns are ignored rather than raising."""
    df_raw = pd.read_csv(file)
    cols_lower = {c.lower().strip(): c for c in df_raw.columns}

    def col(*candidates):
        for c in candidates:
            if c in cols_lower:
                return cols_lower[c]
        return None

    name_col = col("name", "plugin name", "title", "vulnerability")
    sev_col = col("risk", "severity", "risk factor")
    cvss_col = col("cvss", "cvss base score", "cvss v3.0 base score", "cvssv3_basescore")
    host_col = col("host", "ip address", "asset", "target")
    cve_col = col("cve", "cve id")
    desc_col = col("description", "synopsis", "summary")

    rows = []
    for _, r in df_raw.iterrows():
        finding = str(r.get(name_col, "Unnamed Finding")) if name_col else "Unnamed Finding"
        desc = str(r.get(desc_col, "")) if desc_col else ""
        combined_text = f"{finding} {desc}"

        sev_raw = str(r.get(sev_col, "")).strip().lower() if sev_col else ""
        if sev_raw in SCANNER_SEVERITY_MAP:
            severity = SCANNER_SEVERITY_MAP[sev_raw]
        elif cvss_col and pd.notna(r.get(cvss_col)):
            try:
                severity = _cvss_to_severity(float(r.get(cvss_col)))
            except (TypeError, ValueError):
                severity = "Medium"
        else:
            severity = "Medium"

        asset, threat = scanner_text_to_asset_threat(combined_text)

        rows.append({
            "Finding": finding,
            "Severity": severity,
            "Asset": asset,
            "Threat": threat,
            "Host": str(r.get(host_col, "")) if host_col else "",
            "CVE": str(r.get(cve_col, "")) if cve_col and pd.notna(r.get(cve_col)) else "",
        })

    return pd.DataFrame(rows)


def severity_to_likelihood_impact(severity: str) -> tuple[int, int]:
    """Map scanner severity to a sensible starting Likelihood/Impact pair.
    These are starting points an analyst can adjust, not final scores —
    consistent with how Smart Mode's AI suggestions are treated."""
    return {
        "Critical":       (5, 5),
        "High":           (4, 4),
        "Medium":         (3, 3),
        "Low":            (2, 2),
        "Informational":  (1, 1),
    }.get(severity, (3, 3))


# ─────────────────────────────────────────────────────────────
# SOC 2 READINESS TRACKING
# ─────────────────────────────────────────────────────────────
# Trust Services Criteria categories (AICPA SOC 2). Security is required;
# the other four are commonly elected based on engagement scope.
SOC2_CATEGORIES = [
    "Security", "Availability", "Processing Integrity",
    "Confidentiality", "Privacy",
]

# A representative (non-exhaustive) control checklist per category, framed
# at the level of evidence an auditor would actually ask to see.
SOC2_CONTROLS: dict[str, list[str]] = {
    "Security": [
        "Access control policy is documented and enforced",
        "Multi-factor authentication required for privileged access",
        "User access reviews performed at least quarterly",
        "Firewall and network segmentation controls documented",
        "Vulnerability scanning performed on a defined cadence",
        "Security incident response plan tested within the last 12 months",
        "Employee security awareness training completed annually",
        "Vendor / third-party security risk assessments on file",
    ],
    "Availability": [
        "System uptime monitoring and alerting in place",
        "Documented business continuity and disaster recovery plan",
        "Backup procedures tested within the last 12 months",
        "Capacity planning process documented",
    ],
    "Processing Integrity": [
        "Data input validation controls documented",
        "Processing error detection and correction procedures defined",
        "Change management process requires approval before production deployment",
    ],
    "Confidentiality": [
        "Data classification policy in place",
        "Encryption in transit enforced for confidential data",
        "Encryption at rest enforced for confidential data",
        "Data retention and secure disposal policy documented",
    ],
    "Privacy": [
        "Privacy notice published and current",
        "Data subject access request process documented",
        "Consent management process documented where applicable",
    ],
}

# ── Combined checklist lookup - defined here so SOC2_CONTROLS is in scope ──
ALL_FRAMEWORK_CHECKLISTS: dict[str, dict] = {
    "SOC 2":   SOC2_CONTROLS,
    "HIPAA":   HIPAA_CONTROLS,
    "PCI DSS": PCI_CONTROLS,
    "GDPR":    GDPR_CONTROLS,
    "CCPA":    CCPA_CONTROLS,
}

FRAMEWORK_DESCRIPTIONS: dict[str, str] = {
    "SOC 2":      "For SaaS/tech companies - proves to customers that your security controls are in place and working.",
    "HIPAA":      "For healthcare or health-adjacent companies - protects patient health information.",
    "PCI DSS":    "For any company taking card payments - protects cardholder data.",
    "GDPR":       "For any company with customers in the EU - governs how you use personal data.",
    "CCPA":       "For any company with customers in California - gives consumers rights over their personal data.",
    "NIST CSF":   "US government security framework - 6 functions: Govern, Identify, Protect, Detect, Respond, Recover.",
    "ISO 27001":  "International standard - certifiable framework for managing information security.",
    "Zero Trust": "Security model: never trust, always verify. Works for any company size.",
}

FRAMEWORK_WHO_NEEDS_IT: dict[str, str] = {
    "SOC 2":      "Any SaaS company whose enterprise customers ask 'do you have SOC 2?'",
    "HIPAA":      "Healthcare providers, health insurers, and any vendor who handles patient data",
    "PCI DSS":    "Any business that accepts, stores, transmits, or processes payment card data",
    "GDPR":       "Any business that offers goods/services to EU residents or monitors their behaviour",
    "CCPA":       "Businesses with >$25M revenue, or those handling data on >50,000 CA residents annually",
    "NIST CSF":   "US government contractors, critical infrastructure, or any org wanting a rigorous baseline",
    "ISO 27001":  "Companies that want a globally recognised, certifiable security standard",
    "Zero Trust": "Any company looking to modernise security beyond perimeter-based approaches",
}


def soc2_readiness_score(selected: dict[str, bool]) -> tuple[int, str]:
    """Compute an overall readiness percentage from a dict of
    {control_name: bool_evidenced}. Returns (percentage, qualitative band)."""
    if not selected:
        return 0, "Not Started"
    total = len(selected)
    done = sum(1 for v in selected.values() if v)
    pct = round(100 * done / total) if total else 0
    if pct >= 90:
        band = "Audit Ready"
    elif pct >= 70:
        band = "Substantially Ready"
    elif pct >= 40:
        band = "In Progress"
    else:
        band = "Early Stage"
    return pct, band


# ─────────────────────────────────────────────────────────────
# SOC ALERT BATCH IMPORT
# ─────────────────────────────────────────────────────────────
# Important scope note: this is a batch CSV import of alerts a SOC has
# already triaged and exported (e.g. from a SIEM export or ticket queue),
# not live log monitoring. The platform does not ingest streaming logs;
# it converts a point-in-time export of high-severity alerts into draft
# risk register entries for analyst review.
ALERT_SEVERITY_TO_RISK_SEVERITY = {
    "critical": "Critical", "high": "High",
    "medium": "Medium", "low": "Low",
}


def parse_alert_csv(file) -> pd.DataFrame:
    """Parse an exported batch of SOC alerts (a CSV export from a SIEM or
    ticket queue) into normalized draft entries. This is explicitly a
    batch/offline import, not a live monitoring connection."""
    df_raw = pd.read_csv(file)
    cols_lower = {c.lower().strip(): c for c in df_raw.columns}

    def col(*candidates):
        for c in candidates:
            if c in cols_lower:
                return cols_lower[c]
        return None

    title_col = col("alert", "alert name", "title", "rule name", "signature")
    sev_col = col("severity", "priority")
    host_col = col("host", "source", "asset", "src_ip", "device")
    desc_col = col("description", "details", "summary")

    rows = []
    for _, r in df_raw.iterrows():
        title = str(r.get(title_col, "Unnamed Alert")) if title_col else "Unnamed Alert"
        desc = str(r.get(desc_col, "")) if desc_col else ""
        combined_text = f"{title} {desc}"

        sev_raw = str(r.get(sev_col, "")).strip().lower() if sev_col else ""
        severity = ALERT_SEVERITY_TO_RISK_SEVERITY.get(sev_raw, "Medium")

        asset, threat = scanner_text_to_asset_threat(combined_text)

        rows.append({
            "Alert": title,
            "Severity": severity,
            "Asset": asset,
            "Threat": threat,
            "Host / Source": str(r.get(host_col, "")) if host_col else "",
        })

    return pd.DataFrame(rows)



# ─────────────────────────────────────────────────────────────
# ONBOARDING WIZARD
# ─────────────────────────────────────────────────────────────
def render_onboarding_wizard() -> None:
    """Full-screen onboarding wizard shown to first-time users.
    Sets wizard_complete = True and pre-populates session state when done."""

    st.markdown("""
    <div style="background:#0A1628;border-radius:12px;padding:32px 36px;margin-bottom:24px;">
        <h2 style="color:#F0F6FF;margin:0 0 6px 0;font-size:1.6rem;">👋 Welcome to your GRC Platform</h2>
        <p style="color:#7BA3C8;margin:0;font-size:0.95rem;">
            Answer 4 quick questions and we'll set everything up for your business.
            It takes less than a minute.
        </p>
    </div>
    """, unsafe_allow_html=True)

    with st.form("wizard_form"):
        st.markdown("#### 1. What's your company name?")
        company = st.text_input("Company name", placeholder="Acme Inc.",
                                label_visibility="collapsed")

        st.markdown("#### 2. What industry are you in?")
        industry = st.selectbox("Industry", ["Technology", "Healthcare", "Finance",
                                              "Retail", "Education", "Manufacturing", "Other"],
                                label_visibility="collapsed")

        st.markdown("#### 3. Which compliance frameworks matter most to you?")
        st.caption("Pick all that apply - you can change this later.")
        fw_cols = st.columns(4)
        fw_choices = {}
        for i, (fw, desc) in enumerate([
            ("SOC 2",    "SaaS / tech companies"),
            ("HIPAA",    "Healthcare companies"),
            ("PCI DSS",  "Takes card payments"),
            ("GDPR",     "Has EU customers"),
            ("CCPA",     "Has CA customers"),
            ("NIST CSF", "US gov / contractors"),
            ("ISO 27001","Global certification"),
        ]):
            col = fw_cols[i % 4]
            with col:
                fw_choices[fw] = st.checkbox(f"**{fw}**  \n{desc}", key=f"wiz_{fw}",
                                              value=(fw in ["SOC 2", "NIST CSF"]))

        st.markdown("#### 4. What's your biggest security concern right now?")
        concern = st.selectbox("Primary concern",
            ["Data breach / unauthorized access",
             "Passing a compliance audit (SOC 2, HIPAA, etc.)",
             "Employee security awareness and phishing",
             "Cloud misconfiguration",
             "Third-party / vendor risk",
             "Not sure - help me find out"],
            label_visibility="collapsed")

        submitted = st.form_submit_button("Set up my platform →", type="primary",
                                           use_container_width=True)

    if submitted:
        selected_fw = [fw for fw, checked in fw_choices.items() if checked]
        if not selected_fw:
            selected_fw = ["SOC 2", "NIST CSF"]

        st.session_state.wizard_complete  = True
        st.session_state.wizard_company   = company or "My Company"
        st.session_state.wizard_industry  = industry
        st.session_state.wizard_frameworks = selected_fw
        st.session_state.wizard_concern   = concern

        # Pre-suggest a first risk entry based on concern
        concern_to_asset_threat = {
            "Data breach / unauthorized access":           ("Database",          "Data Breach"),
            "Passing a compliance audit (SOC 2, HIPAA, etc.)": ("Cloud Environment", "Misconfiguration"),
            "Employee security awareness and phishing":    ("Email System",       "Phishing"),
            "Cloud misconfiguration":                      ("Cloud Environment",  "Misconfiguration"),
            "Third-party / vendor risk":                   ("Vendor / Third Party", "Supply Chain Attack"),
            "Not sure - help me find out":                 ("Database",          "Data Breach"),
        }
        asset, threat = concern_to_asset_threat.get(concern, ("Database", "Data Breach"))
        st.session_state.selected_asset  = asset
        st.session_state.selected_threat = threat

        st.success("✅ All set! Your platform is personalised and ready.")
        st.rerun()

    # Skip link
    st.markdown("")
    if st.button("Skip setup - go straight to the platform", type="secondary"):
        st.session_state.wizard_complete = True
        st.rerun()



# ─────────────────────────────────────────────────────────────
# AUTO-BUILD RISK REGISTER ENTRY FROM SOC FINDING / ALERT
# No user input required - everything derived from the file.
# ─────────────────────────────────────────────────────────────
def _sev_to_ce(severity: str) -> int:
    """Infer control effectiveness from severity.
    Critical finding → controls are basically absent (CE=1).
    Low finding → controls exist but have a minor gap (CE=4)."""
    return {"Critical": 1, "High": 2, "Medium": 3, "Low": 4, "Informational": 5}.get(severity, 2)

def _sev_to_av(severity: str) -> int:
    """Infer asset value from severity - higher severity usually means
    the affected asset is more critical."""
    return {"Critical": 5, "High": 4, "Medium": 3, "Low": 2, "Informational": 1}.get(severity, 3)

def _sev_to_biz_impact(severity: str) -> str:
    return {"Critical": "Critical", "High": "High", "Medium": "Medium",
            "Low": "Low", "Informational": "Low"}.get(severity, "Medium")

def auto_build_from_finding(
    finding_name: str,
    severity: str,
    asset: str,
    threat: str,
    host: str = "",
    cve: str = "",
    source_type: str = "Scanner",
) -> dict:
    """Convert a parsed scanner/alert row into a full risk register entry
    using the same two-stage scoring model as manual entries.
    No user interaction required."""
    likelihood, impact = severity_to_likelihood_impact(severity)
    av  = _sev_to_av(severity)
    ce  = _sev_to_ce(severity)
    biz = _sev_to_biz_impact(severity)

    company  = st.session_state.get("wizard_company", "My Company")
    industry = st.session_state.get("wizard_industry", "Technology")

    host_note = f" Affected host: {host}." if host else ""
    cve_note  = f" CVE: {cve}." if cve else ""
    summary   = (
        f"Auto-imported from {source_type} export. "
        f"Finding: {finding_name}.{host_note}{cve_note} "
        f"Severity: {severity}. Asset: {asset}. Threat: {threat}. "
        f"Review and update evidence once remediation begins."
    )

    return build_result(
        asset=asset, threat=threat,
        likelihood=likelihood, impact=impact,
        asset_value=av, control_effectiveness=ce,
        reasons=[f"Auto-scored from {source_type} export",
                 f"Severity '{severity}' → L={likelihood} I={impact} AV={av} CE={ce}"],
        plain_summary=summary,
        actions=[
            {"tag": "Immediate", "text": f"Review {finding_name} and assign a remediation owner."},
            {"tag": "This week",  "text": f"Apply patches or configuration fixes for {threat.lower()}."},
            {"tag": "Document",   "text": "Upload evidence of remediation and mark Audit Status accordingly."},
        ],
        confidence="medium",
        company=company, industry=industry,
        department="IT / Security", owner="Security Team",
        status="Open",
        review_date=datetime.now().date(),
        financial_impact=biz, operational_impact=biz, compliance_impact=biz,
        business_process="IT Operations",
        vulnerability_name=f"{finding_name}{cve_note}",
        vulnerability_severity=severity,
        vulnerability_source=source_type,
        evidence_name="",
        evidence_owner="Security Team",
        audit_status="Evidence Missing",
    )


def render_soc_preview_and_save(
    df: pd.DataFrame,
    name_col: str,
    source_type: str,
    save_key: str,
):
    """Render a styled preview table of auto-scored findings and a single
    'Save All to Register' button. No dropdowns, no per-row interaction."""
    from datetime import date as _date

    sev_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Informational": 4}
    df = df.copy()
    df["_sort"] = df["Severity"].map(sev_order).fillna(5)
    df = df.sort_values("_sort").drop(columns="_sort").reset_index(drop=True)

    # Pre-compute full scored entries for every row
    entries = []
    for _, row in df.iterrows():
        finding  = str(row.get(name_col, "Unnamed Finding"))
        severity = str(row.get("Severity", "Medium"))
        asset    = str(row.get("Asset", "Server"))
        threat   = str(row.get("Threat", "Misconfiguration"))
        host     = str(row.get("Host", row.get("Host / Source", "")))
        cve      = str(row.get("CVE", ""))
        entries.append(auto_build_from_finding(finding, severity, asset, threat,
                                               host, cve, source_type))

    # Severity badge colours
    SEV_COLOR = {
        "CRITICAL": ("#FEF2F2", "#991B1B"),
        "HIGH":     ("#FFF7ED", "#9A3412"),
        "MEDIUM":   ("#FEFCE8", "#854D0E"),
        "LOW":      ("#F0FDF4", "#166534"),
    }

    # Summary metrics
    levels = [e["Residual Level"] for e in entries]
    mc = st.columns(4)
    for i, lv in enumerate(["CRITICAL","HIGH","MEDIUM","LOW"]):
        count = levels.count(lv)
        bg, fg = SEV_COLOR[lv]
        mc[i].markdown(
            f'<div style="background:{bg};border-radius:8px;padding:12px 16px;text-align:center;">'
            f'<div style="font-size:1.6rem;font-weight:800;color:{fg};">{count}</div>'
            f'<div style="font-size:0.72rem;font-weight:700;color:{fg};text-transform:uppercase;">{lv}</div>'
            f'</div>', unsafe_allow_html=True
        )
    st.markdown("")

    # Preview table - styled HTML, no dropdowns
    rows_html = ""
    for i, (e, (_, row)) in enumerate(zip(entries, df.iterrows())):
        lv  = e["Residual Level"]
        bg, fg = SEV_COLOR.get(lv, ("#F8FAFC","#475569"))
        sev = str(row.get("Severity",""))
        sbg, sfg = SEV_COLOR.get(sev.upper(), ("#F8FAFC","#475569"))
        rows_html += f"""
        <tr style="border-bottom:1px solid #F1F5F9;">
          <td style="padding:10px 12px;color:#64748B;font-size:0.82rem;font-weight:600;">{i+1}</td>
          <td style="padding:10px 12px;font-size:0.85rem;color:#0F172A;max-width:220px;word-break:break-word;">
            {e['Vulnerability / Finding'][:80]}
          </td>
          <td style="padding:10px 12px;">
            <span style="background:{sbg};color:{sfg};border-radius:12px;padding:3px 10px;
                         font-size:0.72rem;font-weight:700;">{sev}</span>
          </td>
          <td style="padding:10px 12px;font-size:0.83rem;color:#334155;">{e['Asset']}</td>
          <td style="padding:10px 12px;font-size:0.83rem;color:#334155;">{e['Threat']}</td>
          <td style="padding:10px 12px;font-weight:700;font-size:0.9rem;color:{fg};">{e['Residual Risk']}/25</td>
          <td style="padding:10px 12px;">
            <span style="background:{bg};color:{fg};border-radius:12px;padding:3px 10px;
                         font-size:0.72rem;font-weight:700;">{lv}</span>
          </td>
          <td style="padding:10px 12px;font-size:0.8rem;color:#475569;">{e['Final Treatment']}</td>
        </tr>"""

    st.markdown(f"""
    <div style="overflow-x:auto;border:1px solid #E2E8F0;border-radius:10px;">
    <table style="width:100%;border-collapse:collapse;font-family:Inter,sans-serif;">
      <thead>
        <tr style="background:#F8FAFC;border-bottom:2px solid #E2E8F0;">
          <th style="padding:10px 12px;text-align:left;font-size:0.72rem;color:#64748B;font-weight:700;">#</th>
          <th style="padding:10px 12px;text-align:left;font-size:0.72rem;color:#64748B;font-weight:700;">FINDING</th>
          <th style="padding:10px 12px;text-align:left;font-size:0.72rem;color:#64748B;font-weight:700;">SEVERITY</th>
          <th style="padding:10px 12px;text-align:left;font-size:0.72rem;color:#64748B;font-weight:700;">ASSET</th>
          <th style="padding:10px 12px;text-align:left;font-size:0.72rem;color:#64748B;font-weight:700;">THREAT</th>
          <th style="padding:10px 12px;text-align:left;font-size:0.72rem;color:#64748B;font-weight:700;">RISK SCORE</th>
          <th style="padding:10px 12px;text-align:left;font-size:0.72rem;color:#64748B;font-weight:700;">LEVEL</th>
          <th style="padding:10px 12px;text-align:left;font-size:0.72rem;color:#64748B;font-weight:700;">ACTION</th>
        </tr>
      </thead>
      <tbody>{rows_html}</tbody>
    </table>
    </div>
    """, unsafe_allow_html=True)

    st.markdown("")

    # Framework coverage note
    fw_list = ", ".join(st.session_state.get("wizard_frameworks",
                        ["NIST CSF", "ISO 27001", "SOC 2"]))
    st.info(
        f"Each finding will be saved with full framework mappings ({fw_list}), "
        f"recommended controls, Zero Trust guidance, audit tracking, and business impact analysis - "
        f"all included automatically in your unified PDF report."
    )

    # THE button
    already_saved = st.session_state.get(save_key, False)
    if already_saved:
        st.success(
            f"✅ {len(entries)} finding(s) already saved to the Risk Register. "
            f"Go to 📊 Risk Register & Reports to download your report."
        )
        if st.button(f"🔄 Re-import (replace previous import)", key=save_key+"_redo"):
            st.session_state[save_key] = False
            st.rerun()
    else:
        if role_info["can_edit"]:
            if st.button(
                f"✅ Save All {len(entries)} Finding(s) to Risk Register",
                type="primary",
                use_container_width=True,
                key=save_key+"_btn",
            ):
                for e in entries:
                    st.session_state.history.append(e)
                st.session_state[save_key] = True
                st.session_state.active_tab = 1   # jump to Register & Reports
                st.rerun()
        else:
            st.warning("Switch to Admin or Manager role in the sidebar to save findings.")



# ─────────────────────────────────────────────────────────────
# EXECUTIVE SUMMARY ONE-PAGER PDF
# ─────────────────────────────────────────────────────────────
def generate_executive_summary_pdf(
    df: pd.DataFrame,
    soc2_state: dict,
    scanner_df,
    alert_df,
) -> str:
    """Single-page executive summary a CEO can hand to their board or auditor."""
    path = tempfile.NamedTemporaryFile(delete=False, suffix=".pdf",
                                       prefix="grc_exec_summary_").name
    st.session_state["_temp_files"].append(path)

    doc = SimpleDocTemplate(path, pagesize=letter,
                            rightMargin=40, leftMargin=40,
                            topMargin=50, bottomMargin=40)
    styles = getSampleStyleSheet()
    NAVY  = colors.HexColor("#0F172A")
    BLUE  = colors.HexColor("#1D4ED8")
    TEAL  = colors.HexColor("#0E7C7B")
    RED   = colors.HexColor("#DC2626")
    AMBER = colors.HexColor("#D97706")
    GREEN = colors.HexColor("#16A34A")
    SLATE = colors.HexColor("#475569")
    LIGHT = colors.HexColor("#F1F5F9")

    S = {
        "co":   ParagraphStyle("co", fontName="Helvetica-Bold", fontSize=18,
                               textColor=colors.white, alignment=TA_LEFT),
        "sub":  ParagraphStyle("su", fontName="Helvetica", fontSize=9,
                               textColor=colors.HexColor("#93C5FD"), alignment=TA_LEFT),
        "h1":   ParagraphStyle("h1", fontName="Helvetica-Bold", fontSize=13,
                               textColor=NAVY, spaceBefore=10, spaceAfter=4),
        "h2":   ParagraphStyle("h2", fontName="Helvetica-Bold", fontSize=10,
                               textColor=BLUE, spaceBefore=6, spaceAfter=2),
        "body": ParagraphStyle("bo", fontName="Helvetica", fontSize=9,
                               textColor=SLATE, leading=13),
        "note": ParagraphStyle("no", fontName="Helvetica-Oblique", fontSize=7.5,
                               textColor=colors.HexColor("#94A3B8")),
    }

    company = st.session_state.get("wizard_company", "Your Company") or "Your Company"
    industry = st.session_state.get("wizard_industry", "Technology")
    fw_list  = ", ".join(st.session_state.get("wizard_frameworks", ["SOC 2", "NIST CSF"]))

    # ── Overall risk score ────────────────────────────────────
    if not df.empty:
        avg_residual = round(df["Residual Risk"].mean(), 1)
        max_residual = df["Residual Risk"].max()
        critical_n   = (df["Residual Level"] == "CRITICAL").sum()
        high_n       = (df["Residual Level"] == "HIGH").sum()
        medium_n     = (df["Residual Level"] == "MEDIUM").sum()
        low_n        = (df["Residual Level"] == "LOW").sum()
        open_n       = (df["Status"] != "Closed").sum()
        posture_pct  = round(100 - (avg_residual / 25) * 100)
    else:
        avg_residual = max_residual = 0
        critical_n = high_n = medium_n = low_n = open_n = 0
        posture_pct = 100

    if posture_pct >= 75:   posture_label, posture_color = "GOOD",     GREEN
    elif posture_pct >= 50: posture_label, posture_color = "MODERATE", AMBER
    else:                   posture_label, posture_color = "AT RISK",  RED

    # ── SOC 2 readiness ───────────────────────────────────────
    soc2_pct, soc2_band = soc2_readiness_score(soc2_state) if soc2_state else (0, "Not assessed")

    # ── Scanner / alert counts ────────────────────────────────
    scan_n  = len(scanner_df) if scanner_df is not None else 0
    alert_n = len(alert_df)   if alert_df   is not None else 0

    c = []

    # ── HERO HEADER BAND ──────────────────────────────────────
    header_tbl = Table([[
        Paragraph(f"{company}", S["co"]),
        Paragraph(f"GRC Executive Risk Summary", S["co"]),
        Paragraph(f"{datetime.now().strftime('%B %d, %Y')}", S["co"]),
    ]], colWidths=[160, 240, 100])
    header_tbl.setStyle(TableStyle([
        ("BACKGROUND",   (0,0),(-1,-1), NAVY),
        ("TOPPADDING",   (0,0),(-1,-1), 14),
        ("BOTTOMPADDING",(0,0),(-1,-1), 14),
        ("LEFTPADDING",  (0,0),(-1,-1), 14),
        ("RIGHTPADDING", (0,0),(-1,-1), 14),
        ("ALIGN",        (2,0),(2,0), "RIGHT"),
        ("TEXTCOLOR",    (0,0),(-1,-1), colors.white),
        ("FONTNAME",     (0,0),(-1,-1), "Helvetica-Bold"),
        ("FONTSIZE",     (0,0),(-1,-1), 11),
    ]))
    c.append(header_tbl)
    c.append(Spacer(1, 10))

    # ── OVERALL POSTURE + KEY METRICS ─────────────────────────
    posture_cell = f"""<para align="center">
        <b><font size="36" color="{posture_color.hexval()}">{posture_pct}%</font></b><br/>
        <font size="10" color="{posture_color.hexval()}"><b>{posture_label}</b></font><br/>
        <font size="8" color="#64748B">Security Posture Score</font>
    </para>"""

    metric_rows = [
        ["Total Risks Assessed", str(len(df))],
        ["Critical / High Risks", f"{critical_n} / {high_n}"],
        ["Open Items",            str(open_n)],
        ["Avg Residual Risk",     f"{avg_residual} / 25"],
        ["Scanner Findings",      str(scan_n)],
        ["SOC 2 Readiness",       f"{soc2_pct}%  ({soc2_band})"],
    ]

    metric_tbl = Table(
        [[Paragraph(k, ParagraphStyle("mk", fontName="Helvetica-Bold", fontSize=8.5,
                                       textColor=SLATE)),
          Paragraph(v, ParagraphStyle("mv", fontName="Helvetica-Bold", fontSize=8.5,
                                       textColor=NAVY, alignment=1))]
         for k, v in metric_rows],
        colWidths=[130, 80]
    )
    metric_tbl.setStyle(TableStyle([
        ("ROWBACKGROUNDS", (0,0),(-1,-1), [colors.white, LIGHT]),
        ("TOPPADDING",    (0,0),(-1,-1), 5),
        ("BOTTOMPADDING", (0,0),(-1,-1), 5),
        ("LEFTPADDING",   (0,0),(-1,-1), 8),
        ("GRID",          (0,0),(-1,-1), 0.3, colors.HexColor("#E2E8F0")),
    ]))

    risk_bar_data = [["CRITICAL", "HIGH", "MEDIUM", "LOW"],
                     [str(critical_n), str(high_n), str(medium_n), str(low_n)]]
    risk_bar = Table(risk_bar_data, colWidths=[60,60,60,60])
    risk_bar.setStyle(TableStyle([
        ("BACKGROUND",    (0,0),(0,0), colors.HexColor("#991B1B")),
        ("BACKGROUND",    (1,0),(1,0), colors.HexColor("#DC2626")),
        ("BACKGROUND",    (2,0),(2,0), colors.HexColor("#D97706")),
        ("BACKGROUND",    (3,0),(3,0), colors.HexColor("#16A34A")),
        ("TEXTCOLOR",     (0,0),(-1,0), colors.white),
        ("FONTNAME",      (0,0),(-1,0), "Helvetica-Bold"),
        ("FONTSIZE",      (0,0),(-1,-1), 8),
        ("ALIGN",         (0,0),(-1,-1), "CENTER"),
        ("TOPPADDING",    (0,0),(-1,-1), 5),
        ("BOTTOMPADDING", (0,0),(-1,-1), 5),
        ("TEXTCOLOR",     (0,1),(-1,-1), NAVY),
        ("FONTNAME",      (0,1),(-1,-1), "Helvetica-Bold"),
        ("FONTSIZE",      (0,1),(-1,-1), 14),
    ]))

    top_section = Table([
        [Paragraph(posture_cell, styles["Normal"]),
         metric_tbl,
         risk_bar],
    ], colWidths=[130, 220, 150])
    top_section.setStyle(TableStyle([
        ("VALIGN",       (0,0),(-1,-1), "MIDDLE"),
        ("LEFTPADDING",  (0,0),(-1,-1), 8),
        ("RIGHTPADDING", (0,0),(-1,-1), 8),
        ("BOX",          (0,0),(-1,-1), 0.5, colors.HexColor("#E2E8F0")),
        ("BACKGROUND",   (0,0),(0,-1), LIGHT),
        ("ROWBACKGROUNDS",(2,0),(2,-1), [colors.HexColor("#F8FAFC")]),
    ]))
    c.append(top_section)
    c.append(Spacer(1, 10))

    # ── FRAMEWORK READINESS ───────────────────────────────────
    c.append(Paragraph("Framework Readiness", S["h1"]))
    fw_data = [["Framework", "Status", "Relevance"]]
    fw_defs = {
        "SOC 2":     (f"{soc2_pct}%  ({soc2_band})" if soc2_state else "Not assessed",
                      "Required by enterprise customers"),
        "HIPAA":     ("Self-assessment required", "Healthcare / health data"),
        "PCI DSS":   ("Self-assessment required", "Card payment processing"),
        "GDPR":      ("Self-assessment required", "EU customer data"),
        "CCPA":      ("Self-assessment required", "California consumer data"),
        "NIST CSF":  ("Framework aligned",        "US government / contractors"),
        "ISO 27001": ("Framework aligned",        "International certification"),
    }
    for fw, (status, relevance) in fw_defs.items():
        if fw in st.session_state.get("wizard_frameworks", []):
            fw_data.append([fw, status, relevance])
    if len(fw_data) == 1:
        fw_data.append(["SOC 2", f"{soc2_pct}%  ({soc2_band})" if soc2_state else "Not assessed",
                         "Required by enterprise customers"])
    fw_tbl = Table(fw_data, colWidths=[100, 160, 220])
    fw_tbl.setStyle(TableStyle([
        ("BACKGROUND",    (0,0),(-1,0), BLUE),
        ("TEXTCOLOR",     (0,0),(-1,0), colors.white),
        ("FONTNAME",      (0,0),(-1,0), "Helvetica-Bold"),
        ("FONTSIZE",      (0,0),(-1,-1), 8.5),
        ("ROWBACKGROUNDS",(0,1),(-1,-1), [colors.white, LIGHT]),
        ("GRID",          (0,0),(-1,-1), 0.3, colors.HexColor("#E2E8F0")),
        ("TOPPADDING",    (0,0),(-1,-1), 4),
        ("BOTTOMPADDING", (0,0),(-1,-1), 4),
        ("LEFTPADDING",   (0,0),(-1,-1), 8),
    ]))
    c.append(fw_tbl)
    c.append(Spacer(1, 10))

    # ── TOP RISKS ─────────────────────────────────────────────
    c.append(Paragraph("Top Risks Requiring Immediate Attention", S["h1"]))
    if not df.empty:
        top_risks = df.nlargest(min(5, len(df)), "Residual Risk")
        risk_rows = [["#", "Risk", "Level", "Score", "Recommended Action"]]
        for i, (_, row) in enumerate(top_risks.iterrows(), 1):
            risk_rows.append([
                str(i),
                f"{row['Asset']} - {row['Threat']}"[:45],
                row.get("Residual Level", ""),
                f"{row['Residual Risk']}/25",
                (row.get("Final Treatment","") + " - " +
                 str(row.get("Next Steps","")).split(" | ")[0])[:55],
            ])
        lv_colors = {"CRITICAL": "#FEF2F2", "HIGH": "#FFF7ED",
                     "MEDIUM": "#FEFCE8", "LOW": "#F0FDF4"}
        risk_tbl = Table(risk_rows, colWidths=[18, 150, 55, 38, 219])
        risk_style = [
            ("BACKGROUND",    (0,0),(-1,0), TEAL),
            ("TEXTCOLOR",     (0,0),(-1,0), colors.white),
            ("FONTNAME",      (0,0),(-1,0), "Helvetica-Bold"),
            ("FONTSIZE",      (0,0),(-1,-1), 8),
            ("GRID",          (0,0),(-1,-1), 0.3, colors.HexColor("#E2E8F0")),
            ("TOPPADDING",    (0,0),(-1,-1), 4),
            ("BOTTOMPADDING", (0,0),(-1,-1), 4),
            ("LEFTPADDING",   (0,0),(-1,-1), 6),
            ("VALIGN",        (0,0),(-1,-1), "MIDDLE"),
        ]
        for ri, (_, row) in enumerate(top_risks.iterrows(), 1):
            bg = lv_colors.get(row.get("Residual Level",""), "#FFFFFF")
            risk_style.append(("BACKGROUND", (2,ri),(2,ri), colors.HexColor(bg)))
        risk_tbl.setStyle(TableStyle(risk_style))
        c.append(risk_tbl)
    else:
        c.append(Paragraph("No risks assessed yet. Add risks in the Risk Assessment tab.", S["body"]))
    c.append(Spacer(1, 10))

    # ── IMMEDIATE ACTIONS ─────────────────────────────────────
    c.append(Paragraph("Recommended Immediate Actions", S["h1"]))
    actions = []
    if not df.empty:
        critical_risks = df[df["Residual Level"] == "CRITICAL"]
        high_risks     = df[df["Residual Level"] == "HIGH"]
        if not critical_risks.empty:
            actions.append(f"🔴 CRITICAL: Address {len(critical_risks)} critical risk(s) immediately - "
                           f"start with {critical_risks.iloc[0]['Asset']} / {critical_risks.iloc[0]['Threat']}.")
        if not high_risks.empty:
            actions.append(f"🟠 HIGH: Schedule remediation for {len(high_risks)} high risk(s) "
                           f"within the next 30 days.")
        if soc2_state and soc2_pct < 70:
            missing = sum(1 for v in soc2_state.values() if not v)
            actions.append(f"📋 SOC 2: {missing} control(s) still need evidence. "
                           f"Current readiness: {soc2_pct}% ({soc2_band}).")
        if scan_n > 0:
            actions.append(f"🛡️ SCANNER: {scan_n} vulnerability finding(s) imported. "
                           f"Review Critical/High findings first.")
        if not actions:
            actions.append("✅ No critical or high risks identified. Continue monitoring and review quarterly.")
    else:
        actions = ["Complete a risk assessment to generate recommended actions."]

    for action in actions:
        c.append(Paragraph(f"• {action}", S["body"]))
        c.append(Spacer(1, 3))
    c.append(Spacer(1, 8))

    # ── FOOTER ────────────────────────────────────────────────
    footer_tbl = Table([[
        Paragraph("Enterprise GRC Risk Intelligence Platform  ·  Built by Saloni Bhosale  ·  "
                  "  ·  Based on peer-reviewed research (KBO 2026)",
                  S["note"]),
        Paragraph(f"Industry: {industry}  ·  Frameworks: {fw_list}  ·  "
                  f"Methodology: NIST SP 800-30 Rev 1 · ISO 27005:2022",
                  S["note"]),
    ]], colWidths=[250, 250])
    footer_tbl.setStyle(TableStyle([
        ("BACKGROUND",   (0,0),(-1,-1), LIGHT),
        ("TOPPADDING",   (0,0),(-1,-1), 6),
        ("BOTTOMPADDING",(0,0),(-1,-1), 6),
        ("LEFTPADDING",  (0,0),(-1,-1), 10),
        ("BOX",          (0,0),(-1,-1), 0.3, colors.HexColor("#CBD5E1")),
    ]))
    c.append(footer_tbl)

    doc.build(c)
    return path


# ─────────────────────────────────────────────────────────────
# LANDING PAGE
# ─────────────────────────────────────────────────────────────
def render_landing_page() -> None:
    """Professional marketing landing page shown before the app."""

    st.markdown("""
    <style>
    .lp-hero {
        background: linear-gradient(135deg, #0F172A 0%, #1E3A5F 40%, #1D4ED8 100%);
        border-radius: 16px; padding: 56px 48px; margin-bottom: 32px;
        text-align: center; position: relative; overflow: hidden;
    }
    .lp-hero::before {
        content:''; position:absolute; top:-80px; right:-80px;
        width:300px; height:300px; background:rgba(99,179,237,0.1); border-radius:50%;
    }
    .lp-hero-eyebrow {
        background: rgba(99,179,237,0.15); border: 1px solid rgba(99,179,237,0.3);
        border-radius: 20px; display: inline-block;
        padding: 6px 16px; font-size: 0.78rem; font-weight: 700;
        color: #93C5FD; letter-spacing: 0.08em; margin-bottom: 20px;
    }
    .lp-hero h1 {
        font-size: 2.8rem; font-weight: 800; color: white !important;
        line-height: 1.15; letter-spacing: -0.03em; margin: 0 0 16px 0;
    }
    .lp-hero p {
        font-size: 1.1rem; color: #93C5FD !important;
        max-width: 600px; margin: 0 auto 28px auto; line-height: 1.65;
    }
    .lp-pain h2 { font-size:1.7rem; font-weight:800; color:#0F172A; margin-bottom:8px; text-align:center; }
    .lp-pain p  { font-size:0.95rem; color:#64748B; max-width:520px; margin:0 auto; text-align:center; }
    .lp-card {
        background:white; border:1px solid #E2E8F0; border-radius:12px;
        padding:24px; text-align:center; height:100%;
        box-shadow: 0 2px 8px rgba(0,0,0,0.04); margin-bottom:12px;
    }
    .lp-card-icon { font-size:2rem; margin-bottom:12px; }
    .lp-card h3 { font-size:1rem; font-weight:700; color:#0F172A; margin-bottom:6px; }
    .lp-card p  { font-size:0.82rem; color:#64748B; line-height:1.6; margin:0; }
    .lp-stat { text-align:center; padding:16px; }
    .lp-stat-num   { font-size:2.4rem; font-weight:800; color:#1D4ED8; line-height:1; }
    .lp-stat-label { font-size:0.78rem; color:#64748B; margin-top:4px; line-height:1.4; }
    .lp-trust {
        background:linear-gradient(135deg,#0F172A,#1E3A5F);
        border-radius:12px; padding:32px 36px; margin:24px 0; text-align:center;
    }
    .lp-trust h2 { color:white; font-size:1.3rem; font-weight:700; margin-bottom:12px; }
    .lp-trust p  { color:#93C5FD; font-size:0.88rem; margin:0; line-height:1.7; }
    .lp-framework-badge {
        display:inline-block; background:rgba(255,255,255,0.1);
        border:1px solid rgba(255,255,255,0.2); border-radius:20px;
        padding:4px 14px; font-size:0.78rem; color:white; margin:4px;
    }
    .lp-steps {
        display:grid; grid-template-columns:repeat(3,1fr); gap:16px;
        margin:16px 0 24px 0;
    }
    .lp-step {
        background:#F8FAFC; border:1px solid #E2E8F0; border-radius:12px;
        padding:20px; text-align:center;
    }
    .lp-step-num {
        width:36px; height:36px; background:#1D4ED8; color:white;
        border-radius:50%; font-size:1rem; font-weight:800;
        display:flex; align-items:center; justify-content:center;
        margin:0 auto 12px auto;
    }
    .lp-step h3 { font-size:0.92rem; font-weight:700; color:#0F172A; margin-bottom:4px; }
    .lp-step p  { font-size:0.78rem; color:#64748B; margin:0; line-height:1.5; }
    </style>
    """, unsafe_allow_html=True)

    # ── HERO ─────────────────────────────────────────────────
    st.markdown("""
    <div class="lp-hero">
      <div class="lp-hero-eyebrow">✦ GRC BUILT FOR SMALL BUSINESSES</div>
      <h1>Your compliance programme,<br>ready in minutes</h1>
      <p>Risk scoring, SOC 2 readiness, vulnerability scanning, and
         audit-ready reports - all in one platform. No GRC expertise required.</p>
    </div>
    """, unsafe_allow_html=True)

    # ── CTA BUTTONS ──────────────────────────────────────────
    cta1, cta2, cta3 = st.columns([2, 2, 3])
    with cta1:
        if st.button("🚀 Get started - free",
                     type="primary", use_container_width=True):
            st.session_state.landing_visited = True
            st.rerun()
    with cta2:
        if st.button("▶ Load a live demo",
                     use_container_width=True):
            st.session_state.landing_visited = True
            st.session_state.wizard_complete = True
            if not st.session_state.history:
                st.session_state.history.append(build_demo_risk())
            st.rerun()

    st.markdown("<br>", unsafe_allow_html=True)

    # ── PAIN POINTS ──────────────────────────────────────────
    st.markdown("""
    <div class="lp-pain">
      <h2>The problem with most GRC tools</h2>
      <p>They were built for companies with a dedicated security team
         and a six-figure budget. Most small businesses have neither.</p>
    </div>
    """, unsafe_allow_html=True)
    st.markdown("<br>", unsafe_allow_html=True)

    p1, p2, p3 = st.columns(3)
    pains = [
        ("💸", "Too expensive",
         "Enterprise GRC platforms cost tens of thousands per year - "
         "before you've even started your first audit."),
        ("🏗️", "Too complex to set up",
         "Most tools require weeks of configuration and a trained admin "
         "before you can do anything useful."),
        ("😵", "Assumes you already know GRC",
         "You're a founder, an ops manager, or an IT generalist. "
         "You need a tool that guides you, not one that expects expertise."),
    ]
    for col, (icon, title, desc) in zip([p1, p2, p3], pains):
        with col:
            st.markdown(f"""
            <div class="lp-card">
              <div class="lp-card-icon">{icon}</div>
              <h3>{title}</h3>
              <p>{desc}</p>
            </div>
            """, unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)

    # ── HOW IT WORKS ─────────────────────────────────────────
    st.markdown("### How it works")
    st.markdown("""
    <div class="lp-steps">
      <div class="lp-step">
        <div class="lp-step-num">1</div>
        <h3>Tell us about your business</h3>
        <p>Answer 4 quick questions - industry, size, which compliance
           frameworks you need. Takes under 2 minutes.</p>
      </div>
      <div class="lp-step">
        <div class="lp-step-num">2</div>
        <h3>Assess your risks</h3>
        <p>Describe a risk in plain English or upload a scanner file.
           The platform scores everything automatically using a validated model.</p>
      </div>
      <div class="lp-step">
        <div class="lp-step-num">3</div>
        <h3>Download your report</h3>
        <p>Get a professional PDF - including an executive one-pager
           you can hand to your board, a customer, or an auditor.</p>
      </div>
    </div>
    """, unsafe_allow_html=True)

    # ── STATS ────────────────────────────────────────────────
    s1, s2, s3, s4 = st.columns(4)
    stats = [
        ("8",       "compliance frameworks built in"),
        ("< 2 min", "to your first risk score"),
        ("0",       "GRC expertise required"),
        ("1 PDF",   "executive summary for your board"),
    ]
    for col, (num, label) in zip([s1, s2, s3, s4], stats):
        with col:
            st.markdown(f"""
            <div class="lp-stat">
              <div class="lp-stat-num">{num}</div>
              <div class="lp-stat-label">{label}</div>
            </div>
            """, unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)

    # ── FEATURES ─────────────────────────────────────────────
    st.markdown("### Everything you need in one place")
    f1, f2, f3 = st.columns(3)
    features = [
        ("🎯", "Validated Risk Scoring",
         "A two-stage model that separates inherent risk from residual risk - "
         "so improving your controls actually shows up in the score."),
        ("🤖", "AI Risk Identification",
         "Describe an incident in plain English and the platform identifies the "
         "asset, threat, and risk score. No jargon required."),
        ("🛡️", "8 Compliance Frameworks",
         "SOC 2, HIPAA, PCI DSS, GDPR, CCPA, NIST CSF 2.0, ISO 27001, "
         "and Zero Trust - all mapped automatically."),
        ("📥", "Vulnerability Scanner Import",
         "Upload a Nessus or Qualys export. Every finding is auto-scored "
         "and added to your risk register with one click."),
        ("📊", "Executive Summary PDF",
         "A board-ready one-pager: security posture score, top risks, "
         "framework readiness, and recommended actions."),
        ("✅", "SOC 2 Readiness Tracker",
         "Control-by-control checklist with a readiness percentage - "
         "know exactly what's missing before your audit."),
        ("📋", "Audit Evidence Tracking",
         "Four-state evidence workflow with file upload. "
         "Give auditors a clean trail without manual spreadsheets."),
        ("🧾", "Professional PDF Reports",
         "Full technical report covering risks, framework mappings, "
         "controls, audit evidence, and business impact."),
        ("🔒", "Role-Based Access",
         "Admin, Manager, and Viewer roles so the right people "
         "see the right information."),
    ]
    for i, (icon, title, desc) in enumerate(features):
        with [f1, f2, f3][i % 3]:
            st.markdown(f"""
            <div class="lp-card">
              <div class="lp-card-icon">{icon}</div>
              <h3>{title}</h3>
              <p>{desc}</p>
            </div>
            """, unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)

    # ── TRUST - one subtle research badge, not a full section ─
    st.markdown("""
    <div class="lp-trust">
      <h2>A methodology you can defend</h2>
      <p>
        The risk scoring model is grounded in NIST SP 800-30 Rev 1, ISO 27005:2022,
        and the Analytic Hierarchy Process. It has been independently validated across
        625 input combinations and produces results that are reproducible and explainable —
        not arbitrary defaults.<br><br>
        All 8 compliance frameworks are mapped at control level,
        so every risk entry automatically shows you exactly which standard requires attention.
      </p>
      <br>
      <span class="lp-framework-badge">NIST SP 800-30 Rev 1</span>
      <span class="lp-framework-badge">ISO 27005:2022</span>
      <span class="lp-framework-badge">NIST CSF 2.0</span>
      <span class="lp-framework-badge">ISO 27001:2022</span>
      <span class="lp-framework-badge">AICPA SOC 2</span>
      <span class="lp-framework-badge">HIPAA §164</span>
      <span class="lp-framework-badge">PCI DSS v4.0</span>
      <span class="lp-framework-badge">GDPR Art. 32</span>
      <span class="lp-framework-badge">CCPA §1798</span>
      <span class="lp-framework-badge">Zero Trust (NIST SP 800-207)</span>
    </div>
    """, unsafe_allow_html=True)

    # ── FINAL CTA ────────────────────────────────────────────
    st.markdown("### Ready?")
    fc1, fc2 = st.columns(2)
    with fc1:
        if st.button("🚀 Get started - free",
                     type="primary", use_container_width=True, key="cta_bottom"):
            st.session_state.landing_visited = True
            st.rerun()
    with fc2:
        if st.button("▶ See a live demo",
                     use_container_width=True, key="demo_bottom"):
            st.session_state.landing_visited = True
            st.session_state.wizard_complete = True
            if not st.session_state.history:
                st.session_state.history.append(build_demo_risk())
            st.rerun()

    # ── FOOTER ───────────────────────────────────────────────
    st.markdown("""
    <div style="text-align:center;color:#94A3B8;font-size:0.78rem;
                margin-top:24px;padding-top:16px;border-top:1px solid #E2E8F0;">
      Built by <strong style="color:#475569;">Saloni Bhosale</strong> ·
       ·
      GRC Risk Intelligence Platform v3.0
    </div>
    """, unsafe_allow_html=True)



# ─────────────────────────────────────────────────────────────
# RISK DISCOVERY QUESTIONNAIRE
# 15 plain-English questions → automatic risk register
# No GRC knowledge required from the user.
# ─────────────────────────────────────────────────────────────

# Each question has:
#   id:       unique key for session state
#   q:        the plain-English question shown to the user
#   options:  simple Yes/No or multi-choice answers
#   type:     "yesno" | "choice" | "multi"

DISCOVERY_QUESTIONS = [
    {
        "id":  "q_payments",
        "q":   "Does your business take card payments or store payment information?",
        "type": "yesno",
        "hint": "This includes credit/debit cards via Stripe, Square, PayPal, or any payment terminal.",
    },
    {
        "id":  "q_health",
        "q":   "Do you handle any patient or health information?",
        "type": "yesno",
        "hint": "This includes medical records, health insurance details, prescriptions, or any personal health data.",
    },
    {
        "id":  "q_eu_customers",
        "q":   "Do you have customers or users in Europe?",
        "type": "yesno",
        "hint": "If anyone in the EU/UK can sign up for or use your service, GDPR likely applies.",
    },
    {
        "id":  "q_cloud",
        "q":   "Do you use cloud services like AWS, Google Cloud, Azure, or cloud storage like Dropbox/Google Drive?",
        "type": "yesno",
        "hint": "Most businesses use at least one. If you're not sure, answer Yes.",
    },
    {
        "id":  "q_remote",
        "q":   "Do employees work remotely or use personal devices for work?",
        "type": "yesno",
        "hint": "Includes working from home, using personal laptops or phones to access company systems.",
    },
    {
        "id":  "q_vendors",
        "q":   "Do you share customer data with any third-party tools or vendors?",
        "type": "yesno",
        "hint": "Examples: a CRM (HubSpot, Salesforce), marketing platform, accounting software, or any SaaS tool your team uses.",
    },
    {
        "id":  "q_email",
        "q":   "Does your team use email for business communications?",
        "type": "yesno",
        "hint": "Almost every business does. This assesses your phishing and business email compromise exposure.",
    },
    {
        "id":  "q_database",
        "q":   "Do you store customer, employee, or business data in a database or CRM?",
        "type": "yesno",
        "hint": "Examples: customer lists, order history, employee records, or any structured data store.",
    },
    {
        "id":  "q_api",
        "q":   "Does your product or website have a public API or accept data from external systems?",
        "type": "yesno",
        "hint": "If other software can send or retrieve data from your system, you have an API surface.",
    },
    {
        "id":  "q_admin",
        "q":   "Do multiple people have admin or full access to your core systems?",
        "type": "yesno",
        "hint": "Examples: multiple people with AWS root access, shared admin passwords, or no role-based access controls.",
    },
    {
        "id":  "q_backup",
        "q":   "Do you have automated backups of your critical data?",
        "type": "yesno",
        "hint": "Answer No if backups are manual, untested, or you're not sure when they last ran.",
        "invert": True,   # No = higher risk
    },
    {
        "id":  "q_mfa",
        "q":   "Is multi-factor authentication (MFA) enabled on all critical accounts?",
        "type": "yesno",
        "hint": "Critical accounts include email, cloud provider, banking, and any admin systems.",
        "invert": True,   # No = higher risk
    },
    {
        "id":  "q_soc2",
        "q":   "Have you been asked by a customer or partner to provide a SOC 2 report or security questionnaire?",
        "type": "yesno",
        "hint": "This is common when selling to enterprise customers. If you've received a security questionnaire, answer Yes.",
    },
    {
        "id":  "q_incidents",
        "q":   "Has your business ever experienced a security incident, data breach, or suspicious activity?",
        "type": "yesno",
        "hint": "Includes phishing emails that employees clicked, unauthorised account access, lost laptops, or ransomware.",
    },
    {
        "id":  "q_employees",
        "q":   "How many people work in your business?",
        "type": "choice",
        "options": ["Just me", "2–10 people", "11–50 people", "51–200 people", "200+ people"],
        "hint": "Larger teams = more insider threat and access management risk.",
    },
]


# Maps each question answer to a list of risk entries to generate.
# Each entry: (asset, threat, av, ce, note)
# av = asset value (1-5), ce = control effectiveness (1-5)
# note = shown to user explaining why this risk was identified

DISCOVERY_RISK_MAP: dict[str, list[tuple]] = {
    # Card payments
    "q_payments:yes": [
        ("Finance System",    "Data Breach",       4, 2, "You store payment data - a breach exposes you to PCI DSS fines and customer loss."),
        ("Finance System",    "Unauthorized Access",4, 2, "Payment systems are high-value targets - unauthorized access can lead to fraud."),
    ],
    # Health data
    "q_health:yes": [
        ("Database",          "Data Breach",       5, 2, "Health records are highly sensitive - HIPAA requires strict controls and breach notification."),
        ("HR System",         "Insider Threat",    4, 2, "Healthcare data is frequently accessed by insiders - access controls are critical."),
    ],
    # EU customers
    "q_eu_customers:yes": [
        ("Customer Portal",   "Data Breach",       4, 2, "EU customer data is subject to GDPR - a breach requires notification within 72 hours."),
        ("Database",          "Unauthorized Access",3, 2, "GDPR requires you to demonstrate data is only accessed by authorised staff."),
    ],
    # Cloud usage
    "q_cloud:yes": [
        ("Cloud Environment", "Misconfiguration",  4, 2, "Cloud misconfigurations are the leading cause of data breaches for small businesses."),
        ("Cloud Environment", "Unauthorized Access",3, 3, "Cloud environments need strict access controls - shared credentials are a common failure."),
    ],
    # Remote work
    "q_remote:yes": [
        ("Endpoint / Laptop", "Malware",           3, 2, "Personal and remote devices are harder to control and patch - malware risk is elevated."),
        ("Endpoint / Laptop", "Data Loss",         3, 2, "Lost or stolen remote devices can expose sensitive business data."),
    ],
    # Third-party vendors
    "q_vendors:yes": [
        ("Vendor / Third Party", "Supply Chain Attack", 3, 2, "Third parties with access to your data are a common attack vector."),
        ("SaaS Platform",    "Data Breach",        3, 2, "SaaS tools holding customer data can be breached - your liability remains."),
    ],
    # Email
    "q_email:yes": [
        ("Email System",     "Phishing",           5, 2, "Phishing is the most common initial attack vector - email is the primary entry point."),
        ("User Credentials", "Credential Attack",  4, 2, "Business email accounts are targeted for credential stuffing and account takeover."),
    ],
    # Database / CRM
    "q_database:yes": [
        ("Database",         "Data Breach",        4, 2, "Databases containing customer or employee data are prime targets for attackers."),
        ("Database",         "Ransomware",         4, 2, "Ransomware targeting databases can halt operations and result in extortion demands."),
    ],
    # Public API
    "q_api:yes": [
        ("API",              "API Abuse",          4, 2, "Public APIs without rate limiting and authentication are vulnerable to abuse and data scraping."),
        ("API",              "Denial of Service (DDoS)", 3, 2, "APIs are common DDoS targets - lack of protection can take your service offline."),
    ],
    # Multiple admins / no RBAC
    "q_admin:yes": [
        ("Identity / IAM",   "Privilege Escalation",4, 1, "Too many admin accounts significantly increases your blast radius if one is compromised."),
        ("User Credentials", "Unauthorized Access", 4, 1, "Shared admin credentials mean you cannot audit who did what or quickly revoke access."),
    ],
    # No backups (inverted - No = risk)
    "q_backup:no": [
        ("Backup System",    "Data Loss",          4, 1, "Without reliable backups, a ransomware attack or accidental deletion could be unrecoverable."),
        ("Backup System",    "Ransomware",         4, 1, "Ransomware specifically targets and destroys backups - tested backups are your primary recovery option."),
    ],
    # No MFA (inverted - No = risk)
    "q_mfa:no": [
        ("User Credentials", "Credential Attack",  4, 1, "Accounts without MFA are significantly easier to compromise through phishing or password spray."),
        ("Identity / IAM",   "Unauthorized Access",4, 1, "MFA is the single most effective control against account takeover - its absence is a critical gap."),
    ],
    # SOC 2 pressure
    "q_soc2:yes": [
        ("Cloud Environment","Misconfiguration",   4, 2, "SOC 2 auditors specifically check cloud configuration - misconfigurations are a common audit failure."),
        ("Identity / IAM",   "Unauthorized Access",4, 2, "Access control evidence is the most frequently requested item in SOC 2 audits."),
    ],
    # Past incident
    "q_incidents:yes": [
        ("Email System",     "Phishing",           5, 1, "A history of incidents suggests controls are not fully effective - re-assess your phishing defences."),
        ("Endpoint / Laptop","Malware",            4, 1, "Past incidents indicate endpoint protection gaps that may still be present."),
    ],
    # Employee count - insider threat scales with team size
    "q_employees:11–50 people": [
        ("HR System",        "Insider Threat",     3, 2, "With 11-50 staff, access management becomes harder - not all staff need access to everything."),
    ],
    "q_employees:51–200 people": [
        ("HR System",        "Insider Threat",     4, 2, "At this size, formal role-based access control and offboarding procedures are essential."),
        ("Identity / IAM",   "Privilege Escalation",4, 2, "Larger teams mean more privilege creep - regular access reviews are critical."),
    ],
    "q_employees:200+ people": [
        ("HR System",        "Insider Threat",     5, 2, "At this scale, insider threat is statistically significant - formal RBAC and monitoring are required."),
        ("Identity / IAM",   "Privilege Escalation",5, 2, "Enterprise-scale access management requires automated provisioning and deprovisioning."),
    ],
}


def run_discovery_questionnaire(answers: dict) -> list[dict]:
    """
    Takes the user's answers dict {question_id: answer_string}
    and returns a list of fully scored risk register entries.
    No GRC knowledge required from the caller.
    """
    company  = st.session_state.get("wizard_company", "My Company") or "My Company"
    industry = st.session_state.get("wizard_industry", "Technology")

    generated: list[dict] = []
    seen_fingerprints: set[str] = set()

    for q in DISCOVERY_QUESTIONS:
        qid     = q["id"]
        answer  = answers.get(qid, "")
        invert  = q.get("invert", False)

        if not answer:
            continue

        # Normalise to lookup key
        if q["type"] == "yesno":
            answer_norm = "yes" if answer == "Yes" else "no"
            # For inverted questions (No = risk), flip the lookup
            if invert:
                lookup_key = f"{qid}:{answer_norm}"
            else:
                lookup_key = f"{qid}:{answer_norm}"
        else:
            lookup_key = f"{qid}:{answer}"

        risks = DISCOVERY_RISK_MAP.get(lookup_key, [])

        for (asset, threat, av, ce, note) in risks:
            # Deduplicate by asset+threat fingerprint
            fp = _risk_fingerprint(asset, threat)
            if fp in seen_fingerprints:
                continue
            seen_fingerprints.add(fp)

            l, i, reasons = calculate_auto_scores(asset, threat)
            entry = build_result(
                asset=asset, threat=threat,
                likelihood=l, impact=i,
                asset_value=av, control_effectiveness=ce,
                reasons=reasons + [f"Identified by discovery questionnaire: {note}"],
                plain_summary=(
                    f"Risk identified from your business profile. {note} "
                    f"This risk was auto-generated based on your answers - "
                    f"review and adjust the treatment plan as needed."
                ),
                actions=[
                    {"tag": "Review",   "text": f"Confirm this risk is relevant to your specific situation."},
                    {"tag": "Mitigate", "text": f"Review the recommended controls and assign an owner."},
                    {"tag": "Document", "text": f"Upload evidence of any controls already in place."},
                ],
                confidence="medium",
                company=company, industry=industry,
                department="General", owner="Risk Owner",
                status="Open",
                review_date=datetime.now().date(),
                financial_impact="Medium", operational_impact="Medium",
                compliance_impact="Medium",
                business_process="Business Operations",
                vulnerability_name=f"Identified via discovery: {note[:60]}",
                vulnerability_severity="Medium",
                vulnerability_source="Risk Discovery Questionnaire",
                evidence_name="", evidence_owner="",
                audit_status="Evidence Missing",
            )
            generated.append(entry)

    return generated


def render_discovery_questionnaire() -> None:
    """Renders the plain-English questionnaire UI and handles saving results."""

    st.markdown("""
    <div style="background:linear-gradient(135deg,#1E3A5F,#1D4ED8);border-radius:12px;
                padding:20px 24px;margin-bottom:20px;">
      <div style="font-size:1.1rem;font-weight:800;color:white;margin-bottom:6px;">
        🔍 Risk Discovery - Tell us about your business
      </div>
      <div style="font-size:0.87rem;color:#93C5FD;line-height:1.6;">
        Answer these plain-English questions and we'll automatically identify
        the risks that apply to your business, score them, and add them to your
        risk register. <strong style="color:white;">No GRC knowledge required.</strong>
      </div>
    </div>
    """, unsafe_allow_html=True)

    if "discovery_answers" not in st.session_state:
        st.session_state.discovery_answers = {}

    answers = {}

    with st.form("discovery_form"):
        for q in DISCOVERY_QUESTIONS:
            st.markdown(f"**{q['q']}**")
            st.caption(q["hint"])

            if q["type"] == "yesno":
                prev = st.session_state.discovery_answers.get(q["id"], "Yes")
                val  = st.radio(
                    q["id"], ["Yes", "No"],
                    index=0 if prev == "Yes" else 1,
                    horizontal=True,
                    label_visibility="collapsed",
                    key=f"disc_{q['id']}",
                )
            elif q["type"] == "choice":
                prev = st.session_state.discovery_answers.get(q["id"], q["options"][1])
                val  = st.selectbox(
                    q["id"], q["options"],
                    index=q["options"].index(prev) if prev in q["options"] else 1,
                    label_visibility="collapsed",
                    key=f"disc_{q['id']}",
                )
            else:
                val = "Yes"

            answers[q["id"]] = val
            st.markdown("")

        submitted = st.form_submit_button(
            "✅ Generate My Risk Register Automatically",
            type="primary",
            use_container_width=True,
        )

    if submitted:
        st.session_state.discovery_answers = answers
        generated = run_discovery_questionnaire(answers)

        if generated:
            # Clear existing discovery-generated risks to avoid duplicates on re-run
            st.session_state.history = [
                r for r in st.session_state.history
                if r.get("Finding Source") != "Risk Discovery Questionnaire"
            ]
            for entry in generated:
                st.session_state.history.append(entry)

            # Jump to register
            st.session_state.active_tab   = 1
            st.session_state.just_saved   = True
            st.session_state.discovery_done = True
            st.rerun()
        else:
            st.warning("No risks were identified from your answers. Try adjusting your responses.")



# ─────────────────────────────────────────────────────────────
# BREACH SIMULATOR
# ─────────────────────────────────────────────────────────────
BREACH_SCENARIOS: dict[str, dict] = {
    "Data Breach": {
        "incident": "Your customer database was accessed by an unauthorised third party. Customer names, emails, and payment records are exposed.",
        "timeline": [
            ("Hour 1",   "Your monitoring system flags unusual database queries at 2am. By the time someone checks at 9am, the attacker has been inside for 7 hours."),
            ("Hour 4",   "IT confirms the breach. Under GDPR you have 72 hours to notify your supervisory authority. The clock is ticking."),
            ("Day 1",    "You need to notify affected customers. A lawyer reviews the notification draft. Legal fees start at $500/hour."),
            ("Day 3",    "GDPR notification submitted. Regulators acknowledge and open an investigation. ISO 27001 or SOC 2 auditors are notified."),
            ("Week 1",   "Customers start calling. Some cancel. A journalist picks up the story from a customer's social post."),
            ("Week 2",   "Estimated financial impact: legal ($15K-50K), regulatory fine (up to 4% of annual revenue under GDPR), customer churn (5-20%), reputational damage (hard to quantify)."),
            ("Month 1",  "If you had CE=4 (Mature controls): breach likely prevented or contained within 1 hour. Regulatory exposure minimal. This scenario is the CE=1 or CE=2 reality."),
        ],
        "key_control": "Encryption at rest + access logging + anomaly detection",
    },
    "Phishing": {
        "incident": "An employee clicked a phishing link and entered their work credentials on a fake login page. The attacker now has valid access to your systems.",
        "timeline": [
            ("Minute 1",  "The attacker receives the credentials in real time. Automated tools immediately test them against your email, cloud storage, and admin portals."),
            ("Hour 1",    "The attacker is inside your email. They read everything - client contracts, financial data, internal discussions."),
            ("Hour 3",    "A password reset email is sent to your CEO pretending to be IT support. The CEO clicks it. Now the attacker has admin access."),
            ("Day 1",     "The attacker sends invoices to your top 3 clients from your CEO's real email address, changing the bank account number. Business Email Compromise."),
            ("Day 2",     "Client A transfers $45,000 to the attacker's account. They contact you to confirm receipt. This is when you find out."),
            ("Week 1",    "Police report filed. Bank says recovery is unlikely. Client A is furious. You may lose the contract."),
            ("Month 1",   "If MFA had been enabled: the stolen password would have been useless. This entire scenario costs $0. MFA costs $3/user/month."),
        ],
        "key_control": "MFA on all accounts + phishing simulation training",
    },
    "Ransomware": {
        "incident": "Ransomware has encrypted your business systems and backups. You cannot access customer data, invoices, or operations. A ransom note demands $50,000 in Bitcoin.",
        "timeline": [
            ("Hour 1",   "Every file on your network is encrypted. Operations stop completely. Employees cannot work."),
            ("Hour 2",   "You discover your backups are also encrypted - the ransomware targeted them first. Your last clean backup was 3 weeks ago."),
            ("Day 1",    "You contact a specialist incident response firm. Minimum engagement: $15,000. They estimate 2-4 weeks to full recovery."),
            ("Day 2",    "Ransom deadline: pay $50K or they publish your customer data publicly. Paying does not guarantee decryption."),
            ("Week 1",   "Revenue stops. Staff are idle. You notify customers their data may be published. Some leave immediately."),
            ("Week 2",   "Estimated total cost: ransom ($50K if paid) + IR firm ($15-30K) + lost revenue ($X/week) + staff time + reputational damage."),
            ("Month 1",  "With tested backups (CE=4) and endpoint protection (CE=4): recovery in 4 hours, cost under $5K, no ransom paid."),
        ],
        "key_control": "Tested offline backups + endpoint detection + network segmentation",
    },
    "Misconfiguration": {
        "incident": "A cloud storage bucket containing customer records was accidentally set to public. It has been publicly accessible for 6 weeks.",
        "timeline": [
            ("Week 1-6",  "Your customer data - names, addresses, purchase history - has been publicly downloadable. You had no idea."),
            ("Day 1",     "A security researcher finds it and emails you. Alternatively: a threat actor found it 5 weeks ago and has been selling it on dark web forums."),
            ("Hour 4",    "You make the bucket private. But you cannot un-expose data that has already been downloaded by unknown parties."),
            ("Day 2",     "Under GDPR: 72 hour notification window starts from when you became aware, not when the exposure started. You are already in breach of the notification timeline."),
            ("Week 1",    "Regulatory investigation opens. You must prove what data was exposed, for how long, and to whom. You have no access logs."),
            ("Month 1",   "Estimated regulatory fine: $10K-500K depending on jurisdiction and data sensitivity. Plus legal costs."),
            ("Lesson",    "Cloud security posture management (CSPM) tools scan for this automatically. Cost: $0-200/month. Far less than the fine."),
        ],
        "key_control": "Cloud misconfiguration scanning + access logging enabled",
    },
    "Insider Threat": {
        "incident": "A departing employee downloaded your entire customer database and client list to a personal USB drive on their last day.",
        "timeline": [
            ("Day 1",    "The employee leaves. HR processes the offboarding but IT access is not revoked for 3 days - standard for your company."),
            ("Week 1",   "The ex-employee joins a competitor. They bring your customer list with them and start cold-calling your top 20 accounts."),
            ("Month 1",  "You lose 3 major clients who were contacted by the competitor with suspiciously detailed knowledge of your pricing and relationships."),
            ("Month 2",  "You notice the pattern and investigate. Forensic investigation costs $8,000. You find the USB transfer in logs - but you kept logs for only 30 days. Evidence is gone."),
            ("Month 3",  "Legal action is expensive, slow, and uncertain without strong forensic evidence. The damage is done."),
            ("Lesson",   "Immediate access revocation on exit + DLP tools flagging large downloads + 12-month log retention would have prevented or caught this."),
        ],
        "key_control": "Immediate access revocation + DLP monitoring + log retention policy",
    },
}


def render_breach_simulator(risk_register: list) -> None:
    """Interactive breach simulator - makes risk feel real for non-technical users."""

    st.markdown("""
    <div style="background:linear-gradient(135deg,#1E1B4B,#312E81);border-radius:12px;
                padding:20px 24px;margin-bottom:16px;">
      <div style="font-size:1.1rem;font-weight:800;color:white;margin-bottom:6px;">
        💀 Breach Simulator
      </div>
      <div style="font-size:0.87rem;color:#A5B4FC;line-height:1.6;">
        See what actually happens to a small business when a risk materialises.
        Not a score - a story. Pick a threat and we'll walk you through the next 72 hours.
      </div>
    </div>
    """, unsafe_allow_html=True)

    # Let them pick from their register OR from common threats
    threat_options = list(BREACH_SCENARIOS.keys())

    if risk_register:
        register_threats = list({r.get("Threat","") for r in risk_register
                                  if r.get("Threat","") in BREACH_SCENARIOS})
        if register_threats:
            st.caption("These threats are in your risk register:")
            threat_options = register_threats + [t for t in threat_options if t not in register_threats]

    selected = st.selectbox("Choose a threat to simulate", threat_options,
                             key="breach_sim_threat")

    if st.button("💀 Simulate this breach", type="primary",
                 use_container_width=True, key="run_breach_sim"):
        st.session_state.breach_sim_result = selected

    if st.session_state.get("breach_sim_result") == selected:
        scenario = BREACH_SCENARIOS[selected]

        st.markdown(f"""
        <div style="background:#FEF2F2;border:2px solid #FECACA;border-radius:10px;
                    padding:16px 20px;margin:12px 0;">
          <div style="font-size:0.75rem;font-weight:700;color:#991B1B;
                      text-transform:uppercase;letter-spacing:0.08em;margin-bottom:8px;">
            INCIDENT REPORT
          </div>
          <div style="font-size:0.95rem;color:#7F1D1D;font-weight:500;line-height:1.6;">
            {scenario['incident']}
          </div>
        </div>
        """, unsafe_allow_html=True)

        st.markdown("**What happens next:**")
        for i, (timeframe, event) in enumerate(scenario["timeline"]):
            color = "#991B1B" if i < 2 else "#D97706" if i < 4 else "#166534"
            st.markdown(f"""
            <div style="display:flex;gap:14px;margin-bottom:10px;align-items:flex-start;">
              <div style="background:{color};color:white;border-radius:6px;padding:3px 10px;
                          font-size:0.72rem;font-weight:700;white-space:nowrap;margin-top:2px;
                          min-width:70px;text-align:center;">{timeframe}</div>
              <div style="font-size:0.87rem;color:#1E293B;line-height:1.6;">{event}</div>
            </div>
            """, unsafe_allow_html=True)

        st.markdown(f"""
        <div style="background:#F0FDF4;border:1px solid #BBF7D0;border-left:4px solid #16A34A;
                    border-radius:8px;padding:14px 18px;margin-top:12px;">
          <div style="font-size:0.8rem;font-weight:700;color:#166534;margin-bottom:4px;">
            THE CONTROL THAT PREVENTS THIS
          </div>
          <div style="font-size:0.9rem;color:#14532D;">{scenario['key_control']}</div>
        </div>
        """, unsafe_allow_html=True)

        # Check if they have this risk in their register
        matching = [r for r in risk_register if r.get("Threat","") == selected]
        if matching:
            r = matching[0]
            ce = r.get("Control Effectiveness", 1)
            residual = r.get("Residual Risk", 25)
            st.markdown(f"""
            <div style="background:#EFF6FF;border:1px solid #BFDBFE;border-radius:8px;
                        padding:12px 16px;margin-top:10px;font-size:0.87rem;color:#1E3A5F;">
              <strong>Your register shows this risk:</strong> {r.get('Asset','')} / {selected}
              - Residual Risk: <strong>{residual}/25</strong>,
              Control Effectiveness: <strong>{ce}/5</strong>.
              {"Your controls are strong enough to significantly reduce this scenario." if ce >= 4
               else "Your current controls would not prevent this scenario from unfolding as described." if ce <= 2
               else "Your controls provide partial protection but gaps remain."}
            </div>
            """, unsafe_allow_html=True)


# ─────────────────────────────────────────────────────────────
# AI RISK ORACLE
# ─────────────────────────────────────────────────────────────
def render_risk_oracle() -> None:
    """One text box - describe your business - get your top 3 risks instantly."""

    st.markdown("""
    <div style="background:linear-gradient(135deg,#0F172A,#1E3A5F);border-radius:12px;
                padding:20px 24px;margin-bottom:16px;">
      <div style="font-size:1.1rem;font-weight:800;color:white;margin-bottom:6px;">
        🔮 What's My Biggest Risk?
      </div>
      <div style="font-size:0.87rem;color:#93C5FD;line-height:1.6;">
        Describe your business in 1-2 sentences. The AI will identify your top 3 risks
        instantly - no forms, no dropdowns, no GRC knowledge needed.
      </div>
    </div>
    """, unsafe_allow_html=True)

    biz_desc = st.text_area(
        "Describe your business",
        placeholder="Example: We're a 15-person SaaS company that sells HR software to US and UK companies. We store employee data and payroll information in AWS.",
        height=90,
        label_visibility="collapsed",
        key="oracle_desc",
    )

    if st.button("🔮 Identify My Top Risks", type="primary",
                 use_container_width=True, key="run_oracle",
                 disabled=len((biz_desc or "").strip()) < 20):

        with st.spinner("Analysing your business..."):
            prompt = f"""You are a GRC expert. A small business owner describes their business as:

"{biz_desc}"

Identify their top 3 cybersecurity and compliance risks in plain English a non-technical owner would understand.

For each risk return:
- risk_name: short name (e.g. "Customer Data Breach")
- why_you: one sentence explaining why THIS business is specifically at risk
- what_happens: one sentence describing the real-world consequence if it materialises
- quick_win: the single most effective control they can implement, described simply
- severity: "Critical", "High", or "Medium"

Return ONLY valid JSON array with exactly 3 objects. No markdown, no explanation."""

            try:
                import anthropic as _anthropic
                _client = _anthropic.Anthropic()
                _resp = _client.messages.create(
                    model="claude-sonnet-4-6",
                    max_tokens=800,
                    messages=[{"role":"user","content":prompt}],
                )
                import json
                raw = _resp.content[0].text.strip()
                raw = raw.replace("```json","").replace("```","").strip()
                risks = json.loads(raw)
                st.session_state.oracle_result = risks
            except Exception:
                # Fallback: rule-based oracle
                st.session_state.oracle_result = _oracle_fallback(biz_desc)

    if st.session_state.get("oracle_result"):
        risks = st.session_state.oracle_result
        sev_colors = {"Critical":"#991B1B","High":"#DC2626","Medium":"#D97706"}
        sev_bg     = {"Critical":"#FEF2F2","High":"#FFF7ED","Medium":"#FEFCE8"}

        for i, r in enumerate(risks[:3], 1):
            sev = r.get("severity","High")
            col = sev_colors.get(sev,"#1D4ED8")
            bg  = sev_bg.get(sev,"#F8FAFC")
            st.markdown(f"""
            <div style="background:{bg};border:1px solid {col}30;border-left:4px solid {col};
                        border-radius:10px;padding:16px 20px;margin-bottom:12px;">
              <div style="display:flex;align-items:center;gap:10px;margin-bottom:8px;">
                <span style="background:{col};color:white;border-radius:20px;
                             padding:2px 10px;font-size:0.72rem;font-weight:700;">{sev}</span>
                <span style="font-size:1rem;font-weight:800;color:#0F172A;">#{i} {r.get('risk_name','')}</span>
              </div>
              <div style="font-size:0.87rem;color:#334155;margin-bottom:6px;line-height:1.6;">
                <strong>Why you:</strong> {r.get('why_you','')}
              </div>
              <div style="font-size:0.87rem;color:#334155;margin-bottom:6px;line-height:1.6;">
                <strong>If it happens:</strong> {r.get('what_happens','')}
              </div>
              <div style="font-size:0.85rem;color:{col};font-weight:600;">
                Quick win: {r.get('quick_win','')}
              </div>
            </div>
            """, unsafe_allow_html=True)

        st.caption("These are AI-generated starting points. Use the Risk Assessment tab to score and track them properly.")


def _oracle_fallback(description: str) -> list:
    """Rule-based fallback when AI is unavailable."""
    desc = description.lower()
    risks = []

    if any(w in desc for w in ["saas","software","cloud","aws","azure","google cloud"]):
        risks.append({"risk_name":"Cloud Misconfiguration","severity":"Critical",
            "why_you":"Cloud environments are frequently misconfigured, exposing data publicly without the owner realising.",
            "what_happens":"Customer data becomes publicly accessible, triggering regulatory fines and customer loss.",
            "quick_win":"Enable cloud security posture scanning and ensure all storage buckets are private by default."})

    if any(w in desc for w in ["customer","client","user","data","store","database"]):
        risks.append({"risk_name":"Customer Data Breach","severity":"Critical",
            "why_you":"Any business storing customer data is a target - attackers go for the easiest available data.",
            "what_happens":"Customer records are stolen and sold, triggering GDPR/CCPA notification obligations and potential fines.",
            "quick_win":"Encrypt customer data at rest, enable database access logging, and enforce MFA on all admin accounts."})

    if any(w in desc for w in ["employee","staff","team","people","email"]):
        risks.append({"risk_name":"Phishing Attack","severity":"High",
            "why_you":"Email is the #1 attack vector for small businesses - one click from one employee is all it takes.",
            "what_happens":"An attacker gains access to business email and systems, potentially leading to fraud or data theft.",
            "quick_win":"Enable MFA on all email accounts immediately - this single control stops 99% of credential attacks."})

    if any(w in desc for w in ["health","medical","patient","hipaa","hospital","clinic"]):
        risks.append({"risk_name":"HIPAA Violation","severity":"Critical",
            "why_you":"Healthcare data is among the most regulated - any exposure triggers mandatory reporting and fines.",
            "what_happens":"A breach of patient data requires notification to HHS, affected individuals, and potentially the media.",
            "quick_win":"Complete a HIPAA risk analysis, sign BAAs with all vendors, and encrypt all PHI at rest and in transit."})

    if not risks:
        risks = [
            {"risk_name":"Unauthorised Access","severity":"High",
             "why_you":"Most small businesses have weak access controls - shared passwords and no MFA are extremely common.",
             "what_happens":"An attacker gains entry to your systems and can steal data, install malware, or commit fraud.",
             "quick_win":"Enable MFA on all business accounts and eliminate shared passwords immediately."},
            {"risk_name":"Ransomware","severity":"High",
             "why_you":"Small businesses are increasingly targeted because they typically have weaker defences and are more likely to pay.",
             "what_happens":"All your files are encrypted and operations stop completely until you pay or restore from backup.",
             "quick_win":"Set up automated daily backups stored offline or in a separate cloud account the ransomware cannot reach."},
            {"risk_name":"Third-Party Data Exposure","severity":"Medium",
             "why_you":"Most businesses share data with multiple SaaS tools - each one is a potential breach point.",
             "what_happens":"A vendor you use is breached and your customer data is exposed through them, not through you.",
             "quick_win":"Audit which tools have access to customer data and remove access from any tool you no longer actively use."},
        ]
    return risks[:3]


# ─────────────────────────────────────────────────────────────
# SIDEBAR
# ─────────────────────────────────────────────────────────────
with st.sidebar:
    # ── TREE NAVIGATION ───────────────────────────────────────
    _sec = st.session_state.get("active_section", "auto_discovery")
    _tab = st.session_state.get("active_tab", 0)

    st.markdown("""
    <div style="padding:14px 4px 8px 4px;">
      <div style="font-size:1rem;font-weight:800;color:#F1F5F9;
                  letter-spacing:-0.02em;margin-bottom:2px;">🛡️ GRC Platform</div>
      <div style="font-size:0.7rem;color:#475569;font-family:monospace;">v3.0</div>
    </div>
    """, unsafe_allow_html=True)

    # Tree structure definition
    # (section_id, tab_id, label, indent, icon, is_parent)
    TREE = [
        ("assess_root",    0, "Risk Assessment",         0, "📋", True),
        ("auto_discovery", 0, "Auto Discovery",          1, "🔍", False),
        ("describe_risk",  0, "Describe a Risk",         1, "✨", False),
        ("slider_mode",    0, "Slider Mode",             1, "🎛️", False),
        ("breach_sim",     0, "Breach Simulator",        1, "💀", False),
        ("risk_oracle",    0, "Risk Oracle",             1, "🔮", False),
        ("register_root",  1, "Risk Register & Reports", 0, "📊", True),
        ("reg_table",      1, "Risk Register",           1, "📋", False),
        ("reg_charts",     1, "Dashboard Charts",        1, "📈", False),
        ("reg_reports",    1, "Download Reports",        1, "🧾", False),
        ("soc_root",       2, "SOC Analysis",            0, "🔍", True),
        ("soc_scanner",    2, "Scanner Import",          1, "🛡️", False),
        ("soc2_ready",     2, "SOC 2 Readiness",         1, "✅", False),
        ("soc_alerts",     2, "Alert Import",            1, "🚨", False),
        ("soc_frameworks", 2, "All Frameworks",          1, "📋", False),
    ]

    # Section to assessment_mode mapping
    SEC_TO_MODE = {
        "auto_discovery": ("discovery", None),
        "describe_risk":  ("manual",    None),
        "slider_mode":    ("manual",    "slider"),
        "breach_sim":     ("manual",    None),
        "risk_oracle":    ("manual",    None),
        "assess_root":    ("discovery", None),
    }
    SEC_TO_SOC_TAB = {
        "soc_scanner":    0,
        "soc2_ready":     1,
        "soc_alerts":     2,
        "soc_frameworks": 3,
    }

    for sec_id, tab_id, label, indent, icon, is_parent in TREE:
        is_active = (sec_id == _sec) or (is_parent and tab_id == _tab and
                    _sec not in [t[0] for t in TREE if not t[5] and t[1] == tab_id])
        left_pad  = indent * 12
        badge     = (f" [{len(st.session_state.history)}]"
                     if sec_id == "register_root" and st.session_state.history else "")

        if is_parent:
            # Parent = section header, not clickable as a nav item
            st.markdown(f"""
            <div style="padding:8px 4px 3px {left_pad+4}px;margin-top:6px;">
              <span style="font-size:0.72rem;font-weight:700;color:#475569;
                           text-transform:uppercase;letter-spacing:0.08em;">
                {icon} {label}{badge}
              </span>
            </div>
            """, unsafe_allow_html=True)
            if st.button(f"{icon} {label}", key=f"tree_{sec_id}", use_container_width=True,
                         type="secondary"):
                st.session_state.active_section = sec_id
                st.session_state.active_tab = tab_id
                st.rerun()
        else:
            btn_style = "primary" if is_active else "secondary"
            prefix = ""
            if st.button(f"  {icon} {label}" if indent else f"{icon} {label}", key=f"tree_{sec_id}",
                         use_container_width=True, type=btn_style):
                st.session_state.active_section = sec_id
                st.session_state.active_tab = tab_id

                # Set sub-modes based on section
                if sec_id in SEC_TO_MODE:
                    mode, sub = SEC_TO_MODE[sec_id]
                    st.session_state.assessment_mode = mode
                    if sub:
                        st.session_state.input_mode = sub
                    elif sec_id == "describe_risk":
                        st.session_state.input_mode = "smart"

                if sec_id in SEC_TO_SOC_TAB:
                    st.session_state.soc_active_tab = SEC_TO_SOC_TAB[sec_id]

                st.rerun()

    st.markdown('<hr style="border-color:#1E293B;margin:12px 0;">', unsafe_allow_html=True)

    # ── PROGRESS ──────────────────────────────────────────────
    _has_register = len(st.session_state.history) > 0
    _has_result   = st.session_state.get("last_result") is not None
    for num, label, done, hint in [
        ("1", "Assess", True,          "Choose a mode above"),
        ("2", "Save",   _has_result,   "Click Save after analysing"),
        ("3", "Report", _has_register, "Download from Risk Register"),
    ]:
        dot = "#059669" if done else "#334155"
        txt = "✓" if done else num
        fg  = "#86EFAC" if done else "#64748B"
        st.markdown(f"""
        <div style="display:flex;align-items:center;gap:8px;margin:4px 0;">
          <div style="width:20px;height:20px;border-radius:50%;background:{dot};
                      color:white;font-size:0.65rem;font-weight:700;flex-shrink:0;
                      display:flex;align-items:center;justify-content:center;">{txt}</div>
          <div>
            <span style="font-size:0.78rem;font-weight:600;color:{fg};">{label}</span>
            <span style="font-size:0.68rem;color:#475569;margin-left:4px;">{hint}</span>
          </div>
        </div>
        {"<div style=\"margin-left:10px;border-left:1px dashed #334155;height:8px;\"></div>" if num != "3" else ""}
        """, unsafe_allow_html=True)

    st.markdown('<hr style="border-color:#1E293B;margin:12px 0;">', unsafe_allow_html=True)

    # ── ROLE + SETTINGS ───────────────────────────────────────
    with st.expander("👤 Role & Access", expanded=False):
        st.session_state.demo_role = st.radio(
            "Role", ["Admin", "Manager", "Viewer"],
            index=["Admin","Manager","Viewer"].index(st.session_state.demo_role),
            horizontal=True,
        )
        st.caption(get_role_permissions(st.session_state.demo_role)["description"])

    with st.expander("🎯 Risk Appetite", expanded=False):
        appetite_val = st.slider("Threshold", 1, 25,
            st.session_state.get("risk_appetite", DEFAULT_RISK_APPETITE), 1,
            key="sb_appetite")
        st.session_state.risk_appetite = appetite_val
        _ap = "LOW" if appetite_val<=6 else "MEDIUM" if appetite_val<=12 else "HIGH" if appetite_val<=19 else "CRITICAL"
        _apc = {"LOW":"#16A34A","MEDIUM":"#D97706","HIGH":"#DC2626","CRITICAL":"#991B1B"}[_ap]
        st.markdown(f'<span style="color:{_apc};font-size:0.8rem;font-weight:700;">{appetite_val}/25 ({_ap})</span>', unsafe_allow_html=True)

    with st.expander("📋 My Frameworks", expanded=False):
        for fw in st.session_state.get("wizard_frameworks", ["SOC 2","NIST CSF"]):
            st.caption(f"✓ {fw}")
        if st.button("⚙️ Change setup", key="reset_wizard2", use_container_width=True):
            st.session_state.wizard_complete = False
            st.rerun()

    with st.expander("📊 Register Summary", expanded=False):
        if st.session_state.history:
            avg = sum(r["Residual Risk"] for r in st.session_state.history)/len(st.session_state.history)
            lvl, emoji, _ = risk_level(avg)
            st.metric("Avg Residual Risk", f"{round(avg,1)}/25")
            st.write(f"{emoji} {lvl} - {len(st.session_state.history)} risks saved")
        else:
            st.write("No risks saved yet.")

    with st.expander("💡 GRC Tip", expanded=False):
        st.write(random.choice(TIPS))


_active  = st.session_state.get("active_tab", 0)
_sec     = st.session_state.get("active_section", "auto_discovery")
_saved_count = len(st.session_state.history)

# Map section to breadcrumb label
_SEC_LABELS = {
    "assess_root":    ("📋", "Risk Assessment",         "Choose a mode to get started"),
    "auto_discovery": ("🔍", "Auto Discovery",           "Answer questions - we generate your risk register"),
    "describe_risk":  ("✨", "Describe a Risk",          "Type what happened in plain English, or use AI"),
    "slider_mode":    ("🎛️", "Slider Mode",              "Set scores manually with sliders"),
    "breach_sim":     ("💀", "Breach Simulator",         "See what happens when a risk materialises"),
    "risk_oracle":    ("🔮", "Risk Oracle",              "Tell us about your business - get your top risks"),
    "register_root":  ("📊", "Risk Register & Reports",  "All saved risks and downloads"),
    "reg_table":      ("📋", "Risk Register",            "View and filter all saved risk entries"),
    "reg_charts":     ("📈", "Dashboard Charts",         "Visual breakdown of your risk landscape"),
    "reg_reports":    ("🧾", "Download Reports",         "PDF, CSV and executive summary exports"),
    "soc_root":       ("🔍", "SOC Analysis & Scanning",  "Scanner import, SOC 2 readiness and alerts"),
    "soc_scanner":    ("🛡️", "Scanner Import",           "Upload Nessus or Qualys CSV - auto-scored"),
    "soc2_ready":     ("✅", "SOC 2 Readiness",          "Control-by-control audit checklist"),
    "soc_alerts":     ("🚨", "Alert Import",             "Batch import SOC alerts from your SIEM"),
    "soc_frameworks": ("📋", "All Frameworks",           "Combined readiness across all 8 frameworks"),
}
_icon, _title, _desc = _SEC_LABELS.get(_sec, ("📋", "GRC Platform", ""))

# Sticky breadcrumb
st.markdown(f"""
<div style="background:#1E3A5F;border-radius:10px;
            padding:12px 18px;margin-bottom:16px;
            display:flex;align-items:center;gap:14px;
            box-shadow:0 2px 8px rgba(0,0,0,0.12);">
  <span style="font-size:1.4rem;">{_icon}</span>
  <div>
    <div style="font-size:1rem;font-weight:800;color:white;">{_title}</div>
    <div style="font-size:0.73rem;color:#93C5FD;">{_desc}</div>
  </div>
  <div style="margin-left:auto;">
    <span style="background:rgba(255,255,255,0.1);border-radius:20px;padding:4px 12px;
                 font-size:0.73rem;font-weight:600;color:#E0F2FE;">
      {_saved_count} risk{"s" if _saved_count != 1 else ""} saved
    </span>
  </div>
</div>
""", unsafe_allow_html=True)

# Route to correct section
_show_assessment = (_active == 0)
_show_register   = (_active == 1)
_show_soc        = (_active == 2)

# Sub-section routing inside assessment
role_info = get_role_permissions(st.session_state.demo_role)
_show_discovery  = _show_assessment and _sec in ("auto_discovery", "assess_root")
_show_manual     = _show_assessment and _sec in ("describe_risk", "slider_mode")
_show_breach     = _show_assessment and _sec == "breach_sim"
_show_oracle     = _show_assessment and _sec == "risk_oracle"

# Fallback: if on assessment tab but no sub-section matches, show discovery
if _show_assessment and not any([_show_discovery, _show_manual, _show_breach, _show_oracle]):
    _show_discovery = True

# Register sub-section routing
_show_reg_table   = _show_register and _sec in ("reg_table",  "register_root")
_show_reg_charts  = _show_register and _sec == "reg_charts"
_show_reg_reports = _show_register and _sec == "reg_reports"
# Fallback: show everything if no sub-section selected
if _show_register and not any([_show_reg_table, _show_reg_charts, _show_reg_reports]):
    _show_reg_table   = True
    _show_reg_charts  = True
    _show_reg_reports = True

# Sub-section routing inside SOC
_soc_tab = st.session_state.get("soc_active_tab", 0)
if _sec == "soc_scanner":    _soc_tab = 0
elif _sec == "soc2_ready":   _soc_tab = 1
elif _sec == "soc_alerts":   _soc_tab = 2
elif _sec == "soc_frameworks": _soc_tab = 3

# ══════════════════════════════════════════════════════════════
# SECTION 1 - RISK ASSESSMENT
# ══════════════════════════════════════════════════════════════
if _show_assessment:

    if not role_info["can_edit"]:
        st.warning("You are in Viewer mode. Switch to Admin or Manager in the sidebar.")

    # ── ROUTE BY SIDEBAR SECTION ──────────────────────────────
    if _show_discovery:
        render_discovery_questionnaire()

    elif _show_breach:
        render_breach_simulator(st.session_state.history)

    elif _show_oracle:
        render_risk_oracle()

    elif _show_manual:
        # Set input_mode from section
        if _sec == "slider_mode":
            st.session_state.input_mode = "slider"
        elif st.session_state.get("input_mode") not in ("smart","manual","slider"):
            st.session_state.input_mode = "smart"

        # Sub-mode buttons — only the INPUT METHOD differs, everything else is shared
        if st.session_state.input_mode != "slider":
            st.markdown("""
            <div style="background:#F8FAFC;border:1px solid #E2E8F0;border-radius:10px;
                        padding:12px 16px;margin-bottom:12px;">
              <div style="font-size:0.75rem;font-weight:700;color:#475569;
                          text-transform:uppercase;letter-spacing:0.08em;margin-bottom:8px;">
                How would you like to describe the risk?
              </div>
            </div>
            """, unsafe_allow_html=True)
            sm1, sm2 = st.columns(2)
            with sm1:
                if st.button("✨ Type what happened in plain English\nAI identifies the risk automatically",
                             use_container_width=True,
                             type="primary" if st.session_state.input_mode == "smart" else "secondary",
                             key="sub_smart"):
                    st.session_state.input_mode = "smart"
                    st.rerun()
            with sm2:
                if st.button("⚙️ Select asset and threat from lists\nFor GRC professionals",
                             use_container_width=True,
                             type="primary" if st.session_state.input_mode == "manual" else "secondary",
                             key="sub_analyst"):
                    st.session_state.input_mode = "manual"
                    st.rerun()
            st.markdown("")

        # ── SLIDER SUB-MODE ───────────────────────────────────
        if st.session_state.input_mode == "slider":
            sl_asset = st.selectbox("Asset", ASSET_OPTIONS,
                                    index=ASSET_OPTIONS.index(
                                        st.session_state.get("selected_asset","Database")),
                                    key="slider_asset_sb")
            sl_threats = safe_threats_for_asset(sl_asset)
            sl_threat = st.selectbox("Threat", sl_threats, key="slider_threat_sb")
            st.markdown("")
            sl1, sl2 = st.columns(2)
            with sl1:
                sl_av = st.slider("Asset Value / Business Criticality", 1, 5,
                                  st.session_state.get("random_asset_value", 3), 1,
                                  help="1=Negligible · 3=Moderate · 5=Mission-critical",
                                  key="slider_av_sb")
                st.markdown(f'<div class="slider-legend"><span>1 Negligible</span><span>2 Low</span><span>3 Moderate</span><span>4 High</span><span>5 Mission-critical</span></div>', unsafe_allow_html=True)
            with sl2:
                sl_ce = st.slider("Control Effectiveness", 1, 5,
                                  st.session_state.get("random_control_effectiveness", 3), 1,
                                  help="1=No controls (5%) · 3=Standard (45%) · 5=Best-in-class (90%)",
                                  key="slider_ce_sb")
                st.markdown(f'<div class="slider-legend"><span>1 Minimal</span><span>2 Basic</span><span>3 Standard</span><span>4 Mature</span><span>5 Best-in-class</span></div>', unsafe_allow_html=True)
            sl_l, sl_i, sl_reasons = calculate_auto_scores(sl_asset, sl_threat)
            sl_inh, sl_res = calculate_risks(sl_l, sl_i, sl_av, sl_ce)
            sl_lvl, sl_emoji, _ = risk_level(sl_res)
            lv_bgs = {"CRITICAL":"#FEF2F2","HIGH":"#FFF7ED","MEDIUM":"#FEFCE8","LOW":"#F0FDF4"}
            lv_fgs = {"CRITICAL":"#991B1B","HIGH":"#9A3412","MEDIUM":"#854D0E","LOW":"#166534"}
            sl_bg = lv_bgs.get(sl_lvl,"#F8FAFC")
            sl_fg = lv_fgs.get(sl_lvl,"#1D4ED8")
            st.markdown(f"""
            <div style="background:{sl_bg};border-radius:12px;padding:20px 24px;
                        border-left:5px solid {sl_fg};margin:12px 0;">
              <div style="display:flex;gap:32px;align-items:center;flex-wrap:wrap;">
                <div style="text-align:center;">
                  <div style="font-size:2.6rem;font-weight:900;color:{sl_fg};line-height:1;">{sl_res}</div>
                  <div style="font-size:0.7rem;color:{sl_fg};font-weight:700;opacity:0.7;">RESIDUAL / 25</div>
                </div>
                <div>
                  <div style="font-size:1.2rem;font-weight:800;color:{sl_fg};">{sl_emoji} {sl_lvl}</div>
                  <div style="font-size:0.82rem;color:{sl_fg};margin-top:4px;opacity:0.85;">
                    Inherent: {sl_inh}/25 → Residual: {sl_res}/25
                  </div>
                </div>
                <div style="font-family:'JetBrains Mono',monospace;font-size:0.78rem;color:{sl_fg};opacity:0.8;">
                  L={sl_l} · I={sl_i} · AV={sl_av} (×{AV_WEIGHT[sl_av]}) · CE={sl_ce} (−{int(CE_REDUCTION[sl_ce]*100)}%)
                </div>
              </div>
            </div>
            """, unsafe_allow_html=True)
            if st.button("▶ Save this risk to register", type="primary",
                         use_container_width=True, key="slider_save_sb"):
                _co = st.session_state.get("wizard_company","My Company") or "My Company"
                _ind = st.session_state.get("wizard_industry","Technology")
                sl_treat, _ = suggest_treatment(sl_threat, sl_res)
                sl_result = build_result(
                    asset=sl_asset, threat=sl_threat,
                    likelihood=sl_l, impact=sl_i,
                    asset_value=sl_av, control_effectiveness=sl_ce,
                    reasons=sl_reasons,
                    plain_summary=f"Risk scored via Slider Mode: {sl_asset} / {sl_threat}.",
                    actions=[
                        {"tag":"Do now",   "text":f"Review {sl_asset} for {sl_threat} exposure."},
                        {"tag":"This week","text":"Assign an owner and set a target date."},
                        {"tag":"Document", "text":"Upload evidence of existing controls."},
                    ],
                    confidence="medium",
                    company=_co, industry=_ind,
                    department="IT / Security", owner="Risk Owner",
                    status="Open", review_date=date.today(),
                    financial_impact="Medium", operational_impact="Medium",
                    compliance_impact="Medium", business_process="Business Operations",
                    vulnerability_name="", vulnerability_severity="Medium",
                    vulnerability_source="Slider Mode", evidence_name="",
                    evidence_owner="", audit_status="Evidence Missing",
                )
                st.session_state.history.append(sl_result)
                st.session_state.active_tab = 1
                st.session_state.just_saved = True
                st.rerun()
            st.stop()

        st.markdown("---")

        # ── Enterprise Context ────────────────────────────────────
        st.markdown('<div class="section-title">🏢 Enterprise Context</div>', unsafe_allow_html=True)
        st.caption("Who owns this risk and when should it be reviewed? These fields appear in all exports and reports.")
        ec1, ec2, ec3 = st.columns(3)
        with ec1:
            company  = st.text_input(
                "Company / Business Unit",
                value=st.session_state.get("wizard_company","") or "My Company",
                help="The organisation or business unit where this risk exists. Used in report headers.",
            )
            _industry_opts = ["General", "Technology", "Finance", "Healthcare", "Education", "Retail", "Manufacturing"]
            _wiz_ind = st.session_state.get("wizard_industry","General")
            industry = st.selectbox(
                "Industry",
                _industry_opts,
                index=_industry_opts.index(_wiz_ind) if _wiz_ind in _industry_opts else 0,
                help="Your industry sector. This tailors the Business Impact text.",
            )
        with ec2:
            department = st.text_input(
                "Department",
                value=st.session_state.get("wizard_industry","Information Technology"),
                help="The department responsible for managing this risk (e.g. IT, Finance, HR, Operations).",
            )
            owner = st.text_input(
                "Risk Owner",
                value="Security / IT Team",
                help="The named person or team accountable for this risk. They receive remediation actions and should sign off on treatment decisions.",
            )
        with ec3:
            status = st.selectbox(
                "Risk Status",
                ["Open", "In Progress", "Accepted", "Transferred", "Closed"],
                help=(
                    "Open - newly identified, no action taken yet.\n"
                    "In Progress - remediation is actively underway.\n"
                    "Accepted - risk acknowledged and formally accepted by the owner.\n"
                    "Transferred - risk shifted to a third party (e.g. insurer or vendor).\n"
                    "Closed - risk is resolved or no longer applicable."
                ),
            )
            review_date = st.date_input(
                "Review Date",
                value=date.today(),
                help="Date when this risk should next be reviewed. Critical and High risks should be reviewed within 30–90 days. Low risks can be reviewed annually.",
            )

        # ── Business Impact Analysis ──────────────────────────────
        st.markdown("---")
        st.markdown('<div class="section-title">💼 Business Impact Analysis</div>', unsafe_allow_html=True)
        st.caption("Rate the potential business consequences if this risk materialises. These do not affect the risk score - they enrich the report for executives and auditors.")
        bi1, bi2, bi3 = st.columns(3)
        with bi1:
            financial_impact = st.selectbox(
                "Financial Impact",
                ["Low", "Medium", "High", "Critical"],
                index=1,
                help=(
                    "Low - minimal financial exposure (e.g. < $10K).\n"
                    "Medium - moderate financial loss or recovery cost ($10K–$500K).\n"
                    "High - significant financial damage, fines, or litigation (> $500K).\n"
                    "Critical - potential for existential financial harm or regulatory penalty."
                ),
            )
        with bi2:
            operational_impact = st.selectbox(
                "Operational Impact",
                ["Low", "Medium", "High", "Critical"],
                index=1,
                help=(
                    "Low - minor disruption, business continues normally.\n"
                    "Medium - noticeable service degradation or process slowdown.\n"
                    "High - significant downtime or inability to deliver key services.\n"
                    "Critical - complete operational failure or safety-critical system unavailability."
                ),
            )
        with bi3:
            compliance_impact = st.selectbox(
                "Compliance / Regulatory Impact",
                ["Low", "Medium", "High", "Critical"],
                index=1,
                help=(
                    "Low - no regulatory reporting obligation.\n"
                    "Medium - internal policy breach requiring documentation.\n"
                    "High - reportable breach under GDPR, HIPAA, PCI DSS, or equivalent.\n"
                    "Critical - potential licence revocation, criminal liability, or regulatory enforcement."
                ),
            )
        business_process = st.text_input(
            "Affected Business Process",
            value="Core business operations",
            help="Name the specific process this risk targets, e.g. 'Customer order processing', 'Monthly payroll run', 'Patient data access'. This appears in the Business Impact section of reports.",
        )

        # ── Risk Factors ─────────────────────────────────────────
        st.markdown("---")
        st.markdown('<div class="section-title">🎛️ Risk Factors</div>', unsafe_allow_html=True)

        st.markdown('<div class="formula-strip">Inherent Risk = Likelihood × (Impact × AV_Weight) → clamped [1–25] &nbsp;|&nbsp; Residual Risk = Inherent × (1 − Control_Reduction%) → rounded [1–25]</div>', unsafe_allow_html=True)
        st.caption("These two sliders directly affect the risk score. Asset Value raises inherent risk; Control Effectiveness reduces it.")

        rf1, rf2 = st.columns(2)
        with rf1:
            asset_value = st.slider(
                "Asset Value / Business Criticality",
                1, 5, st.session_state.get("random_asset_value", 3), 1,
                help=(
                    "How critical is this asset to your organisation?\n\n"
                    "1 - Negligible (internal test system, low-value device)\n"
                    "2 - Low (departmental tool, non-customer-facing)\n"
                    "3 - Moderate (standard business system)\n"
                    "4 - High (customer-facing, regulated data)\n"
                    "5 - Mission-critical (core infrastructure, financial systems, patient data)"
                ),
            )
            st.markdown(f"""
            <div class="slider-legend">
              <span>{'●' if asset_value == 1 else '○'} 1 Negligible</span>
              <span>{'●' if asset_value == 2 else '○'} 2 Low</span>
              <span>{'●' if asset_value == 3 else '○'} 3 Moderate</span>
              <span>{'●' if asset_value == 4 else '○'} 4 High</span>
              <span>{'●' if asset_value == 5 else '○'} 5 Mission-critical</span>
            </div>""", unsafe_allow_html=True)
        with rf2:
            control_effectiveness = st.slider(
                "Control Effectiveness",
                1, 5, st.session_state.get("random_control_effectiveness", 3), 1,
                help=(
                    "How strong and tested are the current controls for this risk?\n\n"
                    "1 - Minimal / no controls in place (5% risk reduction)\n"
                    "2 - Basic hygiene only - e.g. antivirus, basic firewall (20% reduction)\n"
                    "3 - Standard controls, partially tested - e.g. MFA deployed, patching in place (45% reduction)\n"
                    "4 - Mature controls, regularly tested - e.g. annual pen test, documented IR plan (70% reduction)\n"
                    "5 - Best-in-class, evidenced - e.g. continuous monitoring, zero trust, quarterly red team (90% reduction)"
                ),
            )
            st.markdown(f"""
            <div class="slider-legend">
              <span>{'●' if control_effectiveness == 1 else '○'} 1 Minimal (5% reduction)</span>
              <span>{'●' if control_effectiveness == 2 else '○'} 2 Basic (20%)</span>
              <span>{'●' if control_effectiveness == 3 else '○'} 3 Standard (45%)</span>
              <span>{'●' if control_effectiveness == 4 else '○'} 4 Mature (70%)</span>
              <span>{'●' if control_effectiveness == 5 else '○'} 5 Best-in-class (90%)</span>
            </div>""", unsafe_allow_html=True)

        # Reset random values after they have been read to avoid slider drift on rerun
        st.session_state["random_asset_value"]          = asset_value
        st.session_state["random_control_effectiveness"] = control_effectiveness

        # ── CE evidence gate warning (can show immediately from slider) ──
        if control_effectiveness >= 4:
            st.markdown(f"""
            <div style="background:#FEFCE8;border:1px solid #FDE047;border-radius:8px;
                        padding:10px 14px;margin-top:6px;font-size:0.82rem;color:#713F12;">
              ⚠️ <strong>CE {control_effectiveness}/5 requires evidence.</strong>
              High control effectiveness claims must be supported by audit evidence
              (pen test reports, scan results, policy documents).
              Upload evidence in the Audit section below and set status to "Needs Review" or "Audit Ready."
            </div>
            """, unsafe_allow_html=True)

        st.markdown("---")
        st.markdown('<div class="section-title">🧩 Vulnerability, Evidence & Audit Tracking</div>', unsafe_allow_html=True)
        st.caption("Optional but recommended. Link this risk to a specific finding, upload proof, and set audit readiness. These fields are required for audit-ready GRC workflows.")
        va1, va2, va3 = st.columns(3)
        with va1:
            vulnerability_name = st.text_input(
                "Linked Vulnerability / Finding",
                value=st.session_state.get("prefill_vuln_name", ""),
                placeholder="CVE-2024-XXXX, weak MFA, exposed S3 bucket…",
                key="vulnerability_name_input",
                help="Reference a specific technical finding that this risk is based on. Examples: a CVE ID from a Nessus scan, a failed control from a pen test, a misconfiguration found in a cloud review.",
            )
            vulnerability_severity = st.selectbox(
                "Vulnerability Severity",
                ["Not Linked", "Low", "Medium", "High", "Critical"],
                help=(
                    "Not Linked - no specific vulnerability is attached (risk is threat-based only).\n"
                    "Low - CVSS 0.1–3.9 or minor control gap with limited exploitability.\n"
                    "Medium - CVSS 4.0–6.9 or control gap requiring user interaction to exploit.\n"
                    "High - CVSS 7.0–8.9 or significant control gap exploitable remotely.\n"
                    "Critical - CVSS 9.0–10.0 or critical control gap with active exploitation in the wild."
                ),
            )
        with va2:
            vulnerability_source = st.selectbox(
                "Finding Source",
                ["Manual Assessment", "Nessus", "Splunk", "SIEM", "EDR",
                 "Cloud Security Tool", "Penetration Test", "Audit Finding", "Other"],
                help=(
                    "Where was this finding identified?\n\n"
                    "Manual Assessment - analyst judgement or workshop.\n"
                    "Nessus - vulnerability scanner output (link Plugin ID above).\n"
                    "Splunk - SIEM alert or log search result.\n"
                    "SIEM - generic security information and event management alert.\n"
                    "EDR - endpoint detection and response alert.\n"
                    "Cloud Security Tool - CSPM output (e.g. AWS Security Hub, Defender for Cloud).\n"
                    "Penetration Test - formal pen test or red team finding.\n"
                    "Audit Finding - internal or external audit observation."
                ),
            )
            audit_status = st.selectbox(
                "Audit Status",
                ["Evidence Missing", "Needs Review", "Remediation In Progress", "Audit Ready"],
                help=(
                    "Evidence Missing - no supporting evidence exists yet. Action required before audit.\n"
                    "Needs Review - evidence has been uploaded but not yet validated by control owner or auditor.\n"
                    "Remediation In Progress - risk is being actively fixed; document progress and target date.\n"
                    "Audit Ready - evidence is complete, current, and owned. Ready for auditor review."
                ),
            )
        with va3:
            evidence_owner = st.text_input(
                "Evidence / Control Owner",
                value="Security / IT Team",
                help="The person or team responsible for maintaining the evidence and the underlying control. This is the person an auditor would contact.",
            )
            evidence_file = st.file_uploader(
                "Upload Evidence",
                type=["pdf", "png", "jpg", "jpeg", "csv", "txt", "xlsx", "docx"],
                help=(
                    "Attach proof that supports this risk assessment or demonstrates control effectiveness.\n\n"
                    "Good evidence examples: scan output (CSV/PDF), screenshots of security dashboards, "
                    "policy documents, audit reports, incident tickets, penetration test excerpts, log extracts."
                ),
            )
        evidence_name = evidence_file.name if evidence_file is not None else "No evidence uploaded"

        with st.expander("🔌 Integration Notes - Nessus / Splunk"):
            st.write("**Nessus:** Export CSV scan results and enter the Plugin ID, severity, and affected asset name in the fields above.")
            st.write("**Splunk:** Reference alert name, search ID, and time range from Splunk when entering a finding. Upload the exported log as evidence.")
            st.write("**Future integration:** Direct API connectivity to Nessus and Splunk can be added to auto-populate findings.")

        # Validation warnings (shown before the analysis button)
        val_warnings = validate_inputs(asset_value, control_effectiveness, audit_status, evidence_name, vulnerability_severity)
        for w in val_warnings:
            st.warning(w)

        st.markdown("---")

        # ── INPUT MODE ────────────────────────────────────────────
        asset = threat = None
        likelihood = impact = None
        reasons = []

        if st.session_state.input_mode == "smart":
            st.markdown('<div class="section-title">💬 Describe the Risk</div>', unsafe_allow_html=True)
            st.caption("Describe what happened or what you're concerned about. The platform will detect the asset, threat, and risk scores automatically.")

            # Example prompts
            ex_cols = st.columns(3)
            for idx, ex in enumerate(EXAMPLE_PROMPTS):
                with ex_cols[idx % 3]:
                    if st.button(f"📌 {ex[:44]}…" if len(ex) > 44 else f"📌 {ex}", key=f"ex_{idx}", use_container_width=True):
                        st.session_state.smart_description = ex
                        st.rerun()

            description = st.text_area(
                "Risk description",
                value=st.session_state.smart_description,
                height=110,
                placeholder="Example: Our cloud storage bucket was accidentally set to public access for two days…",
                label_visibility="collapsed",
            )
            st.session_state.smart_description = description
            can_analyze = len(description.strip()) > 10 and role_info["can_edit"]

            if st.button("🚀 Analyse Risk", type="primary", disabled=not can_analyze):
                with st.spinner("Analysing…"):
                    parsed = ai_analyze_description(description)

                fallback_asset, fallback_threat = fallback_detect(description)
                used_ai = False

                if parsed is None:
                    asset, threat   = fallback_asset, fallback_threat
                    likelihood, impact, reasons = calculate_auto_scores(asset, threat)
                    plain_summary   = f"The assessment indicates a {threat.lower()} risk affecting the {asset.lower()}."
                    actions         = []
                    confidence      = "medium"
                else:
                    asset       = parsed.get("asset", fallback_asset)
                    threat      = parsed.get("threat", fallback_threat)
                    if asset  not in ASSET_OPTIONS:  asset  = fallback_asset
                    if threat not in THREAT_OPTIONS: threat = fallback_threat
                    valid = safe_threats_for_asset(asset)
                    if threat not in valid: threat = valid[0]
                    likelihood    = max(1, min(5, int(parsed.get("likelihood", 3))))
                    impact        = max(1, min(5, int(parsed.get("impact",     3))))
                    reasons       = ["Smart Mode: scores estimated by AI from the description."]
                    plain_summary = parsed.get("plain_english_summary", "")
                    actions       = parsed.get("actions", [])
                    confidence    = parsed.get("confidence", "medium")
                    used_ai       = True

                result = build_result(
                    asset, threat, likelihood, impact, asset_value, control_effectiveness,
                    reasons, plain_summary, actions, confidence,
                    company, industry, department, owner, status, review_date,
                    financial_impact, operational_impact, compliance_impact, business_process,
                    vulnerability_name, vulnerability_severity, vulnerability_source,
                    evidence_name, evidence_owner, audit_status,
                )
                st.session_state.last_result = result
                if used_ai:
                    st.caption("✅ AI analysis used. Verify asset, threat, and scores before saving.")
                else:
                    st.caption("ℹ️ Rule-based fallback used. AI unavailable or ANTHROPIC_API_KEY not set.")

        else:
            st.markdown('<div class="section-title">🧾 Analyst Inputs</div>', unsafe_allow_html=True)
            asset = st.selectbox(
                "Asset",
                ASSET_OPTIONS,
                index=ASSET_OPTIONS.index(st.session_state.selected_asset),
                help="Select the IT or business asset that is at risk. The threat list will automatically filter to only the threats relevant to this asset type.",
            )
            st.session_state.selected_asset = asset

            valid_threats = safe_threats_for_asset(asset)
            if st.session_state.selected_threat not in valid_threats:
                st.session_state.selected_threat = valid_threats[0]
            threat = st.selectbox(
                "Threat",
                valid_threats,
                index=valid_threats.index(st.session_state.selected_threat),
                help="Select the threat scenario most relevant to this asset. Only threats applicable to the selected asset are shown. Likelihood and Impact scores will be auto-calculated from the asset–threat pair.",
            )
            st.session_state.selected_threat = threat

            likelihood, impact, reasons = calculate_auto_scores(asset, threat)
            m1, m2 = st.columns(2)
            with m1: st.metric("Auto-scored Likelihood", f"{likelihood} / 5")
            with m2: st.metric("Auto-scored Impact",     f"{impact} / 5")

            with st.expander("How these scores were derived"):
                for r in reasons:
                    st.write(f"- {r}")

            if st.button("🚀 Analyse Risk", type="primary", disabled=not role_info["can_edit"]):
                result = build_result(
                    asset, threat, likelihood, impact, asset_value, control_effectiveness,
                    reasons, "", [], "high",
                    company, industry, department, owner, status, review_date,
                    financial_impact, operational_impact, compliance_impact, business_process,
                    vulnerability_name, vulnerability_severity, vulnerability_source,
                    evidence_name, evidence_owner, audit_status,
                )
                st.session_state.last_result = result

        # ── RESULTS ───────────────────────────────────────────────
        result = st.session_state.last_result
        if result:
            st.markdown("---")

            lvl = result["Residual Level"]
            cls = level_css_class(lvl)
            lv_colors = {
                "CRITICAL": ("#FEF2F2","#991B1B","#FECACA"),
                "HIGH":     ("#FFF7ED","#9A3412","#FED7AA"),
                "MEDIUM":   ("#FEFCE8","#854D0E","#FEF08A"),
                "LOW":      ("#F0FDF4","#166534","#BBF7D0"),
            }
            lv_bg, lv_fg, lv_border = lv_colors.get(lvl, ("#F8FAFC","#1D4ED8","#E2E8F0"))

            # ── 4 KPI CARDS ───────────────────────────────────────
            k1, k2, k3, k4 = st.columns(4)
            with k1:
                st.markdown(f"""
                <div class="kpi-card {cls}">
                  <div class="kpi-label">Inherent Risk</div>
                  <div class="kpi-value">{result['Inherent Risk']}</div>
                  <div class="kpi-sub">Pre-control / 25</div>
                </div>""", unsafe_allow_html=True)
            with k2:
                st.markdown(f"""
                <div class="kpi-card {cls}">
                  <div class="kpi-label">Residual Risk</div>
                  <div class="kpi-value">{result['Residual Risk']}<span style="font-size:1rem;color:#94A3B8"> / 25</span></div>
                  <div class="kpi-sub">After controls</div>
                </div>""", unsafe_allow_html=True)
            with k3:
                st.markdown(f"""
                <div class="kpi-card {cls}">
                  <div class="kpi-label">Risk Level</div>
                  <div class="kpi-value">{result['Residual Emoji']} {lvl}</div>
                  <div class="kpi-sub">Severity band</div>
                </div>""", unsafe_allow_html=True)
            with k4:
                tgt = result.get("Target Residual Risk", result["Residual Risk"])
                delta = result["Residual Risk"] - tgt
                st.markdown(f"""
                <div class="kpi-card">
                  <div class="kpi-label">If Controls Improve</div>
                  <div class="kpi-value" style="color:#16A34A">{tgt}<span style="font-size:1rem;color:#94A3B8"> / 25</span></div>
                  <div class="kpi-sub">↓ {delta} pts at CE+1</div>
                </div>""", unsafe_allow_html=True)

            st.markdown("")

            # ── LEVEL BANNER ──────────────────────────────────────
            st.markdown(f"""
            <div style="background:{lv_bg};border:1px solid {lv_border};border-left:5px solid {lv_fg};
                        border-radius:8px;padding:12px 18px;margin-bottom:10px;
                        display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:8px;">
              <div>
                <strong style="color:{lv_fg};font-size:1.05rem;">{result['Residual Emoji']} {lvl} - {result['Priority']}</strong>
                <span style="color:{lv_fg};font-size:0.85rem;margin-left:8px;">{result['Priority Rationale']}</span>
              </div>
              <div style="background:{lv_fg};color:white;border-radius:16px;
                          padding:4px 14px;font-size:0.8rem;font-weight:700;">
                {result['Final Treatment']}
              </div>
            </div>
            """, unsafe_allow_html=True)

            # ── PLAIN-ENGLISH SUMMARY ─────────────────────────────
            if result.get("Plain English Summary"):
                st.markdown(f"""
                <div style="background:#F8FAFC;border-left:4px solid #1D4ED8;
                            border-radius:0 8px 8px 0;padding:13px 18px;margin-bottom:10px;
                            font-size:0.9rem;color:#1E293B;line-height:1.65;">
                  {result['Plain English Summary']}
                </div>
                """, unsafe_allow_html=True)

            # ── 3 QUICK ACTION TILES ─────────────────────────────
            if result.get("AI Actions"):
                ac = st.columns(len(result["AI Actions"]))
                for i, action in enumerate(result["AI Actions"]):
                    with ac[i]:
                        st.markdown(f"""
                        <div style="background:white;border:1px solid #E2E8F0;
                                    border-top:3px solid #1D4ED8;border-radius:8px;
                                    padding:12px 14px;font-size:0.82rem;height:100%;">
                          <div style="font-weight:700;color:#1D4ED8;margin-bottom:4px;">{action['tag']}</div>
                          <div style="color:#334155;">{action['text']}</div>
                        </div>
                        """, unsafe_allow_html=True)
                st.markdown("")

            # ── IMPROVEMENT + APPETITE ALERTS ─────────────────────
            if result.get("Exceeds Risk Appetite"):
                st.markdown(f"""
                <div style="background:#FEF2F2;border:1px solid #FECACA;border-left:4px solid #DC2626;
                            border-radius:8px;padding:10px 16px;margin-bottom:8px;font-size:0.85rem;">
                  <strong style="color:#991B1B;">⚠️ Exceeds risk appetite (threshold: {st.session_state.get('risk_appetite',12)}/25)</strong>
                  <div style="color:#7F1D1D;margin-top:2px;">{result.get('Risk Appetite Note','')}</div>
                </div>
                """, unsafe_allow_html=True)

            if result.get("Target Risk Note") and result.get("Target Residual Risk", 0) < result["Residual Risk"]:
                st.markdown(f"""
                <div style="background:#F0FDF4;border:1px solid #BBF7D0;border-left:4px solid #16A34A;
                            border-radius:8px;padding:10px 16px;margin-bottom:8px;font-size:0.85rem;">
                  <strong style="color:#166534;">📈 {result['Target Risk Note']}</strong>
                </div>
                """, unsafe_allow_html=True)

            # ── DETAIL EXPANDERS ──────────────────────────────────
            with st.expander("📊 Business Impact, Controls & Heatmap"):
                e1, e2 = st.columns(2)
                with e1:
                    st.markdown("**💼 Business Impact**")
                    st.write(result["Business Impact"])
                    st.markdown("**📈 Control Maturity**")
                    st.write(result["Maturity Hint"])
                with e2:
                    st.markdown("**✅ Recommended Controls**")
                    for rec in result["Recommended Controls"].split(" | "):
                        if rec: st.write(f"• {rec}")
                    st.markdown("**🔄 Next Steps**")
                    for s in result["Next Steps"].split(" | "):
                        if s: st.write(f"• {s}")
                hm_col, _ = st.columns([1, 1])
                with hm_col:
                    st.plotly_chart(
                        create_heatmap_plotly(result["Likelihood"], result["Impact"]),
                        use_container_width=True,
                        config={"displayModeBar": False},
                    )
                hm_img = create_heatmap_image(result["Likelihood"], result["Impact"])
                with open(hm_img, "rb") as hf:
                    _hm_bytes = hf.read()
                    st.download_button("⬇️ Download Heatmap", _hm_bytes, "risk_heatmap.png",
                                       "image/png", key="dl_hm")

            with st.expander("🧠 Framework Mappings"):
                user_fw = st.session_state.get("wizard_frameworks",
                          ["NIST CSF 2.0","ISO 27001","NIST RMF"])
                fw_map = {
                    "NIST CSF 2.0": result.get("NIST Mapping",""),
                    "NIST RMF":     result.get("RMF Mapping",""),
                    "ISO 27001":    result.get("ISO 27001 Mapping",""),
                    "HIPAA":        result.get("HIPAA Mapping",""),
                    "PCI DSS":      result.get("PCI DSS Mapping",""),
                    "GDPR":         result.get("GDPR Mapping",""),
                    "CCPA":         result.get("CCPA Mapping",""),
                }
                fm1, fm2 = st.columns(2)
                cols_cycle = [fm1, fm2]
                for idx, (fw, mapping) in enumerate(fw_map.items()):
                    if not mapping: continue
                    with cols_cycle[idx % 2]:
                        st.markdown(f"**{fw}**")
                        st.caption(mapping)
                        plain = get_framework_plain_english(result["Threat"], fw)
                        if plain and fw in user_fw:
                            st.info(f"💡 {plain}", icon=None)
                st.markdown("**Mapped Controls**")
                for item in result["Mapped Controls"].split(" | "):
                    if item: st.write(f"• {item}")

            with st.expander("🧩 Audit & Evidence"):
                vc1, vc2 = st.columns(2)
                with vc1:
                    st.write(f"**Finding:** {result.get('Vulnerability / Finding','—')}")
                    st.write(f"**Severity:** {result.get('Vulnerability Severity','—')}")
                    st.write(f"**Source:** {result.get('Finding Source','—')}")
                with vc2:
                    st.write(f"**Evidence File:** {result.get('Evidence File','None uploaded')}")
                    st.write(f"**Evidence Owner:** {result.get('Evidence Owner','—')}")
                    st.write(f"**Audit Status:** {result.get('Audit Status','—')}")
                if result.get("CE Gate Warning"):
                    st.warning(result["CE Gate Warning"])
                rec = result.get("Audit Recommendation","")
                if result.get("Audit Status") in ("Evidence Missing","Needs Review"):
                    st.warning(rec)
                else:
                    st.info(rec)

            with st.expander("🧮 Scoring Methodology"):
                _l = result.get("Likelihood",3); _i = result.get("Impact",3)
                ldef = LIKELIHOOD_DEFINITIONS.get(_l,{})
                idef = IMPACT_DEFINITIONS.get(_i,{})
                sc1, sc2, sc3, sc4 = st.columns(4)
                sc1.metric("Likelihood", f"{_l}/5",  ldef.get('label',''))
                sc2.metric("Impact",     f"{_i}/5",  idef.get('label',''))
                sc3.metric("Asset Value",f"{result['Asset Value']}/5")
                sc4.metric("CE",         f"{result['Control Effectiveness']}/5")
            _av_w  = AV_WEIGHT.get(result["Asset Value"], 1.0)
            _ce_r  = int(CE_REDUCTION.get(result["Control Effectiveness"], 0.45) * 100)
            st.markdown(
            f'<div class="formula-strip">Stage 1: Inherent = L({_l}) x I({_i}) x AV({_av_w:.2f}) = {result["Inherent Risk"]}/25 &nbsp;|&nbsp; Stage 2: Residual = {result["Inherent Risk"]} x (1-{_ce_r}%) = {result["Residual Risk"]}/25</div>',
            unsafe_allow_html=True
            )
            for note in result.get("Scoring Notes","").split(" | "):
                if note: st.caption(note)

            st.markdown("---")

            # ── TREATMENT & SAVE ──────────────────────────────────
            st.markdown("### 🛡️ Treatment Decision")

            ts1, ts2 = st.columns([1, 1])
            with ts1:
                treat_opts = ["Mitigate", "Accept", "Transfer", "Avoid"]
                selected_treatment = st.selectbox(
                    "Treatment",
                    treat_opts,
                    index=treat_opts.index(result.get("Final Treatment","Mitigate")),
                    help="Mitigate - reduce. Accept - acknowledge (Low only). Transfer - insure. Avoid - stop the activity.",
                )
                result["Final Treatment"] = selected_treatment
            with ts2:
                treatment_owner = st.text_input(
                    "Treatment Owner",
                    value=result.get("Treatment Owner",""),
                    placeholder="Named person responsible",
                )
                from datetime import date as _date, timedelta as _td
                treatment_target_date = st.text_input(
                    "Target Date",
                    value=result.get("Treatment Target Date", str(_date.today()+_td(days=30))),
                    placeholder="YYYY-MM-DD",
                )

            treatment_notes = st.text_area(
                "Action Steps",
                value=result.get("Treatment Notes",""),
                placeholder="Specific, verifiable steps - e.g. 'Enable MFA on all admin accounts by 2026-08-01.'",
                height=70,
            )

            accept_review_date = ""
            if selected_treatment == "Accept":
                st.warning("⏰ Accepted risks must have a review date (max 12 months).")
                accept_review_date = st.text_input(
                    "Accept Review Date",
                    value=str(_date.today()+_td(days=90)),
                    placeholder="YYYY-MM-DD",
                )

            result["Treatment Owner"]       = treatment_owner
            result["Treatment Target Date"] = treatment_target_date
            result["Treatment Notes"]       = treatment_notes
            result["Accept Review Date"]    = accept_review_date

            is_duplicate = check_for_duplicate(result["Asset"], result["Threat"])
            if is_duplicate:
                st.markdown(
                    f'<div class="dup-warn">⚠️ A risk entry for <strong>{result["Asset"]}</strong> / '
                    f'<strong>{result["Threat"]}</strong> already exists in the register. '
                    f'Saving again will add a second entry.</div>',
                    unsafe_allow_html=True,
                )

            if st.button("💾 Save to Risk Register", type="primary",
                         disabled=not role_info["can_save"], use_container_width=True):
                st.session_state.history.append(result.copy())
                st.session_state.active_tab = 1
                st.session_state.just_saved = True
                st.rerun()
            elif not role_info["can_save"]:
                st.info("Switch to Admin or Manager role in the sidebar to save risks.")
            else:
                st.markdown("""
                <div style="background:#F0FDF4;border:1px solid #BBF7D0;border-radius:8px;
                            padding:10px 16px;font-size:0.88rem;color:#166534;">
                  ⬆️ <strong>Click Save</strong> - you'll jump straight to the Risk Register & Reports tab.
                </div>
                """, unsafe_allow_html=True)
            st.markdown(f"""
            <div style="background:{lv_bg};border:2px solid {lv_border};border-radius:14px;
                        padding:24px 28px;margin-bottom:16px;">
              <div style="display:flex;align-items:center;gap:24px;flex-wrap:wrap;">

                <!-- Residual score -->
                <div style="text-align:center;min-width:80px;">
                  <div style="font-size:3.2rem;font-weight:900;color:{lv_fg};line-height:1;">
                    {result['Residual Risk']}
                  </div>
                  <div style="font-size:0.7rem;color:{lv_fg};font-weight:700;opacity:0.7;">OUT OF 25</div>
                </div>

                <!-- Divider -->
                <div style="width:2px;height:70px;background:{lv_border};opacity:0.6;"></div>

                <!-- Level + arrow + treatment -->
                <div style="flex:1;min-width:180px;">
                  <div style="font-size:1.4rem;font-weight:800;color:{lv_fg};">
                    {result['Residual Emoji']} {lvl}
                  </div>
                  <div style="font-size:0.88rem;color:{lv_fg};margin:4px 0;opacity:0.85;">
                    {result['Priority']} - {result['Priority Rationale']}
                  </div>
                  <div style="display:inline-block;background:{lv_fg};color:white;
                              border-radius:20px;padding:3px 12px;font-size:0.78rem;font-weight:700;margin-top:4px;">
                    Recommended: {result['Final Treatment']}
                  </div>
                </div>

                <!-- Divider -->
                <div style="width:2px;height:70px;background:{lv_border};opacity:0.6;"></div>

                <!-- Inherent vs Residual -->
                <div style="text-align:center;min-width:120px;">
                  <div style="font-size:0.7rem;font-weight:700;color:{lv_fg};opacity:0.7;margin-bottom:6px;">
                    RISK JOURNEY
                  </div>
                  <div style="display:flex;align-items:center;gap:8px;justify-content:center;">
                    <div>
                      <div style="font-size:1.3rem;font-weight:800;color:#64748B;">{result['Inherent Risk']}</div>
                      <div style="font-size:0.65rem;color:#64748B;">Inherent</div>
                    </div>
                    <div style="font-size:1.2rem;color:{lv_fg};">→</div>
                    <div>
                      <div style="font-size:1.3rem;font-weight:800;color:{lv_fg};">{result['Residual Risk']}</div>
                      <div style="font-size:0.65rem;color:{lv_fg};">Residual</div>
                    </div>
                    <div style="font-size:1.2rem;color:#16A34A;">→</div>
                    <div>
                      <div style="font-size:1.3rem;font-weight:800;color:#16A34A;">{result.get('Target Residual Risk', result['Residual Risk'])}</div>
                      <div style="font-size:0.65rem;color:#16A34A;">Target</div>
                    </div>
                  </div>
                </div>

              </div>
            </div>
            """, unsafe_allow_html=True)

            st.markdown("### 🛡️ Treatment Decision & Save")

            ts1, ts2 = st.columns([1, 1])
            with ts1:
                treat_opts = ["Mitigate", "Accept", "Transfer", "Avoid"]
                selected_treatment = st.selectbox(
                    "Treatment",
                    treat_opts,
                    index=treat_opts.index(result.get("Final Treatment","Mitigate")),
                    help="Mitigate=reduce. Accept=acknowledge (Low only). Transfer=insure. Avoid=stop the activity.",
                )
                result["Final Treatment"] = selected_treatment

                if result.get("CE Gate Warning"):
                    st.warning(result["CE Gate Warning"])

            with ts2:
                treatment_owner = st.text_input(
                    "Treatment Owner",
                    value=result.get("Treatment Owner",""),
                    placeholder="Named person responsible",
                )
                from datetime import date as _date, timedelta as _td
                treatment_target_date = st.text_input(
                    "Target Date",
                    value=result.get("Treatment Target Date", str(_date.today()+_td(days=30))),
                    placeholder="YYYY-MM-DD",
                )

            treatment_notes = st.text_area(
                "Action Steps",
                value=result.get("Treatment Notes",""),
                placeholder="Specific, verifiable steps with dates - e.g. 'Enable MFA on all admin accounts by 2026-08-01.'",
                height=70,
            )

            accept_review_date = ""
            if selected_treatment == "Accept":
                st.warning("⏰ Accepted risks require a review date (max 12 months).")
                accept_review_date = st.text_input(
                    "Accept Review Date",
                    value=str(_date.today()+_td(days=90)),
                    placeholder="YYYY-MM-DD",
                )

            result["Treatment Owner"]       = treatment_owner
            result["Treatment Target Date"] = treatment_target_date
            result["Treatment Notes"]       = treatment_notes
            result["Accept Review Date"]    = accept_review_date

            # Duplicate check
            is_duplicate = check_for_duplicate(result["Asset"], result["Threat"])
            if is_duplicate:
                st.markdown(
                    f'<div class="dup-warn">⚠️ A risk entry for <strong>{result["Asset"]}</strong> / '
                    f'<strong>{result["Threat"]}</strong> already exists in the register. '
                    f'Saving again will add a second entry.</div>',
                    unsafe_allow_html=True,
                )

            if st.button("💾 Save to Risk Register", type="primary",
                         disabled=not role_info["can_save"], use_container_width=True):
                st.session_state.history.append(result.copy())
                st.session_state.active_tab = 1
                st.session_state.just_saved = True
                st.rerun()

            elif not role_info["can_save"]:
                st.info("Switch to Admin or Manager role in the sidebar to save risks.")
            else:
                st.markdown("""
                <div style="background:#F0FDF4;border:1px solid #BBF7D0;border-radius:8px;
                            padding:10px 16px;margin-top:4px;font-size:0.88rem;color:#166534;">
                  ⬆️ <strong>Click Save to Risk Register</strong> above - you'll be taken straight
                  to the Risk Register & Reports tab to download your report.
                </div>
                """, unsafe_allow_html=True)




    # ══════════════════════════════════════════════════════════════
    # SECTION 2 - RISK REGISTER & REPORTS
    # ══════════════════════════════════════════════════════════════
if _show_register:
    # ── Success banner if just arrived from saving ────────────
    if st.session_state.history and st.session_state.get("just_saved"):
        latest = st.session_state.history[-1]
        lv = latest.get("Residual Level", "")
        lv_color = {"CRITICAL":"#991B1B","HIGH":"#DC2626","MEDIUM":"#D97706","LOW":"#16A34A"}.get(lv,"#1D4ED8")
        st.markdown(f"""
        <div style="background:{lv_color}10;border:1px solid {lv_color}40;border-left:4px solid {lv_color};
                    border-radius:10px;padding:14px 18px;margin-bottom:16px;">
          <span style="font-weight:700;color:{lv_color};font-size:1.05rem;">
            ✓ Risk saved: {latest.get('Asset','')} / {latest.get('Threat','')} ({lv})
          </span><br>
          <span style="color:#475569;font-size:0.88rem;">
            Residual Risk: <strong>{latest.get('Residual Risk','')}/25</strong> -
            Treatment: <strong>{latest.get('Final Treatment','')}</strong> ·
            Go to Download Reports in the sidebar to get your PDF
          </span>
        </div>
        """, unsafe_allow_html=True)
        st.session_state.just_saved = False

    if not st.session_state.history:
        st.info("No risks saved yet. Go to Risk Assessment to create risks, or load demo data.")
        if st.button("Load demo data", use_container_width=True, key="load_demo_register"):
            st.session_state.history.append(build_demo_risk())
            st.rerun()
    else:
        df = pd.DataFrame(st.session_state.history)

        # Always compute fdf (needed by all sub-sections)
        fc1, fc2, fc3 = st.columns(3)
        with fc1:
            sel_level  = st.selectbox("Filter by Level",  ["All"] + sorted(df["Residual Level"].dropna().unique().tolist()))
        with fc2:
            sel_status = st.selectbox("Filter by Status", ["All"] + sorted(df["Status"].dropna().unique().tolist()))
        with fc3:
            max_rows   = st.slider("Rows to display", 5, min(200, max(5, len(df))), min(25, len(df)))
        fdf = df.copy()
        if sel_level  != "All": fdf = fdf[fdf["Residual Level"] == sel_level]
        if sel_status != "All": fdf = fdf[fdf["Status"]         == sel_status]

        # KPI strip — always visible
        dk1, dk2, dk3, dk4 = st.columns(4)
        with dk1: st.metric("Total Risks",       len(fdf))
        with dk2: st.metric("Avg Residual Risk", f"{round(fdf['Residual Risk'].mean(), 1) if not fdf.empty else 0} / 25")
        with dk3: st.metric("Max Risk",          int(fdf["Residual Risk"].max()) if not fdf.empty else 0)
        with dk4: st.metric("Open Risks",        int((fdf["Status"] != "Closed").sum()) if not fdf.empty else 0)
        st.markdown("")

        if _show_reg_table:
            st.markdown("### 📋 Risk Register")

            # ── Risk appetite summary ─────────────────────────────
            _app = st.session_state.get("risk_appetite", DEFAULT_RISK_APPETITE)
            _exceeds = fdf[fdf.get("Exceeds Risk Appetite", pd.Series([False]*len(fdf))).astype(bool)] if "Exceeds Risk Appetite" in fdf.columns else pd.DataFrame()
            _exc_n = len(_exceeds)
            if _exc_n > 0:
                st.markdown(f"""
                <div style="background:#FEF2F2;border:1px solid #FECACA;border-left:4px solid #DC2626;
                            border-radius:8px;padding:10px 16px;margin-bottom:10px;">
                  <strong style="color:#991B1B;">⚠️ {_exc_n} risk(s) exceed your risk appetite (threshold: {_app}/25)</strong>
                  <span style="color:#7F1D1D;font-size:0.85rem;margin-left:8px;">
                    These require active treatment - they cannot be accepted without explicit sign-off.
                  </span>
                </div>
                """, unsafe_allow_html=True)
            else:
                st.markdown(f"""
                <div style="background:#F0FDF4;border:1px solid #BBF7D0;border-radius:8px;
                            padding:8px 14px;margin-bottom:10px;font-size:0.83rem;color:#166534;">
                  ✅ All risks are within your risk appetite threshold ({_app}/25).
                </div>
                """, unsafe_allow_html=True)

            display_cols = [
                "Asset", "Threat", "Residual Risk", "Residual Level",
                "Final Treatment", "Treatment Owner", "Treatment Target Date",
                "Status", "Review Date", "Audit Status",
            ]
            st.dataframe(
                fdf[[c for c in display_cols if c in fdf.columns]].head(max_rows),
                use_container_width=True,
                height=340,
            )


        if _show_reg_charts or _show_reg_table:
            # Charts
            if _show_reg_charts or _show_reg_table:
                st.markdown("### 📈 Dashboard")
                ch1, ch2 = st.columns(2)
            with ch1:
                level_counts = fdf["Residual Level"].value_counts().reset_index()
                level_counts.columns = ["Level", "Count"]
                color_map = {"CRITICAL": "#991B1B", "HIGH": "#DC2626", "MEDIUM": "#D97706", "LOW": "#16A34A"}
                fig_level = go.Figure(go.Bar(
                    x=level_counts["Level"],
                    y=level_counts["Count"],
                    marker_color=[color_map.get(l, "#2563EB") for l in level_counts["Level"]],
                    text=level_counts["Count"],
                    textposition="outside",
                ))
                fig_level.update_layout(
                    title="Risk Level Distribution", height=320,
                    margin=dict(l=20, r=20, t=40, b=20),
                    plot_bgcolor="#F8FAFC", paper_bgcolor="#F8FAFC",
                    yaxis=dict(fixedrange=True, showgrid=True, gridcolor="#E2E8F0"),
                    xaxis=dict(fixedrange=True),
                    font=dict(family="IBM Plex Sans, sans-serif", size=12),
                )
                st.plotly_chart(fig_level, use_container_width=True, config={"displayModeBar": False})

            with ch2:
                treat_counts = fdf["Final Treatment"].value_counts().reset_index()
                treat_counts.columns = ["Treatment", "Count"]
                treat_color = {"Mitigate": "#1D4ED8", "Accept": "#16A34A", "Transfer": "#D97706", "Avoid": "#991B1B"}
                fig_treat = go.Figure(go.Bar(
                    x=treat_counts["Treatment"],
                    y=treat_counts["Count"],
                    marker_color=[treat_color.get(t, "#2563EB") for t in treat_counts["Treatment"]],
                    text=treat_counts["Count"],
                    textposition="outside",
                ))
                fig_treat.update_layout(
                    title="Treatment Distribution", height=320,
                    margin=dict(l=20, r=20, t=40, b=20),
                    plot_bgcolor="#F8FAFC", paper_bgcolor="#F8FAFC",
                    yaxis=dict(fixedrange=True, showgrid=True, gridcolor="#E2E8F0"),
                    xaxis=dict(fixedrange=True),
                    font=dict(family="IBM Plex Sans, sans-serif", size=12),
                )
                st.plotly_chart(fig_treat, use_container_width=True, config={"displayModeBar": False})

            # ── RISK MAPPED AGAINST ASSET (bubble chart) ──────────
            st.markdown("**Risk by Asset**")
            st.caption("Each bubble is a risk entry. Size = Residual Risk score. Colour = risk level. Hover for details.")

            _bubble_df = fdf[["Asset", "Threat", "Residual Risk", "Inherent Risk",
                               "Residual Level", "Final Treatment"]].copy()
            _bubble_df["_jitter"] = range(len(_bubble_df))  # x-axis spread

            _lv_color_map = {
                "CRITICAL": "#991B1B", "HIGH": "#DC2626",
                "MEDIUM": "#D97706",   "LOW": "#16A34A",
            }

            fig_asset = go.Figure()
            for lv, grp in _bubble_df.groupby("Residual Level"):
                fig_asset.add_trace(go.Scatter(
                    x=grp["Asset"],
                    y=grp["Residual Risk"],
                    mode="markers",
                    name=lv,
                    marker=dict(
                        color=_lv_color_map.get(lv, "#2563EB"),
                        size=grp["Residual Risk"] * 2.8,
                        opacity=0.82,
                        line=dict(width=1.5, color="white"),
                    ),
                    text=grp["Asset"] + " / " + grp["Threat"]
                         + "<br>Residual: " + grp["Residual Risk"].astype(str)
                         + " | Treatment: " + grp["Final Treatment"],
                    hovertemplate="%{text}<extra></extra>",
                ))

            fig_asset.update_layout(
                height=380,
                margin=dict(l=20, r=20, t=20, b=120),
                plot_bgcolor="#F8FAFC", paper_bgcolor="#F8FAFC",
                xaxis=dict(
                    title="Asset",
                    fixedrange=True,
                    tickangle=-35,
                    showgrid=True, gridcolor="#E2E8F0",
                ),
                yaxis=dict(
                    title="Residual Risk Score",
                    fixedrange=True,
                    range=[0, 27],
                    showgrid=True, gridcolor="#E2E8F0",
                ),
                legend=dict(orientation="h", y=1.08, x=0),
                font=dict(family="IBM Plex Sans, sans-serif", size=11),
            )
            st.plotly_chart(fig_asset, use_container_width=True, config={"displayModeBar": False})


        if _show_reg_reports or _show_reg_table:
            # Export
            if _show_reg_reports or _show_reg_table:
                st.subheader("Download Reports")
                EXPORT_COLS = [
                "Company / Unit","Report Type","Industry","Department","Risk Owner","Status","Review Date",
                "Asset","Threat","Likelihood","Impact","Asset Value","Control Effectiveness",
                "Inherent Risk","Residual Risk","Residual Level","Heatmap Summary","Priority","Priority Rationale",
                "Vulnerability / Finding","Vulnerability Severity","Finding Source","Evidence File","Evidence Owner",
                "Audit Status","Audit Recommendation",
                "Financial Impact","Operational Impact","Compliance Impact","Affected Business Process",
                "Business Impact","NIST Mapping","RMF Mapping","ISO 27001 Mapping",
                "Mapped Controls","Zero Trust Guidance","Recommended Controls","Next Steps",
            ]
            export_df = fdf.copy()
            export_df["Assumptions & Limitations"] = " | ".join(get_assumptions_limitations())
            available_cols = [c for c in EXPORT_COLS if c in export_df.columns]
            clean_df  = export_df[available_cols + ["Assumptions & Limitations"]]
            csv_bytes = clean_df.to_csv(index=False).encode("utf-8")

            ex1, ex2, ex3 = st.columns(3)
            with ex1:
                st.download_button(
                    "📥 Download CSV Register",
                    csv_bytes,
                    "grc_risk_register.csv",
                    "text/csv",
                    key="dl_csv",
                )
            with ex2:
                txt_report = generate_txt_report(fdf)
                st.download_button(
                    "📄 Download Text Report",
                    txt_report.encode("utf-8"),
                    "grc_risk_report.txt",
                    "text/plain",
                    key="dl_txt",
                )
            with ex3:
                pdf_path = generate_pdf_report(fdf)
                with open(pdf_path, "rb") as pf:
                    _pdf_bytes = pf.read()
                st.download_button(
                    "🧾 Download PDF Report",
                    _pdf_bytes,
                    "grc_risk_report.pdf",
                    "application/pdf",
                    key="dl_pdf",
                )

            st.markdown("---")
            st.markdown("##### 📋 Unified Full Report")
            st.caption(
                "Combines everything: risk register entries, vulnerability scanner findings, "
                "SOC 2 readiness checklist, and SOC alert triage - in one downloadable document. "
                "Import data in the 🔍 SOC Analysis tab first to include scanner and alert sections."
            )
            uni1, uni2 = st.columns(2)
            with uni1:
                unified_txt = generate_txt_unified(
                    fdf,
                    st.session_state.get("scanner_findings"),
                    st.session_state.get("alert_findings"),
                    st.session_state.get("soc2_state", {}),
                )
                st.download_button(
                    "📄 Unified Report (Text)",
                    unified_txt.encode("utf-8"),
                    "grc_unified_report.txt",
                    "text/plain",
                    key="dl_unified_txt",
                )
            with uni2:
                uni_pdf_path = generate_pdf_unified(
                    fdf,
                    st.session_state.get("scanner_findings"),
                    st.session_state.get("alert_findings"),
                    st.session_state.get("soc2_state", {}),
                )
                with open(uni_pdf_path, "rb") as upf:
                    _uni_pdf_bytes = upf.read()
                st.download_button(
                    "🧾 Unified Report (PDF)",
                    _uni_pdf_bytes,
                    "grc_unified_report.pdf",
                    "application/pdf",
                    key="dl_unified_pdf",
                )

            # ── EXECUTIVE SUMMARY ONE-PAGER ──────────────────────
            st.markdown("---")
            st.markdown("""
            <div style="background:linear-gradient(135deg,#0F172A,#1E3A5F);border-radius:12px;
                        padding:20px 24px;margin-bottom:16px;">
              <div style="font-size:1.1rem;font-weight:800;color:white;margin-bottom:6px;">
                📊 Executive Summary - Board-Ready One-Pager
              </div>
              <div style="font-size:0.85rem;color:#93C5FD;line-height:1.6;">
                A single-page PDF showing your overall security posture score,
                top risks, framework readiness, and recommended actions.
                Designed to hand to your board, a customer's procurement team,
                or a potential investor - no technical knowledge required to read it.
              </div>
            </div>
            """, unsafe_allow_html=True)
            exec_pdf_path = generate_executive_summary_pdf(
                fdf,
                st.session_state.get("soc2_state", {}),
                st.session_state.get("scanner_findings"),
                st.session_state.get("alert_findings"),
            )
            with open(exec_pdf_path, "rb") as epf:
                _exec_pdf_bytes = epf.read()
            st.download_button(
                "📊 Download Executive Summary (1-page PDF)",
                _exec_pdf_bytes,
                "grc_executive_summary.pdf",
                "application/pdf",
                type="primary",
                use_container_width=True,
                key="dl_exec_pdf",
            )

            if role_info["can_clear"]:
                st.markdown("---")
                if st.button("🗑️ Clear Risk Register", type="secondary"):
                    cleanup_temp_files()
                    st.session_state.history = []
                    st.session_state.last_result = None
                    st.rerun()
            else:
                st.caption("Risk register can only be cleared by an Admin.")


# ══════════════════════════════════════════════════════════════
# SECTION 3 - SOC ANALYSIS & SCANNING
# ══════════════════════════════════════════════════════════════
if _show_soc:

    # SOC sub-tabs driven by sidebar tree selection
    _soc_labels = ["🛡️ Scanner Import", "✅ SOC 2 Readiness", "🚨 Alert Import", "📋 All Frameworks"]
    soc_col1, soc_col2, soc_col3, soc_col4 = st.columns(4)
    for _ci, (_cl, _cc) in enumerate(zip(_soc_labels, [soc_col1, soc_col2, soc_col3, soc_col4])):
        with _cc:
            if st.button(_cl, key=f"soc_sub_{_ci}", use_container_width=True,
                         type="primary" if _soc_tab == _ci else "secondary"):
                st.session_state.soc_active_tab = _ci
                st.rerun()
    st.markdown("---")

    # ── 3.1 VULNERABILITY SCANNER IMPORT ─────────────────────
    if _soc_tab == 0:
        st.markdown("#### 🛡️ Vulnerability Scanner Import")
        st.markdown("""
        <div style="background:linear-gradient(135deg,#EFF6FF,#DBEAFE);border:1px solid #BFDBFE;
                    border-radius:10px;padding:16px 20px;margin-bottom:16px;">
          <div style="font-weight:700;color:#1E40AF;margin-bottom:6px;">How it works</div>
          <div style="color:#1E3A5F;font-size:0.88rem;line-height:1.7;">
            1. Export a CSV from your vulnerability scanner (Nessus or Qualys)<br>
            2. Upload it below - the platform automatically maps every finding to an asset,
               threat, and risk score<br>
            3. Review the preview - then click <strong>Save All to Register</strong><br>
            4. Every finding is included in your PDF report with framework mappings and recommended actions
          </div>
        </div>
        """, unsafe_allow_html=True)

        scan_file = st.file_uploader(
            "Upload your scanner export (.csv)",
            type=["csv"], key="scanner_upload",
            help="Nessus: File → Export → CSV. Qualys: Vulnerabilities → Download → CSV."
        )

        if scan_file is not None:
            try:
                scan_df = parse_scanner_csv(scan_file)
            except Exception as e:
                st.error(f"Could not read this file: {e}")
                scan_df = pd.DataFrame()

            if not scan_df.empty:
                st.session_state.scanner_findings = scan_df
                render_soc_preview_and_save(scan_df, "Finding", "Vulnerability Scanner", "scanner_saved")
            else:
                st.warning("No findings could be parsed. Make sure it's a Nessus or Qualys CSV export.")
        else:
            # Show sample of what output looks like
            with st.expander("📄 What does the output look like?"):
                st.markdown("""
                After uploading, you'll see a table like this for each finding:

                | # | Finding | Severity | Asset | Threat | Risk Score | Level | Action |
                |---|---------|----------|-------|--------|------------|-------|--------|
                | 1 | SQL Injection in MySQL | Critical | Database | Data Breach | 24/25 | CRITICAL | Mitigate |
                | 2 | Default Password Found | High | Network | Misconfiguration | 18/25 | HIGH | Mitigate |
                | 3 | Outdated TLS | Medium | Application | Zero-Day Exploit | 9/25 | MEDIUM | Mitigate |

                Every row is auto-scored using the two-stage model from the published research paper.
                """)

            with st.expander("ℹ️ Supported file formats"):
                st.markdown("""
                **Nessus CSV** - columns: `Name`, `Risk`, `CVSS`, `Host`, `CVE`, `Description`

                **Qualys CSV** - columns: `Title`, `Severity`, `IP Address`, `CVSS Base Score`, `Synopsis`

                Not sure if your file will work? [Download a demo file](/demo_nessus_scanner.csv) and try it first.
                """)

    # ── 3.2 SOC 2 READINESS TRACKING ──────────────────────────
    if _soc_tab == 1:
        st.markdown("#### SOC 2 Readiness Tracking")
        st.caption(
            "Track evidence against the AICPA Trust Services Criteria. This is "
            "a self-assessment aid, not a substitute for a licensed auditor's "
            "examination."
        )

        if "soc2_state" not in st.session_state:
            st.session_state.soc2_state = {}

        selected_categories = st.multiselect(
            "Trust Services Criteria in scope for this engagement",
            SOC2_CATEGORIES,
            default=["Security"],
            key="soc2_categories",
        )

        all_controls: dict[str, bool] = {}
        for cat in selected_categories:
            st.markdown(f"**{cat}**")
            for control in SOC2_CONTROLS.get(cat, []):
                key = f"soc2__{cat}__{control}"
                checked = st.checkbox(
                    control,
                    value=st.session_state.soc2_state.get(key, False),
                    key=key,
                )
                st.session_state.soc2_state[key] = checked
                all_controls[f"{cat}: {control}"] = checked
            st.markdown("")

        if all_controls:
            pct, band = soc2_readiness_score(all_controls)
            st.markdown("---")
            rc1, rc2 = st.columns([1, 2])
            with rc1:
                st.metric("Overall Readiness", f"{pct}%", band)
            with rc2:
                st.progress(pct / 100)
                missing = [c for c, v in all_controls.items() if not v]
                if missing:
                    with st.expander(f"⚠️ {len(missing)} control(s) without evidence"):
                        for m in missing:
                            st.write(f"- {m}")
                else:
                    st.success("All selected controls are marked as evidenced.")

            csv_lines = ["Category / Control,Evidenced"]
            for c, v in all_controls.items():
                csv_lines.append(f'"{c}",{"Yes" if v else "No"}')
            st.download_button(
                "📥 Download Readiness Checklist (CSV)",
                "\n".join(csv_lines),
                "soc2_readiness_checklist.csv",
                "text/csv",
                key="dl_soc2_csv",
            )
        else:
            st.info("Select at least one Trust Services Criteria category above to begin.")

    # ── 3.3 SOC ALERT BATCH IMPORT ────────────────────────────
    if _soc_tab == 2:
        st.markdown("#### 🚨 SOC Alert Batch Import")
        st.markdown("""
        <div style="background:linear-gradient(135deg,#FFF7ED,#FEF3C7);border:1px solid #FDE68A;
                    border-radius:10px;padding:16px 20px;margin-bottom:16px;">
          <div style="font-weight:700;color:#92400E;margin-bottom:6px;">How it works</div>
          <div style="color:#78350F;font-size:0.88rem;line-height:1.7;">
            1. Export a CSV of security alerts from your SIEM or ticketing system<br>
            2. Upload it below - the platform auto-maps each alert to an asset, threat, and risk score<br>
            3. Review the preview - then click <strong>Save All to Register</strong><br>
            4. All alerts appear in your PDF report with recommended actions and framework mappings
          </div>
          <div style="margin-top:10px;font-size:0.8rem;color:#92400E;font-style:italic;">
            Note: this is a batch import of already-triaged alerts, not live log monitoring.
          </div>
        </div>
        """, unsafe_allow_html=True)

        alert_file = st.file_uploader(
            "Upload your alert export (.csv)",
            type=["csv"], key="alert_upload",
            help="Export from your SIEM (Splunk, Sentinel, etc.) or ticketing system as CSV."
        )

        if alert_file is not None:
            try:
                alert_df = parse_alert_csv(alert_file)
            except Exception as e:
                st.error(f"Could not read this file: {e}")
                alert_df = pd.DataFrame()

            if not alert_df.empty:
                st.session_state.alert_findings = alert_df
                render_soc_preview_and_save(alert_df, "Alert", "SOC Alert Import", "alerts_saved")
            else:
                st.warning("No alerts could be parsed. Check the column headers match the format below.")
        else:
            with st.expander("ℹ️ Supported file format"):
                st.markdown("""
                Your CSV should have columns for:
                - **Alert name** - `Alert`, `Alert Name`, `Title`, `Rule Name`, or `Signature`
                - **Severity** - `Severity` or `Priority` with values: Critical / High / Medium / Low
                - **Source** - `Host`, `Source`, `Src_IP`, or `Device`
                - **Description** - `Description`, `Details`, or `Summary` (optional but helps with mapping)

                Column names are case-insensitive and common aliases are supported.
                """)

    # ── 3.4 ALL FRAMEWORKS READINESS ─────────────────────────
    if _soc_tab == 3:
        st.markdown("#### All Frameworks Readiness")
        st.caption(
            "Track your compliance readiness across all frameworks in one place. "
            "Select the frameworks that apply to your business. "
            "The SOC 2 tab has more detail on SOC 2 specifically."
        )

        # Framework selector - default to wizard choices
        default_fw = [f for f in st.session_state.get("wizard_frameworks", ["SOC 2"])
                      if f in ALL_FRAMEWORK_CHECKLISTS]
        if not default_fw:
            default_fw = ["SOC 2"]

        selected_fw = st.multiselect(
            "Frameworks in scope for your business",
            list(ALL_FRAMEWORK_CHECKLISTS.keys()),
            default=default_fw,
            key="all_fw_selected",
        )

        if selected_fw:
            # Show framework descriptions
            fw_desc_cols = st.columns(min(len(selected_fw), 3))
            for i, fw in enumerate(selected_fw):
                with fw_desc_cols[i % len(fw_desc_cols)]:
                    st.info(f"**{fw}**\n\n{FRAMEWORK_DESCRIPTIONS.get(fw,'')}\n\n*{FRAMEWORK_WHO_NEEDS_IT.get(fw,'')}*")

            st.markdown("---")

            # Combined state key
            if "all_fw_state" not in st.session_state:
                st.session_state.all_fw_state = {}

            all_controls_combined: dict[str, bool] = {}

            for fw in selected_fw:
                st.markdown(f"### {fw}")
                fw_controls = ALL_FRAMEWORK_CHECKLISTS.get(fw, {})
                fw_done = 0
                fw_total = 0
                for cat, ctrls in fw_controls.items():
                    with st.expander(f"**{cat}**", expanded=False):
                        for ctrl in ctrls:
                            key = f"allfw__{fw}__{cat}__{ctrl}"
                            checked = st.checkbox(
                                ctrl,
                                value=st.session_state.all_fw_state.get(key, False),
                                key=key,
                            )
                            st.session_state.all_fw_state[key] = checked
                            all_controls_combined[f"{fw} - {cat}: {ctrl}"] = checked
                            fw_total += 1
                            if checked:
                                fw_done += 1

                fw_pct = round(100 * fw_done / fw_total) if fw_total else 0
                st.progress(fw_pct / 100, text=f"{fw}: {fw_pct}% ({fw_done}/{fw_total} controls evidenced)")
                st.markdown("")

            # Overall score
            st.markdown("---")
            st.markdown("### Overall Combined Readiness")
            total_all = len(all_controls_combined)
            done_all  = sum(1 for v in all_controls_combined.values() if v)
            pct_all   = round(100 * done_all / total_all) if total_all else 0
            _, band_all = soc2_readiness_score(all_controls_combined)

            oc1, oc2 = st.columns([1, 2])
            with oc1:
                st.metric("Combined Readiness", f"{pct_all}%", band_all)
            with oc2:
                st.progress(pct_all / 100)
                gaps = [c for c, v in all_controls_combined.items() if not v]
                if gaps:
                    with st.expander(f"⚠️ {len(gaps)} control(s) not yet evidenced"):
                        for g in gaps[:30]:
                            st.write(f"- {g}")
                        if len(gaps) > 30:
                            st.caption(f"...and {len(gaps)-30} more. Download the CSV for the full list.")

            # Download full checklist
            csv_lines = ["Framework,Category,Control,Evidenced"]
            for c, v in all_controls_combined.items():
                parts = c.split(" - ", 1)
                fw_part = parts[0] if len(parts) == 2 else ""
                rest = parts[1] if len(parts) == 2 else c
                cat_ctrl = rest.split(": ", 1)
                cat_part  = cat_ctrl[0] if len(cat_ctrl) == 2 else ""
                ctrl_part = cat_ctrl[1] if len(cat_ctrl) == 2 else rest
                csv_lines.append(f'"{fw_part}","{cat_part}","{ctrl_part}","{"Yes" if v else "No"}"')

            st.download_button(
                "📥 Download Full Readiness Checklist (CSV)",
                "\n".join(csv_lines),
                "grc_full_readiness_checklist.csv",
                "text/csv",
                key="dl_all_fw_csv",
            )
        else:
            st.info("Select at least one framework above to begin tracking readiness.")



# ─────────────────────────────────────────────────────────────
# FOOTER
# ─────────────────────────────────────────────────────────────
_footer_fw = " · ".join(st.session_state.get("wizard_frameworks",
    ["NIST CSF 2.0", "ISO 27001", "SOC 2"]))
st.markdown(f"""
<div style="
    background:#0F172A;
    border-radius:12px;
    padding:20px 28px;
    margin-top:32px;
    text-align:center;
    font-family:'Inter',sans-serif;
">
  <div style="font-size:0.95rem;font-weight:700;color:#F1F5F9;margin-bottom:4px;">
    🛡️ Enterprise GRC Risk Intelligence Platform · v3.0
  </div>
  <div style="font-size:0.82rem;color:#93C5FD;margin-bottom:6px;">
    Built by <strong style="color:white;">Saloni Bhosale</strong> ·
    
  </div>
  <div style="font-size:0.75rem;color:#475569;font-family:'JetBrains Mono',monospace;">
    {_footer_fw} · {datetime.now().strftime('%Y-%m-%d')}
  </div>
</div>
""", unsafe_allow_html=True)
