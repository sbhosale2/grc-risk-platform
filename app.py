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
    "Residual risk explains what remains after controls are applied — always document it.",
    "Evidence upload and audit status bring this tool closer to a real GRC audit workflow.",
    "Control effectiveness scoring is subjective — calibrate it against actual test results when possible.",
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
    "NIST CSF 2.0":           "NIST Cybersecurity Framework 2.0 — six functions: Govern, Identify, Protect, Detect, Respond, Recover.",
    "RMF":                    "NIST Risk Management Framework — six steps: Categorize, Select, Implement, Assess, Authorize, Monitor.",
    "ISO 27001":              "International standard for information security management systems (ISMS).",
    "Zero Trust":             "Security model that assumes no implicit trust — verify every user, device, and session explicitly.",
}


# ─────────────────────────────────────────────────────────────
# CSS — CLEAN, PROFESSIONAL, NO UNNECESSARY ANIMATION
# ─────────────────────────────────────────────────────────────
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Sans:wght@300;400;500;600;700&family=IBM+Plex+Mono:wght@400;500&display=swap');

/* ── Base ── */
html, body, [class*="css"] {
    font-family: 'IBM Plex Sans', system-ui, sans-serif;
}
.block-container {
    padding-top: 1rem;
    padding-bottom: 2rem;
    max-width: 1400px;
}

/* ── Header banner ── */
.platform-header {
    background: #0A1628;
    border: 1px solid #1E3A5F;
    border-radius: 10px;
    padding: 24px 28px;
    margin-bottom: 1.5rem;
    display: flex;
    align-items: center;
    gap: 18px;
}
.platform-header-icon {
    font-size: 2.2rem;
    line-height: 1;
}
.platform-header-title {
    color: #F0F6FF !important;
    font-size: 1.55rem !important;
    font-weight: 700 !important;
    letter-spacing: -0.02em;
    margin: 0 !important;
    padding: 0 !important;
}
.platform-header-sub {
    color: #7BA3C8 !important;
    font-size: 0.85rem !important;
    margin: 3px 0 0 0 !important;
    font-family: 'IBM Plex Mono', monospace;
}

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
    border-radius: 8px;
    padding: 16px 18px;
    border-top: 3px solid #2563EB;
}
.kpi-card.critical { border-top-color: #991B1B; }
.kpi-card.high     { border-top-color: #DC2626; }
.kpi-card.medium   { border-top-color: #D97706; }
.kpi-card.low      { border-top-color: #16A34A; }
.kpi-label {
    font-size: 0.72rem;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    color: #64748B;
    margin-bottom: 4px;
    font-family: 'IBM Plex Mono', monospace;
}
.kpi-value {
    font-size: 1.9rem;
    font-weight: 700;
    color: #0F172A;
    line-height: 1.1;
}
.kpi-sub {
    font-size: 0.75rem;
    color: #94A3B8;
    margin-top: 3px;
}

/* ── Section containers ── */
.section-panel {
    background: #F8FAFC;
    border: 1px solid #E2E8F0;
    border-radius: 8px;
    padding: 18px 20px;
    margin-bottom: 14px;
}
.section-title {
    font-size: 0.78rem;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.1em;
    color: #475569;
    margin-bottom: 12px;
    font-family: 'IBM Plex Mono', monospace;
    display: flex;
    align-items: center;
    gap: 6px;
}

/* ── Plain-English box ── */
.summary-box {
    background: #EFF6FF;
    border-left: 4px solid #2563EB;
    border-radius: 0 8px 8px 0;
    padding: 14px 18px;
    margin: 10px 0;
    font-size: 0.95rem;
    line-height: 1.65;
    color: #1E3A5F;
}

/* ── Risk level badges ── */
.badge {
    display: inline-block;
    padding: 3px 10px;
    border-radius: 4px;
    font-size: 0.75rem;
    font-weight: 600;
    letter-spacing: 0.05em;
    font-family: 'IBM Plex Mono', monospace;
}
.badge-critical { background: #FEF2F2; color: #991B1B; border: 1px solid #FECACA; }
.badge-high     { background: #FFF5F5; color: #DC2626; border: 1px solid #FECACA; }
.badge-medium   { background: #FFFBEB; color: #92400E; border: 1px solid #FDE68A; }
.badge-low      { background: #F0FDF4; color: #166534; border: 1px solid #BBF7D0; }

/* ── Onboarding ── */
.onboarding-panel {
    background: #1E3A5F !important;
    border: 1px solid #2563EB;
    border-radius: 8px;
    padding: 18px 22px;
    margin-bottom: 16px;
    color: #E2F0FF !important;
}
.onboarding-panel * {
    color: #E2F0FF !important;
}
.onboarding-panel strong {
    color: #93C5FD !important;
}
.onboarding-panel ol {
    margin: 8px 0 0 20px;
    padding: 0;
    line-height: 1.8;
}

/* ── Sidebar ── */
[data-testid="stSidebar"] {
    background: #0A1628;
}
[data-testid="stSidebar"] * {
    color: #CBD5E1 !important;
}
[data-testid="stSidebar"] .sidebar-section {
    background: #0F2040;
    border: 1px solid #1E3A5F;
    border-radius: 8px;
    padding: 12px 14px;
    margin-bottom: 10px;
}
[data-testid="stSidebar"] h2,
[data-testid="stSidebar"] h3,
[data-testid="stSidebar"] h4 {
    color: #94B8D4 !important;
    font-size: 0.75rem !important;
    text-transform: uppercase;
    letter-spacing: 0.1em;
}
[data-testid="stSidebar"] .status-ok   { background: #052E16; border: 1px solid #166534; color: #86EFAC !important; padding: 6px 10px; border-radius: 6px; margin-bottom: 5px; font-size: 0.82rem; }
[data-testid="stSidebar"] .status-warn { background: #451A03; border: 1px solid #92400E; color: #FDE68A !important; padding: 6px 10px; border-radius: 6px; margin-bottom: 5px; font-size: 0.82rem; }

/* ── Action row buttons ── */
.stButton button {
    font-family: 'IBM Plex Sans', sans-serif !important;
    font-weight: 500 !important;
    border-radius: 6px !important;
    border: 1px solid #CBD5E1 !important;
    transition: background 0.15s, border-color 0.15s !important;
}
.stButton button[kind="primary"] {
    background: #1D4ED8 !important;
    border-color: #1D4ED8 !important;
    color: #FFFFFF !important;
}
.stButton button[kind="primary"]:hover {
    background: #1E40AF !important;
}

/* ── Audit alert ── */
.audit-warn {
    background: #FFF7ED;
    border: 1px solid #FED7AA;
    border-radius: 6px;
    padding: 10px 14px;
    color: #7C2D12;
    font-size: 0.88rem;
}

/* ── Formula strip ── */
.formula-strip {
    background: #0A1628;
    color: #7DD3FC;
    font-family: 'IBM Plex Mono', monospace;
    font-size: 0.82rem;
    padding: 10px 16px;
    border-radius: 6px;
    margin: 8px 0;
    letter-spacing: 0.02em;
}

/* ── Duplicate warning ── */
.dup-warn {
    background: #FFFBEB;
    border: 1px solid #FCD34D;
    border-radius: 6px;
    padding: 10px 14px;
    color: #78350F;
    font-size: 0.88rem;
    margin-top: 8px;
}

/* ── Footer ── */
.platform-footer {
    text-align: center;
    font-size: 0.78rem;
    color: #94A3B8;
    padding: 20px 0 8px 0;
    font-family: 'IBM Plex Mono', monospace;
    border-top: 1px solid #E2E8F0;
    margin-top: 24px;
}

/* ── Slider legend ── */
.slider-legend {
    display: flex;
    flex-wrap: wrap;
    gap: 6px 12px;
    margin-top: 6px;
    padding: 8px 10px;
    background: #F8FAFC;
    border: 1px solid #E2E8F0;
    border-radius: 6px;
    font-family: 'IBM Plex Mono', monospace;
    font-size: 0.72rem;
    color: #475569;
    line-height: 1.5;
}
.slider-legend span { white-space: nowrap; }

/* ── Field help context ── */
.field-note {
    font-size: 0.76rem;
    color: #64748B;
    margin: -4px 0 10px 2px;
    line-height: 1.4;
    font-style: italic;
}

/* ── Responsive ── */
@media (max-width: 900px) {
    .kpi-grid { grid-template-columns: repeat(2, 1fr); }
    .platform-header-title { font-size: 1.2rem !important; }
    .slider-legend { font-size: 0.68rem; gap: 4px 8px; }
}
</style>
""", unsafe_allow_html=True)


# ─────────────────────────────────────────────────────────────
# SESSION STATE
# ─────────────────────────────────────────────────────────────
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
    "_temp_files": [],   # track temp files for cleanup
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
# CORE SCORING
#
# Methodology: aligned with NIST SP 800-30 Rev 1 and ISO 27005:2022
#
# Step 1 — Inherent Risk
#   Impact is weighted by asset criticality before multiplying by likelihood.
#   Asset Value uses a log-like weight so high-criticality assets aren't
#   linearly over-penalised and low-criticality assets aren't ignored.
#
#   Impact_Adjusted = Impact × AV_WEIGHT[Asset_Value]
#   Inherent_Risk   = Likelihood × Impact_Adjusted   → clamped to [1, 25]
#
# Step 2 — Residual Risk
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
    3: 1.00,   # moderate — baseline
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
    if score >= 20: return "Immediate", "Executive escalation required — treat as a critical priority."
    if score >= 13: return "Immediate", "High-priority remediation should begin without delay."
    if score >=  7: return "Planned",   "Address through a planned remediation cycle with a named owner."
    return                 "Monitor",   "Continue monitoring and review periodically — no urgent action required."


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
        "Privilege Escalation":     ["Limit standing admin privileges — use just-in-time access.", "Alert on privilege changes within minutes.", "Patch privilege escalation vulnerabilities on priority schedule."],
        "API Abuse":                ["Authenticate every API request with scoped tokens.", "Apply rate limiting and quota controls per consumer.", "Monitor API usage patterns and alert on anomalies."],
    }
    return m.get(threat, ["Verify every user, device, and session explicitly.", "Apply least privilege throughout.", "Assume breach and design for containment."])


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
        f"Business Impact Analysis — affected process: '{process}'. "
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
        "Zero-Day Exploit":         ["Deploy layered defences — no single point of failure.", "Monitor for anomalous behaviour that may indicate exploitation.", "Segment critical systems to contain blast radius.", "Establish an emergency patch deployment process."],
        "Denial of Service (DDoS)": ["Implement DDoS scrubbing or CDN-based protection.", "Apply rate limiting on all public-facing endpoints.", "Develop and test a failover and recovery plan.", "Monitor traffic anomalies in real time."],
        "Credential Attack":        ["Mandate phishing-resistant MFA (FIDO2/passkeys).", "Monitor and block brute-force and credential-stuffing attempts.", "Enforce a strong password policy with breach-credential checks.", "Disable dormant and stale accounts promptly."],
        "Data Loss":                ["Maintain automated, tested, and versioned backups.", "Restrict bulk-delete operations with approval workflows.", "Use data versioning and soft-delete where available.", "Schedule and document recovery testing quarterly."],
        "Privilege Escalation":     ["Remove standing admin rights — use just-in-time access.", "Deploy a Privileged Access Management (PAM) solution.", "Alert immediately on any privilege-change events.", "Prioritise patching of privilege escalation CVEs."],
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
    return "Accept",          "Low residual risk may be accepted — document rationale and monitor."


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
        maturity = "low control maturity — foundational controls are missing or ineffective"
    elif control_effectiveness == 3:
        maturity = "moderate control maturity — baseline controls exist but are not consistently applied or tested"
    else:
        maturity = "stronger control maturity — controls are in place and demonstrate evidence of effectiveness"
    return (
        f"The {asset.lower()} currently shows {maturity}. "
        f"Strengthening the mapped controls and improving audit evidence quality will directly reduce the residual risk score."
    )


def get_heatmap_summary(likelihood: int, impact: int) -> str:
    raw = likelihood * impact
    zone = "Critical" if raw >= 20 else "High" if raw >= 13 else "Medium" if raw >= 7 else "Low"
    return f"Likelihood {likelihood}/5 × Impact {impact}/5 = {raw}/25 — positioned in the {zone} Zone."


def get_assumptions_limitations() -> list[str]:
    return [
        "This platform is a decision-support tool and does not replace formal audit, legal, or compliance review.",
        "Risk scoring uses a two-stage model (Inherent Risk → Residual Risk) aligned with NIST SP 800-30 Rev 1 and ISO 27005:2022. It does not perform live threat intelligence queries.",
        "Final decisions should be reviewed and approved by security, compliance, IT, and business stakeholders.",
        "Smart Mode AI analysis should be validated for high-impact or regulated environments before acting on it.",
        "Risk scores should be reviewed periodically as threats, assets, controls, regulations, and business context change.",
        "Asset value and control effectiveness ratings are subjective — calibrate them against internal standards and test results.",
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
Analyse the user's description and return ONLY a single valid JSON object — no markdown, no backticks, no preamble.

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
    "Manager": {"can_edit": True,  "can_save": True,  "can_export": True,  "can_clear": False, "description": "Can assess, save, and export — cannot clear the register."},
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
    Native Plotly heatmap — vector-quality at any resolution, matches app design system.
    Returns a go.Figure that renders inline via st.plotly_chart().
    """
    # 5×5 matrix: rows = impact 5→1, cols = likelihood 1→5
    z = [[i * j for j in range(1, 6)] for i in range(5, 0, -1)]
    text = [[str(i * j) for j in range(1, 6)] for i in range(5, 0, -1)]

    # Colour scale: green → yellow → red (matches risk levels)
    colorscale = [
        [0.0,  "#DCFCE7"],  # 1  — Low green
        [0.24, "#86EFAC"],  # 6
        [0.28, "#FEF9C3"],  # 7  — Medium yellow
        [0.52, "#FDE047"],  # 13
        [0.52, "#FEE2E2"],  # 13 — High red
        [0.80, "#FCA5A5"],  # 20
        [0.80, "#991B1B"],  # 20 — Critical dark red
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
    """Kept for PDF export only — not used in UI."""
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
    canvas.drawString(50, 28, f"Confidential — Generated {datetime.now().strftime('%Y-%m-%d %H:%M')} UTC")
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
              "  Stage 1 — Inherent Risk = Likelihood × (Impact × AV_Weight), clamped to [1–25]",
              "  Stage 2 — Residual Risk = Inherent × (1 − CE_Reduction%), rounded to [1–25]",
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
        lines += [f"RISK ENTRY {i+1} — {row.get('Asset','')} / {row.get('Threat','')}",
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
        "Stage 1 — Inherent Risk = Likelihood × (Impact × AV_Weight), clamped to [1–25].",
        "Stage 2 — Residual Risk = Inherent × (1 − CE_Reduction%), rounded to [1–25].",
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
            block.append(Paragraph(f"Entry {i+1}: {row['Asset']} — {row['Threat']}", S["h2"]))
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
) -> dict:
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
# SIDEBAR
# ─────────────────────────────────────────────────────────────
with st.sidebar:
    st.markdown("## 🛡️ GRC Platform")
    st.caption("NIST CSF 2.0 · ISO 27001 · RMF · Zero Trust")
    st.divider()

    # Demo access
    st.markdown('<div class="sidebar-section">', unsafe_allow_html=True)
    st.markdown("#### 👤 Demo Access")
    st.session_state.demo_user = st.text_input("User name", value=st.session_state.demo_user, label_visibility="collapsed")
    st.session_state.demo_role = st.radio(
        "Role", ["Admin", "Manager", "Viewer"],
        index=["Admin", "Manager", "Viewer"].index(st.session_state.demo_role),
        horizontal=True,
    )
    st.caption(get_role_permissions(st.session_state.demo_role)["description"])
    st.info("Demo mode only. Production requires real authentication, MFA, and session management.")
    st.markdown("</div>", unsafe_allow_html=True)

    # Integration health
    st.markdown('<div class="sidebar-section">', unsafe_allow_html=True)
    st.markdown("#### 🩺 Integration Health")
    for name, (status_label, detail) in get_integration_health().items():
        css = "status-ok" if status_label in ("Ready", "Manual Link", "Manual Evidence") else "status-warn"
        st.markdown(f'<div class="{css}"><b>{name}:</b> {status_label}</div>', unsafe_allow_html=True)
        st.caption(detail)
    st.markdown("</div>", unsafe_allow_html=True)

    # Risk mood meter
    st.markdown('<div class="sidebar-section">', unsafe_allow_html=True)
    st.markdown("#### 📊 Register Summary")
    if st.session_state.history:
        avg = sum(r["Residual Risk"] for r in st.session_state.history) / len(st.session_state.history)
        lvl, emoji, _ = risk_level(avg)
        st.write(f"{emoji} Average residual risk: **{round(avg, 1)} / 25** ({lvl})")
        st.write(f"Total risks in register: **{len(st.session_state.history)}**")
    else:
        st.write("No risks saved yet.")
    st.markdown("</div>", unsafe_allow_html=True)

    # Random scenario
    st.markdown('<div class="sidebar-section">', unsafe_allow_html=True)
    st.markdown("#### 🎲 Random Scenario")
    if st.button("Generate random risk scenario", use_container_width=True):
        rand_asset, rand_threat, rand_av, rand_ce = random.choice(DEMO_SCENARIOS)
        st.session_state.selected_asset              = rand_asset
        st.session_state.selected_threat             = rand_threat
        st.session_state.input_mode                  = "manual"
        st.session_state.random_asset_value          = rand_av
        st.session_state.random_control_effectiveness = rand_ce
        st.rerun()
    st.markdown("</div>", unsafe_allow_html=True)

    # Tip
    st.markdown('<div class="sidebar-section">', unsafe_allow_html=True)
    st.markdown("#### 💡 GRC Tip")
    st.write(random.choice(TIPS))
    st.markdown("</div>", unsafe_allow_html=True)


# ─────────────────────────────────────────────────────────────
# HEADER
# ─────────────────────────────────────────────────────────────
st.markdown("""
<div class="platform-header">
  <div class="platform-header-icon">🛡️</div>
  <div>
    <div class="platform-header-title">Enterprise GRC Risk Intelligence Platform</div>
    <div class="platform-header-sub">
      NIST CSF 2.0 · ISO 27001 · RMF · Zero Trust · Evidence Tracking · Audit Workflow
    </div>
  </div>
</div>
""", unsafe_allow_html=True)

role_info = get_role_permissions(st.session_state.demo_role)

# Header KPIs
h1, h2, h3, h4 = st.columns(4)
with h1: st.metric("Demo Role",   st.session_state.demo_role)
with h2: st.metric("Saved Risks", len(st.session_state.history))
with h3:
    if st.session_state.history:
        avg_r = round(sum(r["Residual Risk"] for r in st.session_state.history) / len(st.session_state.history), 1)
        st.metric("Avg Residual Risk", f"{avg_r} / 25")
    else:
        st.metric("Avg Residual Risk", "—")
with h4: st.metric("AI Analysis", get_integration_health()["Smart AI Analysis"][0])

# Onboarding
if st.session_state.show_onboarding:
    st.markdown("""
    <div class="onboarding-panel">
    <strong>Getting started</strong>
    <ol>
      <li>Set your demo role and verify integration health in the sidebar.</li>
      <li>Enter enterprise context — department, owner, and review date.</li>
      <li>Use <em>Smart Mode</em> to describe a risk in plain English, or <em>Analyst Mode</em> to select asset and threat directly.</li>
      <li>Attach evidence and set vulnerability / audit fields.</li>
      <li>Analyse, review results, select a treatment, then save to the Risk Register.</li>
      <li>Export CSV, text, or PDF reports from the Risk Register tab.</li>
    </ol>
    </div>
    """, unsafe_allow_html=True)
    oc1, oc2 = st.columns(2)
    with oc1:
        if st.button("Load demo data", use_container_width=True):
            if not st.session_state.history:
                st.session_state.history.append(build_demo_risk())
                st.success("Demo risk loaded — switch to the Risk Register tab to view it.")
            else:
                st.info("Risk register already contains data.")
    with oc2:
        if st.button("Dismiss guide", use_container_width=True):
            st.session_state.show_onboarding = False
            st.rerun()

st.caption(f"Version 2.0 · Production-grade prototype · Demo mode · {datetime.now().strftime('%Y-%m-%d')}")

# ─────────────────────────────────────────────────────────────
# MAIN TABS
# ─────────────────────────────────────────────────────────────
main_tab, register_tab = st.tabs(["📋 Risk Assessment", "📊 Risk Register & Dashboard"])


# ══════════════════════════════════════════════════════════════
# TAB 1 — RISK ASSESSMENT
# ══════════════════════════════════════════════════════════════
with main_tab:

    if not role_info["can_edit"]:
        st.warning("You are in Viewer mode. Switch to Admin or Manager in the sidebar to create assessments.")

    # Mode selector
    mc1, mc2 = st.columns(2)
    with mc1:
        if st.button(
            "✨ Smart Mode — describe the risk in plain English"
            + (" ✓ active" if st.session_state.input_mode == "smart" else ""),
            use_container_width=True,
        ):
            st.session_state.input_mode = "smart"
            st.rerun()
    with mc2:
        if st.button(
            "⚙️ Analyst Mode — select asset and threat directly"
            + (" ✓ active" if st.session_state.input_mode == "manual" else ""),
            use_container_width=True,
        ):
            st.session_state.input_mode = "manual"
            st.rerun()

    st.markdown("---")

    # ── Enterprise Context ────────────────────────────────────
    st.markdown('<div class="section-title">🏢 Enterprise Context</div>', unsafe_allow_html=True)
    st.caption("Who owns this risk and when should it be reviewed? These fields appear in all exports and reports.")
    ec1, ec2, ec3 = st.columns(3)
    with ec1:
        company  = st.text_input(
            "Company / Business Unit",
            value="Demo Organisation",
            help="The organisation or business unit where this risk exists. Used in report headers.",
        )
        industry = st.selectbox(
            "Industry",
            ["General", "Technology", "Finance", "Healthcare", "Education", "Retail", "Manufacturing"],
            help="Your industry sector. This tailors the Business Impact text — e.g. Healthcare adds patient safety and HIPAA context, Finance adds PCI DSS and fraud context.",
        )
    with ec2:
        department = st.text_input(
            "Department",
            value="Information Technology",
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
                "Open — newly identified, no action taken yet.\n"
                "In Progress — remediation is actively underway.\n"
                "Accepted — risk acknowledged and formally accepted by the owner.\n"
                "Transferred — risk shifted to a third party (e.g. insurer or vendor).\n"
                "Closed — risk is resolved or no longer applicable."
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
    st.caption("Rate the potential business consequences if this risk materialises. These do not affect the risk score — they enrich the report for executives and auditors.")
    bi1, bi2, bi3 = st.columns(3)
    with bi1:
        financial_impact = st.selectbox(
            "Financial Impact",
            ["Low", "Medium", "High", "Critical"],
            index=1,
            help=(
                "Low — minimal financial exposure (e.g. < $10K).\n"
                "Medium — moderate financial loss or recovery cost ($10K–$500K).\n"
                "High — significant financial damage, fines, or litigation (> $500K).\n"
                "Critical — potential for existential financial harm or regulatory penalty."
            ),
        )
    with bi2:
        operational_impact = st.selectbox(
            "Operational Impact",
            ["Low", "Medium", "High", "Critical"],
            index=1,
            help=(
                "Low — minor disruption, business continues normally.\n"
                "Medium — noticeable service degradation or process slowdown.\n"
                "High — significant downtime or inability to deliver key services.\n"
                "Critical — complete operational failure or safety-critical system unavailability."
            ),
        )
    with bi3:
        compliance_impact = st.selectbox(
            "Compliance / Regulatory Impact",
            ["Low", "Medium", "High", "Critical"],
            index=1,
            help=(
                "Low — no regulatory reporting obligation.\n"
                "Medium — internal policy breach requiring documentation.\n"
                "High — reportable breach under GDPR, HIPAA, PCI DSS, or equivalent.\n"
                "Critical — potential licence revocation, criminal liability, or regulatory enforcement."
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
                "1 — Negligible (internal test system, low-value device)\n"
                "2 — Low (departmental tool, non-customer-facing)\n"
                "3 — Moderate (standard business system)\n"
                "4 — High (customer-facing, regulated data)\n"
                "5 — Mission-critical (core infrastructure, financial systems, patient data)"
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
                "1 — Minimal / no controls in place (5% risk reduction)\n"
                "2 — Basic hygiene only — e.g. antivirus, basic firewall (20% reduction)\n"
                "3 — Standard controls, partially tested — e.g. MFA deployed, patching in place (45% reduction)\n"
                "4 — Mature controls, regularly tested — e.g. annual pen test, documented IR plan (70% reduction)\n"
                "5 — Best-in-class, evidenced — e.g. continuous monitoring, zero trust, quarterly red team (90% reduction)"
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

    # ── Vulnerability, Evidence & Audit ──────────────────────
    st.markdown("---")
    st.markdown('<div class="section-title">🧩 Vulnerability, Evidence & Audit Tracking</div>', unsafe_allow_html=True)
    st.caption("Optional but recommended. Link this risk to a specific finding, upload proof, and set audit readiness. These fields are required for audit-ready GRC workflows.")
    va1, va2, va3 = st.columns(3)
    with va1:
        vulnerability_name = st.text_input(
            "Linked Vulnerability / Finding",
            value="",
            placeholder="CVE-2024-XXXX, weak MFA, exposed S3 bucket…",
            help="Reference a specific technical finding that this risk is based on. Examples: a CVE ID from a Nessus scan, a failed control from a pen test, a misconfiguration found in a cloud review.",
        )
        vulnerability_severity = st.selectbox(
            "Vulnerability Severity",
            ["Not Linked", "Low", "Medium", "High", "Critical"],
            help=(
                "Not Linked — no specific vulnerability is attached (risk is threat-based only).\n"
                "Low — CVSS 0.1–3.9 or minor control gap with limited exploitability.\n"
                "Medium — CVSS 4.0–6.9 or control gap requiring user interaction to exploit.\n"
                "High — CVSS 7.0–8.9 or significant control gap exploitable remotely.\n"
                "Critical — CVSS 9.0–10.0 or critical control gap with active exploitation in the wild."
            ),
        )
    with va2:
        vulnerability_source = st.selectbox(
            "Finding Source",
            ["Manual Assessment", "Nessus", "Splunk", "SIEM", "EDR",
             "Cloud Security Tool", "Penetration Test", "Audit Finding", "Other"],
            help=(
                "Where was this finding identified?\n\n"
                "Manual Assessment — analyst judgement or workshop.\n"
                "Nessus — vulnerability scanner output (link Plugin ID above).\n"
                "Splunk — SIEM alert or log search result.\n"
                "SIEM — generic security information and event management alert.\n"
                "EDR — endpoint detection and response alert.\n"
                "Cloud Security Tool — CSPM output (e.g. AWS Security Hub, Defender for Cloud).\n"
                "Penetration Test — formal pen test or red team finding.\n"
                "Audit Finding — internal or external audit observation."
            ),
        )
        audit_status = st.selectbox(
            "Audit Status",
            ["Evidence Missing", "Needs Review", "Remediation In Progress", "Audit Ready"],
            help=(
                "Evidence Missing — no supporting evidence exists yet. Action required before audit.\n"
                "Needs Review — evidence has been uploaded but not yet validated by control owner or auditor.\n"
                "Remediation In Progress — risk is being actively fixed; document progress and target date.\n"
                "Audit Ready — evidence is complete, current, and owned. Ready for auditor review."
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

    with st.expander("🔌 Integration Notes — Nessus / Splunk"):
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
        st.header("📊 Risk Assessment Results")

        lvl = result["Residual Level"]
        cls = level_css_class(lvl)

        # KPI row
        k1, k2, k3, k4 = st.columns(4)
        with k1:
            st.markdown(f"""
            <div class="kpi-card {cls}">
              <div class="kpi-label">Inherent Risk</div>
              <div class="kpi-value">{result['Inherent Risk']}</div>
              <div class="kpi-sub">Pre-control exposure (1–25)</div>
            </div>""", unsafe_allow_html=True)
        with k2:
            st.markdown(f"""
            <div class="kpi-card {cls}">
              <div class="kpi-label">Residual Risk</div>
              <div class="kpi-value">{result['Residual Risk']}<span style="font-size:1rem;color:#64748B"> / 25</span></div>
              <div class="kpi-sub">After control effectiveness</div>
            </div>""", unsafe_allow_html=True)
        with k3:
            st.markdown(f"""
            <div class="kpi-card {cls}">
              <div class="kpi-label">Risk Level</div>
              <div class="kpi-value">{result['Residual Emoji']} {result['Residual Level']}</div>
              <div class="kpi-sub">Normalised to 1–25 scale</div>
            </div>""", unsafe_allow_html=True)
        with k4:
            st.markdown(f"""
            <div class="kpi-card">
              <div class="kpi-label">Priority</div>
              <div class="kpi-value" style="font-size:1.4rem">{result['Priority']}</div>
              <div class="kpi-sub">{result['Priority Rationale'][:55]}…</div>
            </div>""", unsafe_allow_html=True)

        # Alert banner
        if lvl == "CRITICAL":
            st.error("🔴 CRITICAL — Requires immediate executive escalation and a formal remediation plan.")
        elif lvl == "HIGH":
            st.error("🔴 HIGH — Prioritise remediation. Assign an owner and target date immediately.")
        elif lvl == "MEDIUM":
            st.warning("🟡 MEDIUM — Address within the next planned remediation cycle.")
        else:
            st.success("🟢 LOW — Manageable. Continue monitoring and review at the next scheduled date.")

        # Plain-English summary
        if result.get("Plain English Summary"):
            st.markdown(f"""
            <div class="summary-box">
              <strong>Plain-English Summary</strong><br>
              {result['Plain English Summary']}
            </div>""", unsafe_allow_html=True)

        # AI actions
        if result.get("AI Actions"):
            action_cols = st.columns(len(result["AI Actions"]))
            for i, action in enumerate(result["AI Actions"]):
                with action_cols[i]:
                    st.info(f"**{action['tag']}:** {action['text']}")

        st.markdown("---")

        # Business Impact
        st.subheader("💼 Business Impact")
        st.write(result["Business Impact"])

        # Priority
        st.subheader("🚦 Priority & Treatment")
        pc1, pc2 = st.columns(2)
        with pc1:
            st.info(f"**Priority:** {result['Priority']} — {result['Priority Rationale']}")
        with pc2:
            st.info(f"**Suggested Treatment:** {result['Final Treatment']} — {result['Treatment Reason']}")

        # Maturity
        st.subheader("📈 Control Maturity Insight")
        st.write(result["Maturity Hint"])

        # Vulnerability & Audit
        st.subheader("🧩 Vulnerability, Evidence & Audit")
        vac1, vac2 = st.columns(2)
        with vac1:
            st.write(f"**Finding:** {result['Vulnerability / Finding']}")
            st.write(f"**Severity:** {result['Vulnerability Severity']}")
            st.write(f"**Source:** {result['Finding Source']}")
        with vac2:
            st.write(f"**Evidence File:** {result['Evidence File']}")
            st.write(f"**Evidence Owner:** {result['Evidence Owner']}")
            st.write(f"**Audit Status:** {result['Audit Status']}")
        if result["Audit Status"] in ("Evidence Missing", "Needs Review"):
            st.markdown(f'<div class="audit-warn">⚠️ {result["Audit Recommendation"]}</div>', unsafe_allow_html=True)
        else:
            st.info(result["Audit Recommendation"])

        # Recommended controls
        st.subheader("✅ Recommended Controls")
        rc1, rc2 = st.columns(2)
        recs = result["Recommended Controls"].split(" | ")
        for i, rec in enumerate(recs):
            (rc1 if i % 2 == 0 else rc2).write(f"- {rec}")

        # Heatmap — native Plotly, vector quality, matches design system
        st.subheader("🧭 Risk Heatmap")
        hm_col, _ = st.columns([1, 1])
        with hm_col:
            st.plotly_chart(
                create_heatmap_plotly(result["Likelihood"], result["Impact"]),
                use_container_width=True,
                config={"displayModeBar": False},
            )
        st.caption(result.get("Heatmap Summary", ""))
        hm_img_path = create_heatmap_image(result["Likelihood"], result["Impact"])
        with open(hm_img_path, "rb") as hf:
            st.download_button("⬇️ Download Heatmap (PNG)", hf, "risk_heatmap.png", "image/png",
                               key="dl_heatmap_result")

        # Framework mapping
        with st.expander("🧠 Framework & Control Mapping"):
            fm1, fm2, fm3 = st.columns(3)
            with fm1:
                st.write("**NIST CSF 2.0**")
                st.write(result["NIST Mapping"])
            with fm2:
                st.write("**NIST RMF**")
                st.write(result["RMF Mapping"])
            with fm3:
                st.write("**ISO 27001**")
                st.write(result["ISO 27001 Mapping"])
            st.write("**Mapped Controls:**")
            for item in result["Mapped Controls"].split(" | "):
                if item: st.write(f"- {item}")
            st.write("**Zero Trust Guidance:**")
            for item in result["Zero Trust Guidance"].split(" | "):
                if item: st.write(f"- {item}")

        # Treatment plan
        with st.expander("📌 Treatment Plan & Next Steps"):
            for step in result["Next Steps"].split(" | "):
                if step: st.write(f"- {step}")

        # Scoring methodology
        with st.expander("🧮 Scoring Methodology"):
            st.markdown('<div class="formula-strip">Inherent Risk = Likelihood × (Impact × AV_Weight)&nbsp;|&nbsp;Residual Risk = Inherent × (1 − CE_Reduction%) — both on 1–25 scale&nbsp;|&nbsp;NIST SP 800-30 Rev 1 / ISO 27005:2022</div>', unsafe_allow_html=True)
            mc1, mc2, mc3, mc4 = st.columns(4)
            mc1.metric("Likelihood",           f"{result['Likelihood']} / 5")
            mc2.metric("Impact",               f"{result['Impact']} / 5")
            mc3.metric("Asset Value",          f"{result['Asset Value']} / 5")
            mc4.metric("Control Effectiveness",f"{result['Control Effectiveness']} / 5")
            st.write(f"Inherent Risk: **{result['Inherent Risk']}** / 25 | Residual Risk: **{result['Residual Risk']}** / 25")
            st.write(f"Confidence: **{result['Confidence']}**")
            for note in result["Scoring Notes"].split(" | "):
                if note: st.caption(note)

        # Assumptions
        with st.expander("⚠️ Assumptions & Limitations"):
            for item in get_assumptions_limitations():
                st.write(f"- {item}")

        st.markdown("---")

        # Treatment decision + save
        st.subheader("🛡️ Final Risk Treatment Decision")
        st.caption("The platform has suggested a treatment based on the residual risk score. Override it here if your business context requires a different approach.")
        treat_opts = ["Mitigate", "Accept", "Transfer", "Avoid"]
        selected_treatment = st.selectbox(
            "Treatment Decision",
            treat_opts,
            index=treat_opts.index(result.get("Final Treatment", "Mitigate")),
            help=(
                "Mitigate — implement or improve controls to reduce the risk. Recommended for Critical and High risks.\n\n"
                "Accept — formally acknowledge the risk without further action. Only appropriate for Low risks "
                "or where mitigation cost exceeds potential loss. Requires sign-off from the risk owner.\n\n"
                "Transfer — shift financial exposure to a third party via cyber insurance, vendor contract, or SLA. "
                "Residual risk remains — transfer does not eliminate the threat.\n\n"
                "Avoid — cease the activity that creates the risk. Only feasible when the risky activity is "
                "non-essential or can be redesigned to eliminate exposure entirely."
            ),
        )
        result["Final Treatment"] = selected_treatment

        # Duplicate check
        is_duplicate = check_for_duplicate(result["Asset"], result["Threat"])
        if is_duplicate:
            st.markdown(
                f'<div class="dup-warn">⚠️ A risk entry for <strong>{result["Asset"]}</strong> / '
                f'<strong>{result["Threat"]}</strong> already exists in the register. '
                f'Saving again will add a second entry.</div>',
                unsafe_allow_html=True,
            )

        if st.button("💾 Save to Risk Register", type="primary", disabled=not role_info["can_save"]):
            st.session_state.history.append(result.copy())
            n = len(st.session_state.history)
            level_saved = result["Residual Level"]
            color_map_save = {"CRITICAL": "#991B1B", "HIGH": "#DC2626", "MEDIUM": "#D97706", "LOW": "#16A34A"}
            accent = color_map_save.get(level_saved, "#1D4ED8")
            st.markdown(f"""
            <div style="background:{accent}10; border:1px solid {accent}40; border-left:4px solid {accent};
                        border-radius:6px; padding:12px 16px; margin-top:8px;">
              <span style="font-weight:600; color:{accent};">✓ Risk saved to register</span>
              <span style="color:#475569; font-size:0.88rem; margin-left:12px;">
                {result['Asset']} / {result['Threat']} · {level_saved} · Entry #{n}
              </span>
            </div>
            """, unsafe_allow_html=True)

        st.markdown("---")
        st.subheader("📖 Glossary")
        for term, defn in GLOSSARY.items():
            with st.expander(term):
                st.write(defn)


# ══════════════════════════════════════════════════════════════
# TAB 2 — RISK REGISTER & DASHBOARD
# ══════════════════════════════════════════════════════════════
with register_tab:
    st.header("📊 Risk Register & Dashboard")

    if not st.session_state.history:
        st.info("No risks saved yet. Use the Risk Assessment tab to create and save risk entries, or load demo data below.")
        if st.button("Load demo data", use_container_width=True, key="load_demo_register"):
            st.session_state.history.append(build_demo_risk())
            st.rerun()
    else:
        df = pd.DataFrame(st.session_state.history)
        st.info("Filter and review saved risks, visualise the register, and export reports.")

        # Filters
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

        # Dashboard KPIs
        dk1, dk2, dk3, dk4 = st.columns(4)
        with dk1: st.metric("Filtered Risks",        len(fdf))
        with dk2: st.metric("Avg Residual Risk",      f"{round(fdf['Residual Risk'].mean(), 1) if not fdf.empty else 0} / 25")
        with dk3: st.metric("Max Residual Risk",      int(fdf["Residual Risk"].max())  if not fdf.empty else 0)
        with dk4: st.metric("Open Risks",             int((fdf["Status"] != "Closed").sum()) if not fdf.empty else 0)

        # Register table
        st.subheader("Risk Register")
        display_cols = [
            "Asset", "Threat", "Inherent Risk", "Residual Level", "Residual Risk", "Priority",
            "Final Treatment", "Status", "Risk Owner", "Review Date",
            "Audit Status", "Vulnerability / Finding",
        ]
        st.dataframe(
            fdf[[c for c in display_cols if c in fdf.columns]].head(max_rows),
            use_container_width=True,
            height=340,
        )

        # Charts — Plotly, fixed height, no scroll, full view
        st.subheader("Visual Dashboard")
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

        # Residual risk trend — horizontal bar for readability at any count
        risk_trend = fdf[["Asset", "Threat", "Residual Risk", "Residual Level"]].copy().reset_index(drop=True)
        risk_trend["Label"] = risk_trend["Asset"] + " / " + risk_trend["Threat"]
        fig_trend = go.Figure(go.Bar(
            y=risk_trend["Label"],
            x=risk_trend["Residual Risk"],
            orientation="h",
            marker_color=[color_map.get(l, "#2563EB") for l in risk_trend["Residual Level"]],
            text=risk_trend["Residual Risk"],
            textposition="outside",
        ))
        row_height = max(320, len(risk_trend) * 38)
        fig_trend.update_layout(
            title="Residual Risk Score per Entry (1–25)",
            height=min(row_height, 600),
            margin=dict(l=20, r=60, t=40, b=20),
            plot_bgcolor="#F8FAFC", paper_bgcolor="#F8FAFC",
            xaxis=dict(fixedrange=True, range=[0, 27], showgrid=True, gridcolor="#E2E8F0"),
            yaxis=dict(fixedrange=True, automargin=True),
            font=dict(family="IBM Plex Sans, sans-serif", size=11),
        )
        st.plotly_chart(fig_trend, use_container_width=True, config={"displayModeBar": False})

        # Export
        st.subheader("Export Reports")
        st.caption("All exports include assumptions, limitations, framework mappings, heatmap context, and audit tracking fields.")

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
                st.download_button(
                    "🧾 Download PDF Report",
                    pf,
                    "grc_risk_report.pdf",
                    "application/pdf",
                    key="dl_pdf",
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


# ─────────────────────────────────────────────────────────────
# FOOTER
# ─────────────────────────────────────────────────────────────
st.markdown(f"""
<div class="platform-footer">
  Enterprise GRC Risk Intelligence Platform · v2.0<br>
  Saloni Bhosale<br>
  NIST CSF 2.0 &nbsp;·&nbsp; ISO 27001 &nbsp;·&nbsp; NIST RMF &nbsp;·&nbsp; Zero Trust &nbsp;·&nbsp; Evidence Tracking &nbsp;·&nbsp; Audit Workflow<br>
  {datetime.now().strftime('%Y-%m-%d %H:%M UTC')}
</div>
""", unsafe_allow_html=True)
