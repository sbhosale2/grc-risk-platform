import random
import streamlit as st
import pandas as pd

# ---------------- PAGE SETUP ----------------
st.set_page_config(
    page_title="GRC Risk Intelligence Platform",
    page_icon="🛡️",
    layout="wide"
)

# ---------------- CUSTOM STYLE ----------------
st.markdown("""
<style>
.block-container {
    padding-top: 1.0rem;
    padding-bottom: 2rem;
}

html, body, [class*="css"] {
    font-family: "Segoe UI", sans-serif;
}

.card {
    background: white;
    padding: 22px;
    border-radius: 18px;
    box-shadow: 0px 6px 16px rgba(0,0,0,0.08);
    text-align: center;
    margin-bottom: 10px;
    border: 1px solid #eef1f5;
}

.section-box {
    background: white;
    padding: 20px;
    border-radius: 16px;
    box-shadow: 0px 6px 16px rgba(0,0,0,0.08);
    margin-top: 10px;
    margin-bottom: 16px;
    border: 1px solid #eef1f5;
}

.sidebar-card {
    background: #f4f8ff;
    padding: 14px;
    border-radius: 14px;
    border: 1px solid #dce7f7;
    margin-bottom: 12px;
}
</style>
""", unsafe_allow_html=True)

# ---------------- SESSION STATE ----------------
if "history" not in st.session_state:
    st.session_state.history = []

if "random_asset" not in st.session_state:
    st.session_state.random_asset = None

if "random_threat" not in st.session_state:
    st.session_state.random_threat = None

# ---------------- OPTIONS ----------------
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
    "Database": [
        "Data Breach", "Unauthorized Access", "Ransomware",
        "Misconfiguration", "Privilege Escalation", "Data Loss"
    ],
    "Application": [
        "Unauthorized Access", "Phishing", "Misconfiguration",
        "Denial of Service (DDoS)", "Zero-Day Exploit"
    ],
    "Cloud Environment": [
        "Misconfiguration", "Data Breach", "Unauthorized Access",
        "Denial of Service (DDoS)", "Zero-Day Exploit",
        "Supply Chain Attack"
    ],
    "Network": [
        "Denial of Service (DDoS)", "Unauthorized Access",
        "Malware", "Misconfiguration"
    ],
    "Endpoint / Laptop": [
        "Malware", "Phishing", "Ransomware",
        "Unauthorized Access", "Data Loss"
    ],
    "Email System": [
        "Phishing", "Data Breach", "Unauthorized Access", "Malware"
    ],
    "User Credentials": [
        "Credential Attack", "Unauthorized Access", "Phishing",
        "Privilege Escalation"
    ],
    "Server": [
        "Malware", "Ransomware", "Privilege Escalation",
        "Unauthorized Access", "Zero-Day Exploit"
    ],
    "API": [
        "API Abuse", "Unauthorized Access",
        "Denial of Service (DDoS)", "Zero-Day Exploit"
    ],
    "Backup System": [
        "Data Loss", "Ransomware", "Unauthorized Access"
    ],
    "Identity / IAM": [
        "Privilege Escalation", "Unauthorized Access", "Credential Attack"
    ],
    "SaaS Platform": [
        "Data Breach", "Unauthorized Access", "Phishing",
        "Supply Chain Attack", "Credential Attack"
    ],
    "Mobile Device": [
        "Malware", "Phishing", "Unauthorized Access", "Data Loss"
    ],
    "Vendor / Third Party": [
        "Supply Chain Attack", "Data Breach", "Unauthorized Access"
    ],
    "HVAC / Building Management System": [
        "Unauthorized Access", "Misconfiguration",
        "Denial of Service (DDoS)", "Insider Threat"
    ],
    "IoT Device": [
        "Unauthorized Access", "Malware",
        "Denial of Service (DDoS)", "Misconfiguration"
    ],
    "OT / Industrial System": [
        "Unauthorized Access", "Malware",
        "Denial of Service (DDoS)", "Insider Threat",
        "Ransomware"
    ],
    "Building Access Control": [
        "Unauthorized Access", "Insider Threat", "Misconfiguration"
    ],
    "Security Camera / CCTV": [
        "Unauthorized Access", "Data Breach", "Misconfiguration"
    ],
    "Finance System": [
        "Data Breach", "Unauthorized Access",
        "Insider Threat", "Data Loss", "Ransomware"
    ],
    "HR System": [
        "Data Breach", "Unauthorized Access", "Insider Threat",
        "Phishing", "Data Loss"
    ],
    "Customer Portal": [
        "Phishing", "API Abuse", "Data Breach",
        "Denial of Service (DDoS)", "Credential Attack"
    ]
}

TIPS = [
    "Strong logging makes Detect and Respond much stronger.",
    "Low-risk items still need owners and review dates.",
    "Backup quality matters most before ransomware happens.",
    "Misconfigurations often create silent, high-impact exposure.",
    "Credential attacks are often stopped by MFA and monitoring.",
    "Third-party risk can become your risk very quickly."
]

FUN_FACTS = [
    "A medium risk ignored for too long can become a high risk.",
    "Good GRC work is often about prioritization, not panic.",
    "Not every risk should be mitigated — some are accepted or transferred.",
    "A good risk register helps teams act, not just document.",
    "Operational systems like HVAC and CCTV can also create cyber risk."
]

# ---------------- HELPER FUNCTIONS ----------------
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

def suggest_treatment(selected_threat: str, score: int) -> tuple[str, str]:
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

def get_treatment_actions(option: str, score: int) -> list[str]:
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

def risk_consequence(selected_threat: str) -> str:
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

# ---------------- SIDEBAR ----------------
st.sidebar.title("🧭 GRC Analyst Console")
st.sidebar.write("Use this workspace to review cyber risk scenarios, treatment suggestions, and supporting clues.")

st.sidebar.markdown('<div class="sidebar-card">', unsafe_allow_html=True)
st.sidebar.markdown("### 🎲 Try Random Scenario")
if st.sidebar.button("Generate Random Risk"):
    st.session_state.random_asset = random.choice(ASSET_OPTIONS)
    temp_asset = st.session_state.random_asset
    st.session_state.random_threat = random.choice(ASSET_THREAT_MAP[temp_asset])
    st.sidebar.success("Random scenario generated.")
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

st.sidebar.markdown('<div class="sidebar-card">', unsafe_allow_html=True)
st.sidebar.markdown("### ✅ Analyst Checklist")
st.sidebar.checkbox("Asset selected", value=True)
st.sidebar.checkbox("Threat reviewed", value=True)
st.sidebar.checkbox("Likelihood scored", value=True)
st.sidebar.checkbox("Impact scored", value=True)
st.sidebar.markdown("</div>", unsafe_allow_html=True)

# ---------------- HEADER ----------------
st.title("🛡️ GRC Risk Intelligence Platform")
st.subheader("NIST CSF 2.0 Aligned Risk Analysis")
st.write("Analyze cyber risks using likelihood, impact, uploaded text clues, business impact, treatment suggestions, and actionable recommendations.")

# ---------------- DOCUMENT UPLOAD ----------------
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

        if sug_asset or sug_threat:
            if sug_asset:
                st.write(f"**Suggested Asset:** {sug_asset}")
            if sug_threat:
                st.write(f"**Suggested Threat:** {sug_threat}")
            if sug_likelihood and sug_impact:
                st.write(f"**Suggested Likelihood:** {sug_likelihood}")
                st.write(f"**Suggested Impact:** {sug_impact}")
            if matched_words:
                st.write(f"**Matched Keywords:** {', '.join(matched_words)}")

            st.caption("These are keyword-based clues to support, not replace, analyst judgment.")

            if st.button("⚡ Apply Suggested Values"):
                if sug_asset and sug_asset in ASSET_OPTIONS:
                    st.session_state.random_asset = sug_asset
                if sug_asset and sug_asset in ASSET_THREAT_MAP:
                    if sug_threat and sug_threat in ASSET_THREAT_MAP[sug_asset]:
                        st.session_state.random_threat = sug_threat
                st.rerun()
        else:
            st.write("No strong risk clues found from the uploaded file.")
            st.caption("Try including more descriptive words such as system names, weak controls, incidents, or threat terms.")

        st.markdown("</div>", unsafe_allow_html=True)

# ---------------- INPUTS ----------------
st.header("🧾 Enter Risk Details")

default_asset = st.session_state.random_asset if st.session_state.random_asset in ASSET_OPTIONS else ASSET_OPTIONS[0]

col1, col2 = st.columns(2)

with col1:
    asset = st.selectbox("Select Asset", ASSET_OPTIONS, index=ASSET_OPTIONS.index(default_asset))

relevant_threats = ASSET_THREAT_MAP.get(asset, THREAT_OPTIONS)

default_threat = st.session_state.random_threat if st.session_state.random_threat in relevant_threats else relevant_threats[0]

with col2:
    threat = st.selectbox("Select Threat (Filtered by Asset)", relevant_threats, index=relevant_threats.index(default_threat))

st.caption("Showing threats relevant to the selected asset using GRC-style threat mapping.")

# ---------------- RISK SCORING ----------------
st.header("🎯 Risk Scoring")

col3, col4 = st.columns(2)

default_likelihood = upload_suggestion.get("likelihood", 3) if upload_suggestion else 3
default_impact = upload_suggestion.get("impact", 3) if upload_suggestion else 3

with col3:
    likelihood = st.slider("Likelihood (1–5)", 1, 5, default_likelihood)

with col4:
    impact = st.slider("Impact (1–5)", 1, 5, default_impact)

analyze = st.button("🚀 Analyze Risk")

# ---------------- RESULTS ----------------
if analyze:
    risk_score = likelihood * impact

    if risk_score >= 15:
        risk_level = "HIGH"
        risk_emoji = "🔴"
        risk_color = "red"
        business_impact = "High financial and reputational damage."
        fun_message = "This one needs urgent attention."
        priority = "🔥 Critical Priority"
        personality = "🔥 This risk is screaming for attention!"
    elif risk_score >= 8:
        risk_level = "MEDIUM"
        risk_emoji = "🟡"
        risk_color = "orange"
        business_impact = "Moderate operational impact."
        fun_message = "Worth fixing before it grows into a bigger problem."
        priority = "⚠️ Moderate Priority"
        personality = "⚖️ This one is manageable but should not be ignored."
    else:
        risk_level = "LOW"
        risk_emoji = "🟢"
        risk_color = "green"
        business_impact = "Low impact."
        fun_message = "Not a fire right now, but still worth monitoring."
        priority = "✅ Low Priority"
        personality = "😌 Pretty chill risk, just keep an eye on it."

    nist_mapping = get_nist_mapping(threat)
    recommendations = get_recommendations(threat)
    suggested_treatment, treatment_reason = suggest_treatment(threat, risk_score)

    treatment_options = ["Mitigate", "Avoid", "Accept", "Transfer"]
    default_index = treatment_options.index(suggested_treatment)

    st.header("📊 Results")

    c1, c2, c3 = st.columns(3)

    with c1:
        st.markdown(f"""
        <div class="card">
            <h4>Risk Score</h4>
            <h2>{risk_score}</h2>
        </div>
        """, unsafe_allow_html=True)

    with c2:
        st.markdown(f"""
        <div class="card">
            <h4>Risk Level</h4>
            <h2 style="color:{risk_color};">{risk_emoji} {risk_level}</h2>
        </div>
        """, unsafe_allow_html=True)

    with c3:
        st.markdown(f"""
        <div class="card">
            <h4>Asset</h4>
            <h2>{asset}</h2>
        </div>
        """, unsafe_allow_html=True)

    st.progress(risk_score / 25)

    if risk_level == "HIGH":
        st.error(f"⚠️ {fun_message}")
    elif risk_level == "MEDIUM":
        st.warning(f"⚠️ {fun_message}")
    else:
        st.success(f"✅ {fun_message}")

    st.markdown(f"### {priority}")
    st.markdown(f"**Risk Personality:** {personality}")
    st.markdown(
        f"**Quick Summary:** A **{threat.lower()}** risk against **{asset.lower()}** currently scores "
        f"**{risk_score}/25**, which is **{risk_level.lower()}** risk."
    )

    col5, col6 = st.columns(2)

    with col5:
        st.markdown('<div class="section-box">', unsafe_allow_html=True)
        st.subheader("🧠 NIST Mapping")
        st.write(nist_mapping)
        st.caption("Relevant NIST CSF 2.0 functions for this threat scenario.")
        st.markdown("</div>", unsafe_allow_html=True)

    with col6:
        st.markdown('<div class="section-box">', unsafe_allow_html=True)
        st.subheader("💼 Business Impact")
        st.write(business_impact)
        st.markdown("**🚨 If ignored:**")
        st.write(risk_consequence(threat))
        st.caption("Plain-English view of what this could mean for the organization.")
        st.markdown("</div>", unsafe_allow_html=True)

    st.markdown('<div class="section-box">', unsafe_allow_html=True)
    st.subheader("🛠 Recommendations")
    for rec in recommendations:
        st.write(f"- {rec}")
    st.markdown("</div>", unsafe_allow_html=True)

    st.markdown('<div class="section-box">', unsafe_allow_html=True)
    st.subheader("🛡️ Recommended Risk Treatment")
    st.info(f"💡 Suggested Treatment Strategy: {suggested_treatment}")
    st.write(treatment_reason)

    final_treatment = st.selectbox(
        "Change treatment if needed",
        treatment_options,
        index=default_index
    )

    st.write(f"**Final Selected Treatment:** {final_treatment}")
    st.write("**Suggested Next Steps:**")
    for action in get_treatment_actions(final_treatment, risk_score):
        st.write(f"- {action}")
    st.markdown("</div>", unsafe_allow_html=True)

    st.markdown('<div class="section-box">', unsafe_allow_html=True)
    st.subheader("🎮 What if the risk changes over time?")
    sim_likelihood = st.slider("Simulated Likelihood", 1, 5, likelihood, key="sim_l")
    sim_impact = st.slider("Simulated Impact", 1, 5, impact, key="sim_i")
    sim_score = sim_likelihood * sim_impact
    st.write(f"🔮 Simulated Risk Score: **{sim_score}**")
    st.markdown("</div>", unsafe_allow_html=True)

    with st.expander("🎉 Why did I get this result?"):
        st.write(f"- Likelihood = **{likelihood}**")
        st.write(f"- Impact = **{impact}**")
        st.write(f"- Risk Score = **{likelihood} × {impact} = {risk_score}**")
        st.write(f"- This puts the result in the **{risk_level}** category.")
        st.write("- The treatment suggestion is based on simplified educational risk logic.")
        if upload_suggestion:
            st.write("- Uploaded file suggestions were treated as clues, not final analyst conclusions.")
        st.write("- Threat selection is filtered by asset type to make the assessment more realistic.")

    st.session_state.history.append({
        "Asset": asset,
        "Threat": threat,
        "Likelihood": likelihood,
        "Impact": impact,
        "Risk Score": risk_score,
        "Risk Level": risk_level,
        "Suggested Treatment": suggested_treatment,
        "Final Treatment": final_treatment
    })

# ---------------- HISTORY ----------------
st.header("📊 Risk History")

if st.session_state.history:
    df = pd.DataFrame(st.session_state.history)
    st.dataframe(df, use_container_width=True)

    m1, m2, m3 = st.columns(3)
    with m1:
        st.metric("Total Analyses", len(df))
    with m2:
        st.metric("Average Risk Score", round(df["Risk Score"].mean(), 1))
    with m3:
        st.metric("Most Recent Treatment", df.iloc[-1]["Final Treatment"])

    if len(df) >= 2:
        st.subheader("📈 Risk Score Distribution")
        st.bar_chart(df["Risk Score"])
    else:
        st.caption("Add more analyses to see trend charts.")

    st.download_button(
        label="📥 Download Risk Report",
        data=df.to_csv(index=False),
        file_name="risk_report.csv",
        mime="text/csv"
    )

    if st.button("🗑️ Clear History"):
        st.session_state.history = []
        st.rerun()
else:
    st.info("No history yet. Run one or more analyses to build your risk history.")

# ---------------- FOOTER ----------------
st.markdown("---")
st.caption("Built by Saloni Bhosale | Educational risk guidance using simulated scenarios aligned with NIST CSF 2.0")