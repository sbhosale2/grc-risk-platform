import random
import streamlit as st
import pandas as pd

# ---------------- PAGE CONFIG ----------------
st.set_page_config(
    page_title="AI-Enhanced GRC Risk Intelligence Platform",
    page_icon="🛡️",
    layout="wide"
)

# ---------------- CSS ----------------
st.markdown("""
<style>
.block-container {
    padding-top: 1rem;
}

/* CARDS */
.card {
    background: white;
    padding: 22px;
    border-radius: 18px;
    box-shadow: 0px 6px 16px rgba(0,0,0,0.08);
    text-align: center;
    border: 1px solid #eef1f5;
    color: #111111 !important;
}
.card h2 {
    color: #111111 !important;
}
.card h4 {
    color: #555555 !important;
}

/* SECTIONS */
.section-box {
    background: white;
    padding: 20px;
    border-radius: 16px;
    box-shadow: 0px 6px 16px rgba(0,0,0,0.08);
    margin-top: 10px;
    border: 1px solid #eef1f5;
}

/* SIDEBAR */
.sidebar-card {
    background: #f4f8ff;
    padding: 12px;
    border-radius: 12px;
    margin-bottom: 12px;
}
</style>
""", unsafe_allow_html=True)

# ---------------- DATA ----------------
ASSETS = {
    "Database": ["Data Breach", "Unauthorized Access", "Ransomware"],
    "API": ["API Abuse", "Unauthorized Access", "DDoS"],
    "User Credentials": ["Credential Attack", "Phishing", "Privilege Escalation"],
    "HVAC": ["Unauthorized Access", "Misconfiguration", "DDoS"],
    "Application": ["XSS", "Injection Attack", "Misconfiguration"],
}

RECOMMENDATIONS = {
    "Data Breach": ["Encrypt data", "Use access control", "Enable logging"],
    "API Abuse": ["Rate limiting", "Monitor API calls", "Secure endpoints"],
    "Credential Attack": ["Enable MFA", "Monitor login attempts"],
    "DDoS": ["Traffic filtering", "Use CDN", "Scale infra"],
}

# ---------------- SIDEBAR ----------------
st.sidebar.title("🧭 GRC Panel")

st.sidebar.markdown('<div class="sidebar-card">', unsafe_allow_html=True)
st.sidebar.write("💡 Tip: Try different asset + threat combos")
st.sidebar.markdown("</div>", unsafe_allow_html=True)

st.sidebar.markdown('<div class="sidebar-card">', unsafe_allow_html=True)
st.sidebar.write("🎯 Fun Fact:")
st.sidebar.write(random.choice([
    "Medium risks become high risks if ignored",
    "Logging improves detection massively",
    "Misconfigs cause most breaches"
]))
st.sidebar.markdown("</div>", unsafe_allow_html=True)

# ---------------- HEADER ----------------
st.title("🛡️ GRC Risk Intelligence Platform")
st.subheader("NIST CSF 2.0 Risk Analysis")

# ---------------- INPUT ----------------
col1, col2 = st.columns(2)

with col1:
    asset = st.selectbox("Select Asset", list(ASSETS.keys()))

with col2:
    threat = st.selectbox("Select Threat", ASSETS[asset])

# ---------------- SLIDERS ----------------
col3, col4 = st.columns(2)

with col3:
    likelihood = st.slider("Likelihood", 1, 5, 3)

with col4:
    impact = st.slider("Impact", 1, 5, 3)

# ---------------- ANALYZE ----------------
if st.button("🚀 Analyze Risk"):
    score = likelihood * impact

    if score >= 15:
        level = "HIGH"
        color = "red"
    elif score >= 8:
        level = "MEDIUM"
        color = "orange"
    else:
        level = "LOW"
        color = "green"

    st.header("📊 Results")

    c1, c2, c3 = st.columns(3)

    with c1:
        st.markdown(f"""
        <div class="card">
            <h4>Risk Score</h4>
            <h2>{score}</h2>
        </div>
        """, unsafe_allow_html=True)

    with c2:
        st.markdown(f"""
        <div class="card">
            <h4>Risk Level</h4>
            <h2 style="color:{color};">{level}</h2>
        </div>
        """, unsafe_allow_html=True)

    with c3:
        st.markdown(f"""
        <div class="card">
            <h4>Asset</h4>
            <h2>{asset}</h2>
        </div>
        """, unsafe_allow_html=True)

    st.progress(score / 25)

    # ---------------- DETAILS ----------------
    col5, col6 = st.columns(2)

    with col5:
        st.markdown('<div class="section-box">', unsafe_allow_html=True)
        st.subheader("🧠 NIST Mapping")
        st.write("Identify, Protect, Detect, Respond")
        st.markdown("</div>", unsafe_allow_html=True)

    with col6:
        st.markdown('<div class="section-box">', unsafe_allow_html=True)
        st.subheader("💼 Business Impact")
        st.write("Operational and financial impact possible.")
        st.markdown("</div>", unsafe_allow_html=True)

    # ---------------- RECOMMENDATIONS ----------------
    st.markdown('<div class="section-box">', unsafe_allow_html=True)
    st.subheader("🛠 Recommendations")

    recs = RECOMMENDATIONS.get(threat, ["Review controls", "Monitor risk"])

    for r in recs:
        st.write(f"- {r}")

    st.markdown("</div>", unsafe_allow_html=True)

    # ---------------- TREATMENT ----------------
    st.markdown('<div class="section-box">', unsafe_allow_html=True)
    st.subheader("🛡️ Risk Treatment")

    treatment = st.selectbox("Select Treatment", ["Mitigate", "Accept", "Transfer", "Avoid"])

    st.write(f"Final Decision: **{treatment}**")
    st.markdown("</div>", unsafe_allow_html=True)
