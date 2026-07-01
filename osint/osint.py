import streamlit as st
import json
import pandas as pd
from datetime import datetime
import os

# ─── Page Config ────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="OSINT Intelligence Portal",
    page_icon="🔍",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ─── Custom CSS ─────────────────────────────────────────────────────────────
st.markdown("""
<style>
    /* Dark professional theme */
    .stApp {
        background-color: #0d1117;
        color: #e6edf3;
    }
    
    /* Sidebar */
    [data-testid="stSidebar"] {
        background-color: #161b22;
        border-right: 1px solid #21262d;
    }
    [data-testid="stSidebar"] .stMarkdown h1,
    [data-testid="stSidebar"] .stMarkdown h2,
    [data-testid="stSidebar"] .stMarkdown h3 {
        color: #58a6ff;
    }

    /* Header */
    .portal-header {
        background: linear-gradient(135deg, #1a2332 0%, #0d1117 50%, #1a1a2e 100%);
        border: 1px solid #21262d;
        border-radius: 12px;
        padding: 28px 36px;
        margin-bottom: 24px;
        display: flex;
        align-items: center;
        gap: 16px;
    }
    .portal-title {
        font-size: 2rem;
        font-weight: 700;
        color: #58a6ff;
        margin: 0;
        letter-spacing: -0.5px;
    }
    .portal-subtitle {
        font-size: 0.9rem;
        color: #8b949e;
        margin: 4px 0 0;
    }
    .badge-le {
        background: #1f3a5f;
        border: 1px solid #58a6ff;
        border-radius: 6px;
        padding: 3px 10px;
        font-size: 0.7rem;
        color: #58a6ff;
        font-weight: 600;
        letter-spacing: 1px;
    }

    /* Step pills */
    .step-nav {
        display: flex;
        gap: 8px;
        margin-bottom: 24px;
        flex-wrap: wrap;
    }
    .step-pill {
        padding: 8px 18px;
        border-radius: 20px;
        font-size: 0.82rem;
        font-weight: 600;
        border: 1px solid #30363d;
        background: #161b22;
        color: #8b949e;
        cursor: default;
    }
    .step-pill.active {
        background: #1f6feb;
        border-color: #388bfd;
        color: #ffffff;
    }
    .step-pill.done {
        background: #1a3a2a;
        border-color: #3fb950;
        color: #3fb950;
    }

    /* Tool cards */
    .tool-card {
        background: #161b22;
        border: 1px solid #21262d;
        border-radius: 10px;
        padding: 16px 20px;
        margin-bottom: 12px;
        transition: border-color 0.2s;
    }
    .tool-card:hover {
        border-color: #388bfd;
    }
    .tool-name {
        font-size: 1rem;
        font-weight: 600;
        color: #58a6ff;
        margin-bottom: 4px;
    }
    .tool-desc {
        font-size: 0.82rem;
        color: #8b949e;
        margin-bottom: 10px;
        line-height: 1.5;
    }
    .tool-meta {
        display: flex;
        gap: 8px;
        flex-wrap: wrap;
    }
    .tag {
        padding: 2px 8px;
        border-radius: 12px;
        font-size: 0.72rem;
        font-weight: 500;
    }
    .tag-free { background: #1a3a2a; color: #3fb950; border: 1px solid #3fb950; }
    .tag-freemium { background: #332a1a; color: #e3b341; border: 1px solid #e3b341; }
    .tag-paid { background: #3a1a1a; color: #f85149; border: 1px solid #f85149; }
    .tag-passive { background: #1f2937; color: #60a5fa; border: 1px solid #60a5fa; }
    .tag-active { background: #2a1a1a; color: #fca5a5; border: 1px solid #fca5a5; }
    .tag-reg { background: #2a2a1a; color: #fbbf24; border: 1px solid #fbbf24; }
    .tag-local { background: #1a2a2a; color: #34d399; border: 1px solid #34d399; }

    /* Data input cards */
    .data-card {
        background: #161b22;
        border: 1px solid #21262d;
        border-radius: 10px;
        padding: 20px;
        margin-bottom: 14px;
    }
    .data-card h4 {
        color: #e6edf3;
        font-size: 0.9rem;
        margin-bottom: 4px;
    }

    /* Report section */
    .report-header {
        background: linear-gradient(135deg, #1a2332, #0d1117);
        border: 1px solid #21262d;
        border-radius: 10px;
        padding: 20px 24px;
        margin-bottom: 20px;
    }
    .report-section {
        background: #161b22;
        border: 1px solid #21262d;
        border-left: 3px solid #58a6ff;
        border-radius: 8px;
        padding: 16px 20px;
        margin-bottom: 16px;
    }
    .report-section h4 {
        color: #58a6ff;
        margin-bottom: 10px;
        font-size: 0.9rem;
        text-transform: uppercase;
        letter-spacing: 1px;
    }
    .report-entry {
        border-bottom: 1px solid #21262d;
        padding: 8px 0;
        font-size: 0.85rem;
    }
    .report-entry:last-child { border-bottom: none; }
    .report-label {
        color: #8b949e;
        font-size: 0.75rem;
        text-transform: uppercase;
        letter-spacing: 0.5px;
    }
    .report-value {
        color: #e6edf3;
        margin-top: 2px;
    }

    /* Stats bar */
    .stat-box {
        background: #161b22;
        border: 1px solid #21262d;
        border-radius: 8px;
        padding: 14px 18px;
        text-align: center;
    }
    .stat-num {
        font-size: 1.6rem;
        font-weight: 700;
        color: #58a6ff;
    }
    .stat-label {
        font-size: 0.75rem;
        color: #8b949e;
        margin-top: 2px;
    }

    /* Divider */
    hr { border-color: #21262d; }

    /* Streamlit overrides */
    .stButton > button {
        background-color: #1f6feb;
        color: white;
        border: none;
        border-radius: 6px;
        font-weight: 600;
        padding: 8px 20px;
    }
    .stButton > button:hover {
        background-color: #388bfd;
        border: none;
    }
    .stTextInput > div > div > input,
    .stTextArea > div > div > textarea,
    .stSelectbox > div > div {
        background-color: #161b22;
        border: 1px solid #30363d;
        color: #e6edf3;
        border-radius: 6px;
    }
    .stMultiSelect > div {
        background-color: #161b22;
        border: 1px solid #30363d;
        border-radius: 6px;
    }
    .stCheckbox label { color: #e6edf3; }
    .stRadio label { color: #e6edf3; }
    div[data-testid="stExpander"] {
        background: #161b22;
        border: 1px solid #21262d;
        border-radius: 8px;
    }
    .stDataFrame { background: #161b22; }
    
    /* Category chip */
    .cat-chip {
        display: inline-block;
        background: #1f2937;
        border: 1px solid #374151;
        border-radius: 6px;
        padding: 2px 10px;
        font-size: 0.75rem;
        color: #9ca3af;
        margin-right: 6px;
        margin-bottom: 6px;
    }
    .cat-chip.selected {
        background: #1f3a5f;
        border-color: #58a6ff;
        color: #58a6ff;
        font-weight: 600;
    }

    /* Warning / info boxes */
    .info-box {
        background: #1a2332;
        border: 1px solid #1f6feb;
        border-radius: 8px;
        padding: 12px 16px;
        font-size: 0.84rem;
        color: #93c5fd;
        margin-bottom: 16px;
    }
    .warn-box {
        background: #2a1f0a;
        border: 1px solid #d97706;
        border-radius: 8px;
        padding: 12px 16px;
        font-size: 0.84rem;
        color: #fbbf24;
        margin-bottom: 16px;
    }

    /* Anchor links */
    a { color: #58a6ff !important; text-decoration: none; }
    a:hover { text-decoration: underline; }
</style>
""", unsafe_allow_html=True)


# ─── Load Data ───────────────────────────────────────────────────────────────
@st.cache_data
def load_tools():
    base = os.path.dirname(__file__)
    path = os.path.join(base, "osint_tools.json")
    with open(path) as f:
        tools = json.load(f)
    df = pd.DataFrame(tools)
    df['pricing'] = df['pricing'].fillna('unknown')
    df['opsec'] = df['opsec'].fillna('unknown')
    df['input'] = df['input'].fillna('')
    df['output'] = df['output'].fillna('')
    df['description'] = df['description'].fillna('')
    df['bestFor'] = df['bestFor'].fillna('')
    return df

df_tools = load_tools()
ALL_CATEGORIES = sorted(df_tools['category'].unique().tolist())

# ─── Session State Defaults ───────────────────────────────────────────────────
defaults = {
    "step": 1,
    "selected_data_types": [],
    "tool_results": {},          # category -> list of selected tool names
    "collected_findings": {},    # tool_name -> findings text
    "subject_info": {},          # case metadata
    "report_generated": False,
    "filter_free_only": False,
    "filter_no_reg": False,
    "filter_passive_only": False,
    "search_query": "",
}
for k, v in defaults.items():
    if k not in st.session_state:
        st.session_state[k] = v


# ─── Helper Functions ─────────────────────────────────────────────────────────
def go_to(step):
    st.session_state.step = step
    

def render_pricing_tag(p):
    if p == "free":
        return '<span class="tag tag-free">FREE</span>'
    elif p == "freemium":
        return '<span class="tag tag-freemium">FREEMIUM</span>'
    elif p in ("paid", "commercial"):
        return '<span class="tag tag-paid">PAID</span>'
    return ''

def render_opsec_tag(o):
    if o == "passive":
        return '<span class="tag tag-passive">PASSIVE</span>'
    elif o == "active":
        return '<span class="tag tag-active">ACTIVE</span>'
    return ''

def render_extras(row):
    extra = ""
    if row.get('registration'):
        extra += '<span class="tag tag-reg">REG REQUIRED</span> '
    if row.get('localInstall'):
        extra += '<span class="tag tag-local">LOCAL INSTALL</span> '
    return extra

def tool_card_html(row):
    name_clean = row['name'].replace('(T)', '').replace('(R)', '').replace('(D)', '').replace('(M)', '').strip()
    return f"""
<div class="tool-card">
  <div class="tool-name">🔗 <a href="{row['url']}" target="_blank">{name_clean}</a></div>
  <div class="tool-desc">{row['description'][:200] + '…' if len(str(row['description'])) > 200 else row['description']}</div>
  <div class="tool-meta">
    {render_pricing_tag(row['pricing'])}
    {render_opsec_tag(row['opsec'])}
    {render_extras(row)}
  </div>
  {"<div style='font-size:0.75rem;color:#8b949e;margin-top:8px;'>📥 <b>Input:</b> " + str(row['input']) + "</div>" if row['input'] else ""}
  {"<div style='font-size:0.75rem;color:#8b949e;'>📤 <b>Output:</b> " + str(row['output']) + "</div>" if row['output'] else ""}
</div>
"""

def generate_report_text():
    info = st.session_state.subject_info
    findings = st.session_state.collected_findings
    tools_used = st.session_state.tool_results
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    lines = []
    lines.append("=" * 70)
    lines.append("         LAW ENFORCEMENT OSINT INTELLIGENCE REPORT")
    lines.append("=" * 70)
    lines.append(f"Generated: {now}")
    lines.append(f"Case Number: {info.get('case_number', 'N/A')}")
    lines.append(f"Investigator: {info.get('investigator', 'N/A')}")
    lines.append(f"Agency: {info.get('agency', 'N/A')}")
    lines.append(f"Classification: {info.get('classification', 'UNCLASSIFIED')}")
    lines.append("")
    lines.append("─" * 70)
    lines.append("SUBJECT PROFILE")
    lines.append("─" * 70)
    lines.append(f"Full Name:      {info.get('full_name', 'N/A')}")
    lines.append(f"AKA / Aliases:  {info.get('aliases', 'N/A')}")
    lines.append(f"DOB:            {info.get('dob', 'N/A')}")
    lines.append(f"Known Location: {info.get('location', 'N/A')}")
    lines.append(f"Email:          {info.get('email', 'N/A')}")
    lines.append(f"Phone:          {info.get('phone', 'N/A')}")
    lines.append(f"Username(s):    {info.get('username', 'N/A')}")
    lines.append(f"Vehicle:        {info.get('vehicle', 'N/A')}")
    lines.append(f"IP Address:     {info.get('ip_address', 'N/A')}")
    lines.append(f"Domain(s):      {info.get('domains', 'N/A')}")
    lines.append("")
    lines.append("─" * 70)
    lines.append("INVESTIGATION SCOPE")
    lines.append("─" * 70)
    data_types = st.session_state.selected_data_types
    lines.append(f"Data Categories Investigated: {', '.join(data_types)}")
    lines.append("")

    all_tools_used = []
    for cat, tool_list in tools_used.items():
        all_tools_used.extend(tool_list)
    lines.append(f"Total OSINT Tools Referenced: {len(all_tools_used)}")
    lines.append("")

    lines.append("─" * 70)
    lines.append("FINDINGS BY CATEGORY")
    lines.append("─" * 70)

    for cat in data_types:
        cat_findings = {k: v for k, v in findings.items() if k.startswith(cat + "::") and v.strip()}
        cat_tools = tools_used.get(cat, [])
        if not cat_findings and not cat_tools:
            continue
        lines.append(f"\n[{cat.upper()}]")
        if cat_tools:
            lines.append(f"Tools Used: {', '.join(cat_tools)}")
        for key, val in cat_findings.items():
            tool_name = key.split("::", 1)[1] if "::" in key else key
            lines.append(f"\n  >> {tool_name}:")
            for line in val.strip().split('\n'):
                lines.append(f"     {line}")
        lines.append("")

    lines.append("─" * 70)
    lines.append("ADDITIONAL NOTES")
    lines.append("─" * 70)
    lines.append(info.get('notes', 'None'))
    lines.append("")
    lines.append("─" * 70)
    lines.append("LEGAL DISCLAIMER")
    lines.append("─" * 70)
    lines.append(
        "This report is generated for law enforcement investigative purposes only.\n"
        "All information must be corroborated through official channels before use\n"
        "in legal proceedings. OSINT data is not a substitute for court-admissible\n"
        "evidence. Handle per agency data classification policy."
    )
    lines.append("")
    lines.append("=" * 70)
    lines.append("END OF REPORT")
    lines.append("=" * 70)
    return "\n".join(lines)


# ─── Sidebar ─────────────────────────────────────────────────────────────────
with st.sidebar:
    st.markdown("## 🔍 OSINT Portal")
    st.markdown("<div style='color:#8b949e;font-size:0.8rem;margin-bottom:16px;'>Law Enforcement Intelligence Platform</div>", unsafe_allow_html=True)
    
    st.markdown("---")
    st.markdown("### Navigation")

    step_labels = {
        1: "① Case Setup",
        2: "② Select Data Types",
        3: "③ Find Tools",
        4: "④ Enter Findings",
        5: "⑤ Generate Report",
    }
    for s, label in step_labels.items():
        is_current = st.session_state.step == s
        is_done = st.session_state.step > s
        prefix = "✅ " if is_done else ("▶ " if is_current else "   ")
        color = "#58a6ff" if is_current else ("#3fb950" if is_done else "#8b949e")
        st.markdown(f"<div style='color:{color};font-size:0.9rem;padding:4px 0;'>{prefix}{label}</div>", unsafe_allow_html=True)

    st.markdown("---")
    st.markdown("### Quick Stats")
    col1, col2 = st.columns(2)
    with col1:
        st.markdown(f"<div class='stat-box'><div class='stat-num'>{len(df_tools)}</div><div class='stat-label'>Tools</div></div>", unsafe_allow_html=True)
    with col2:
        st.markdown(f"<div class='stat-box'><div class='stat-num'>{len(ALL_CATEGORIES)}</div><div class='stat-label'>Categories</div></div>", unsafe_allow_html=True)

    st.markdown("---")
    if st.session_state.step > 1:
        st.markdown("### Filters")
        st.session_state.filter_free_only = st.checkbox("Free tools only", value=st.session_state.filter_free_only)
        st.session_state.filter_no_reg = st.checkbox("No registration required", value=st.session_state.filter_no_reg)
        st.session_state.filter_passive_only = st.checkbox("Passive OpSec only", value=st.session_state.filter_passive_only)

    st.markdown("---")
    st.markdown("<div style='color:#8b949e;font-size:0.72rem;'>Data source: osintframework.com<br>Updated from live GitHub repo</div>", unsafe_allow_html=True)
    


# ─── Header ──────────────────────────────────────────────────────────────────
st.markdown("""
<div class="portal-header">
  <div>
    <div style="display:flex;align-items:center;gap:12px;margin-bottom:6px;">
      <span style="font-size:2rem;">🔍</span>
      <span class="portal-title">OSINT Intelligence Portal</span>
      <span class="badge-le">LAW ENFORCEMENT</span>
    </div>
    <div class="portal-subtitle">Powered by OSINT Framework · 1,100+ tools · Structured investigative workflow</div>
  </div>
</div>
""", unsafe_allow_html=True)

# ─── Step Progress Bar ────────────────────────────────────────────────────────
step_names = ["Case Setup", "Data Types", "Find Tools", "Enter Findings", "Generate Report"]
pills = ""
for i, name in enumerate(step_names, 1):
    if i < st.session_state.step:
        cls = "done"
        icon = "✓"
    elif i == st.session_state.step:
        cls = "active"
        icon = str(i)
    else:
        cls = ""
        icon = str(i)
    pills += f'<span class="step-pill {cls}">{icon} {name}</span>'
st.markdown(f'<div class="step-nav">{pills}</div>', unsafe_allow_html=True)


# ════════════════════════════════════════════════════════════════════════════
# STEP 1 — Case Setup
# ════════════════════════════════════════════════════════════════════════════
if st.session_state.step == 1:
    st.markdown("## 📋 Step 1: Case Setup")
    st.markdown("<div class='info-box'>ℹ️ Enter the investigation metadata and any known subject identifiers. This information will be embedded in the final report.</div>", unsafe_allow_html=True)

    with st.form("case_form"):
        st.markdown("### 🗂️ Case Information")
        c1, c2, c3 = st.columns(3)
        case_number = c1.text_input("Case Number", placeholder="e.g. INV-2024-001")
        investigator = c2.text_input("Investigator Name", placeholder="Agent / Officer name")
        agency = c3.text_input("Agency / Department", placeholder="e.g. FBI, DEA, Metro PD")

        classification = st.selectbox("Classification Level", [
            "UNCLASSIFIED", "LAW ENFORCEMENT SENSITIVE", "CONFIDENTIAL", "SECRET"
        ])

        st.markdown("### 👤 Subject Identifiers (enter what you have)")
        c1, c2 = st.columns(2)
        full_name = c1.text_input("Full Name / Legal Name", placeholder="Last, First Middle")
        aliases = c2.text_input("Known Aliases / AKAs", placeholder="Comma-separated")

        c1, c2, c3 = st.columns(3)
        dob = c1.text_input("Date of Birth", placeholder="MM/DD/YYYY")
        location = c2.text_input("Known Location / City", placeholder="City, State/Country")
        vehicle = c3.text_input("Vehicle Info", placeholder="Year/Make/Model/Plate")

        c1, c2 = st.columns(2)
        email = c1.text_input("Email Address(es)", placeholder="Comma-separated")
        phone = c2.text_input("Phone Number(s)", placeholder="Comma-separated")

        c1, c2 = st.columns(2)
        username = c1.text_input("Username(s) / Handle(s)", placeholder="Comma-separated")
        ip_address = c2.text_input("IP Address(es)", placeholder="Comma-separated")

        c1, c2 = st.columns(2)
        domains = c1.text_input("Domain(s) / Website(s)", placeholder="Comma-separated")
        crypto_addr = c2.text_input("Crypto Wallet Address(es)", placeholder="Optional")

        notes = st.text_area("Preliminary Notes / Background", height=100,
                              placeholder="Known criminal history, associates, case context...")

        submitted = st.form_submit_button("Save Case & Continue →", use_container_width=True)

    if submitted:
        st.session_state.subject_info = {
            "case_number": case_number or "N/A",
            "investigator": investigator or "N/A",
            "agency": agency or "N/A",
            "classification": classification,
            "full_name": full_name or "N/A",
            "aliases": aliases or "N/A",
            "dob": dob or "N/A",
            "location": location or "N/A",
            "vehicle": vehicle or "N/A",
            "email": email or "N/A",
            "phone": phone or "N/A",
            "username": username or "N/A",
            "ip_address": ip_address or "N/A",
            "domains": domains or "N/A",
            "crypto_addr": crypto_addr or "N/A",
            "notes": notes or "None",
        }
        go_to(2)
        st.rerun()


# ════════════════════════════════════════════════════════════════════════════
# STEP 2 — Select Data Types
# ════════════════════════════════════════════════════════════════════════════
elif st.session_state.step == 2:
    st.markdown("## 🗂️ Step 2: Select Data Types You Have")
    st.markdown("<div class='info-box'>ℹ️ Select all types of data/identifiers available for this investigation. The portal will filter relevant OSINT tools for each category.</div>", unsafe_allow_html=True)

    # Smart pre-selection based on filled fields
    info = st.session_state.subject_info
    auto_suggest = []
    if info.get("username") and info["username"] != "N/A":
        auto_suggest.append("Username")
    if info.get("email") and info["email"] != "N/A":
        auto_suggest.append("Email Address")
    if info.get("phone") and info["phone"] != "N/A":
        auto_suggest.append("Telephone Numbers")
    if info.get("ip_address") and info["ip_address"] != "N/A":
        auto_suggest.append("IP & MAC Address")
    if info.get("domains") and info["domains"] != "N/A":
        auto_suggest.append("Domain Name")
    if info.get("full_name") and info["full_name"] != "N/A":
        auto_suggest.extend(["People Search Engines", "Public Records", "Social Networks"])
    if info.get("crypto_addr") and info["crypto_addr"] != "N/A":
        auto_suggest.append("Blockchain & Cryptocurrency")

    if auto_suggest:
        st.markdown(f"<div class='warn-box'>💡 <b>Auto-detected from case setup:</b> {', '.join(set(auto_suggest))}</div>", unsafe_allow_html=True)

    # Organize categories into groups for display
    CATEGORY_GROUPS = {
        "🆔 Identity & People": [
            "Username", "Email Address", "Telephone Numbers",
            "People Search Engines", "Dating",
        ],
        "🌐 Digital Infrastructure": [
            "IP & MAC Address", "Domain Name", "Cloud Infrastructure",
            "Dark Web", "Mobile OSINT",
        ],
        "📡 Social & Communications": [
            "Social Networks", "Instant Messaging", "Online Communities",
        ],
        "📄 Records & Finance": [
            "Public Records", "Business Records", "Blockchain & Cryptocurrency",
            "Compliance & Risk Intelligence", "Transportation",
        ],
        "🖼️ Media & Content": [
            "Images / Videos / Docs", "Geolocation Tools / Maps",
            "Archives", "Language Translation",
        ],
        "🔧 Technical & Security": [
            "Search Engines", "Malicious File Analysis", "Cyber Threat Intelligence",
            "Encoding / Decoding", "AI Tools", "Tools",
            "Disinformation & Media Verification",
        ],
        "📚 Support": [
            "Training", "Documentation / Evidence Capture", "OpSec", "Classifieds",
        ],
    }

    selected = list(st.session_state.selected_data_types)
    if not selected and auto_suggest:
        selected = list(set(auto_suggest))

    all_grouped = set()
    for items in CATEGORY_GROUPS.values():
        all_grouped.update(items)
    other_cats = [c for c in ALL_CATEGORIES if c not in all_grouped]

    with st.form("data_type_form"):
        for group_name, cats in CATEGORY_GROUPS.items():
            st.markdown(f"**{group_name}**")
            cols = st.columns(3)
            for i, cat in enumerate(cats):
                if cat in ALL_CATEGORIES:
                    count = len(df_tools[df_tools['category'] == cat])
                    checked = cat in selected
                    if cols[i % 3].checkbox(f"{cat} ({count})", value=checked, key=f"cat_{cat}"):
                        if cat not in selected:
                            selected.append(cat)
                    else:
                        if cat in selected:
                            selected.remove(cat)
            st.markdown("")

        if other_cats:
            st.markdown("**📁 Other Categories**")
            cols = st.columns(3)
            for i, cat in enumerate(other_cats):
                count = len(df_tools[df_tools['category'] == cat])
                checked = cat in selected
                if cols[i % 3].checkbox(f"{cat} ({count})", value=checked, key=f"cat_{cat}"):
                    if cat not in selected:
                        selected.append(cat)
                else:
                    if cat in selected:
                        selected.remove(cat)

        col1, col2 = st.columns([1, 4])
        back = col1.form_submit_button("← Back")
        proceed = col2.form_submit_button("Find Tools for Selected Categories →", use_container_width=True)

    if back:
        go_to(1)
        st.rerun()
    if proceed:
        # Collect all checked boxes from session
        final_selected = [cat for cat in ALL_CATEGORIES if st.session_state.get(f"cat_{cat}", False)]
        if not final_selected:
            st.error("Please select at least one data category.")
        else:
            st.session_state.selected_data_types = final_selected
            # Initialize tool_results for new categories
            for cat in final_selected:
                if cat not in st.session_state.tool_results:
                    st.session_state.tool_results[cat] = []
            go_to(3)
            st.rerun()


# ════════════════════════════════════════════════════════════════════════════
# STEP 3 — Browse & Select Tools
# ════════════════════════════════════════════════════════════════════════════
elif st.session_state.step == 3:
    st.markdown("## 🛠️ Step 3: Find & Select Your Tools")
    st.markdown("<div class='info-box'>ℹ️ Browse tools for each selected category. Check the tools you plan to use — they will appear in your final report.</div>", unsafe_allow_html=True)

    search = st.text_input("🔎 Search tools across all categories", placeholder="e.g. phone lookup, email breach, social media...")

    selected_cats = st.session_state.selected_data_types

    # Category tabs
    tabs = st.tabs([f"📂 {c}" for c in selected_cats] + ["📊 Summary"])

    for i, cat in enumerate(selected_cats):
        with tabs[i]:
            cat_df = df_tools[df_tools['category'] == cat].copy()

            # Apply search
            if search:
                mask = (
                    cat_df['name'].str.contains(search, case=False, na=False) |
                    cat_df['description'].str.contains(search, case=False, na=False) |
                    cat_df['input'].str.contains(search, case=False, na=False) |
                    cat_df['bestFor'].str.contains(search, case=False, na=False)
                )
                cat_df = cat_df[mask]

            # Apply sidebar filters
            if st.session_state.filter_free_only:
                cat_df = cat_df[cat_df['pricing'] == 'free']
            if st.session_state.filter_no_reg:
                cat_df = cat_df[cat_df['registration'] == False]
            if st.session_state.filter_passive_only:
                cat_df = cat_df[cat_df['opsec'] == 'passive']

            # Sub-category filter
            subcats = sorted(cat_df['subcategory'].unique().tolist())
            if len(subcats) > 1:
                subcat_filter = st.multiselect(
                    "Filter by sub-category", options=subcats,
                    key=f"subcat_{cat}", default=[]
                )
                if subcat_filter:
                    cat_df = cat_df[cat_df['subcategory'].isin(subcat_filter)]

            st.markdown(f"**{len(cat_df)} tools found** in *{cat}*")

            if cat_df.empty:
                st.info("No tools match current filters.")
                continue

            # Display by subcategory
            current_selected = st.session_state.tool_results.get(cat, [])
            new_selected = []

            for subcat in sorted(cat_df['subcategory'].unique()):
                sub_df = cat_df[cat_df['subcategory'] == subcat]
                if subcat:
                    st.markdown(f"#### 📁 {subcat}")
                for _, row in sub_df.iterrows():
                    col_check, col_card = st.columns([0.05, 0.95])
                    with col_check:
                        is_checked = row['name'] in current_selected
                        checked = st.checkbox("", value=is_checked, key=f"tool_{cat}_{row['name'][:40]}")
                        if checked:
                            new_selected.append(row['name'])
                    with col_card:
                        st.markdown(tool_card_html(row), unsafe_allow_html=True)

            st.session_state.tool_results[cat] = new_selected

    # Summary tab
    with tabs[-1]:
        st.markdown("### 📊 Selected Tools Summary")
        total = sum(len(v) for v in st.session_state.tool_results.values())
        st.markdown(f"**{total} tools selected across {len(selected_cats)} categories**")
        for cat, tools in st.session_state.tool_results.items():
            if tools:
                with st.expander(f"**{cat}** — {len(tools)} tool(s) selected"):
                    for t in tools:
                        st.markdown(f"- {t}")

    st.markdown("---")
    col1, col2 = st.columns([1, 4])
    if col1.button("← Back"):
        go_to(2)
        st.rerun()
    if col2.button("Proceed to Enter Findings →", use_container_width=True):
        go_to(4)
        st.rerun()


# ════════════════════════════════════════════════════════════════════════════
# STEP 4 — Enter Findings
# ════════════════════════════════════════════════════════════════════════════
elif st.session_state.step == 4:
    st.markdown("## 📝 Step 4: Enter Findings from Each Tool")
    st.markdown("""
<div class='info-box'>
ℹ️ For each tool you used, paste or type the findings below.
Use the tool link to open each resource, run your query, then paste results back here.
Even a brief note like "No results" is valuable for documentation.
</div>
""", unsafe_allow_html=True)

    selected_cats = st.session_state.selected_data_types
    tool_results = st.session_state.tool_results

    # Build a lookup for tool metadata
    tool_meta = {row['name']: row for _, row in df_tools.iterrows()}

    tabs = st.tabs([f"📂 {c}" for c in selected_cats])

    for i, cat in enumerate(selected_cats):
        with tabs[i]:
            selected_tools = tool_results.get(cat, [])
            cat_tools_all = df_tools[df_tools['category'] == cat]

            if not selected_tools:
                st.info(f"No tools were selected for **{cat}**. You can still add free-form notes below.")
                key = f"{cat}::GENERAL"
                val = st.session_state.collected_findings.get(key, "")
                new_val = st.text_area(
                    "General notes for this category",
                    value=val, height=100,
                    key=f"findings_{cat}_general",
                    placeholder="Enter any findings or notes for this category..."
                )
                st.session_state.collected_findings[key] = new_val
                continue

            for tool_name in selected_tools:
                row = tool_meta.get(tool_name)
                key = f"{cat}::{tool_name}"
                current_val = st.session_state.collected_findings.get(key, "")

                with st.expander(f"🔧 {tool_name.replace('(T)', '[Local]').replace('(R)', '[Reg]')}", expanded=False):
                    if row is not None:
                        c1, c2 = st.columns([3, 1])
                        with c1:
                            st.markdown(f"**Description:** {row['description'][:300] if row['description'] else 'N/A'}")
                            if row['input']:
                                st.markdown(f"**Input needed:** `{row['input']}`")
                            if row['output']:
                                st.markdown(f"**Expected output:** {row['output']}")
                        with c2:
                            st.markdown(f"[🔗 Open Tool]({row['url']})", unsafe_allow_html=False)
                            st.markdown(f"**Pricing:** {row['pricing']}")
                            st.markdown(f"**OpSec:** {row['opsec']}")

                    new_val = st.text_area(
                        f"Findings / Results",
                        value=current_val,
                        height=120,
                        key=f"findings_{cat}_{tool_name[:30]}",
                        placeholder=f"Paste results from {tool_name} here...\nInclude: profile URLs, account details, metadata, any relevant info found.\nNote 'No results' if nothing was found.",
                    )
                    st.session_state.collected_findings[key] = new_val

    st.markdown("---")
    col1, col2 = st.columns([1, 4])
    if col1.button("← Back"):
        go_to(3)
        st.rerun()
    if col2.button("Generate Intelligence Report →", use_container_width=True):
        go_to(5)
        st.rerun()


# ════════════════════════════════════════════════════════════════════════════
# STEP 5 — Generate Report
# ════════════════════════════════════════════════════════════════════════════
elif st.session_state.step == 5:
    st.markdown("## 📄 Step 5: Intelligence Report")

    info = st.session_state.subject_info
    findings = st.session_state.collected_findings
    tool_results = st.session_state.tool_results
    selected_cats = st.session_state.selected_data_types

    # ── Summary Header ──
    st.markdown(f"""
<div class="report-header">
  <div style="display:flex;justify-content:space-between;align-items:flex-start;flex-wrap:wrap;gap:12px;">
    <div>
      <div style="font-size:1.3rem;font-weight:700;color:#e6edf3;">📄 Intelligence Report</div>
      <div style="color:#8b949e;font-size:0.85rem;margin-top:4px;">Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}</div>
    </div>
    <div style="text-align:right;">
      <div style="color:#8b949e;font-size:0.75rem;">CASE NUMBER</div>
      <div style="color:#58a6ff;font-size:1.1rem;font-weight:700;">{info.get('case_number','N/A')}</div>
      <div style="color:#8b949e;font-size:0.75rem;margin-top:6px;">CLASSIFICATION</div>
      <div style="color:#f85149;font-size:0.85rem;font-weight:600;">{info.get('classification','UNCLASSIFIED')}</div>
    </div>
  </div>
</div>
""", unsafe_allow_html=True)

    # ── Case Metadata Row ──
    cols = st.columns(3)
    cols[0].markdown(f"<div class='stat-box'><div class='stat-num'>{info.get('investigator','N/A')}</div><div class='stat-label'>Investigator</div></div>", unsafe_allow_html=True)
    cols[1].markdown(f"<div class='stat-box'><div class='stat-num'>{info.get('agency','N/A')}</div><div class='stat-label'>Agency</div></div>", unsafe_allow_html=True)
    total_tools = sum(len(v) for v in tool_results.values())
    cols[2].markdown(f"<div class='stat-box'><div class='stat-num'>{total_tools}</div><div class='stat-label'>Tools Used</div></div>", unsafe_allow_html=True)

    st.markdown("")

    # ── Subject Profile ──
    st.markdown('<div class="report-section"><h4>👤 Subject Profile</h4>', unsafe_allow_html=True)
    fields = [
        ("Full Name", "full_name"), ("Aliases / AKAs", "aliases"),
        ("Date of Birth", "dob"), ("Known Location", "location"),
        ("Email Address(es)", "email"), ("Phone Number(s)", "phone"),
        ("Username(s)", "username"), ("IP Address(es)", "ip_address"),
        ("Domain(s)", "domains"), ("Vehicle Info", "vehicle"),
        ("Crypto Wallets", "crypto_addr"),
    ]
    c1, c2 = st.columns(2)
    for j, (label, key) in enumerate(fields):
        val = info.get(key, "N/A")
        if val and val != "N/A":
            col = c1 if j % 2 == 0 else c2
            col.markdown(f"""
<div class="report-entry">
  <div class="report-label">{label}</div>
  <div class="report-value">{val}</div>
</div>
""", unsafe_allow_html=True)
    st.markdown("</div>", unsafe_allow_html=True)

    # ── Findings by Category ──
    st.markdown('<div class="report-section"><h4>🔍 Investigation Findings</h4>', unsafe_allow_html=True)
    has_any_findings = False
    for cat in selected_cats:
        cat_findings = {k: v for k, v in findings.items() if k.startswith(cat + "::") and v.strip()}
        cat_tools = tool_results.get(cat, [])

        if not cat_findings and not cat_tools:
            continue
        has_any_findings = True

        with st.expander(f"**{cat}** — {len(cat_tools)} tool(s)", expanded=True):
            if cat_tools:
                st.markdown(f"**Tools referenced:** {', '.join(cat_tools)}")
            if cat_findings:
                for fkey, fval in cat_findings.items():
                    tool_name = fkey.split("::", 1)[1] if "::" in fkey else fkey
                    st.markdown(f"**▶ {tool_name}**")
                    st.markdown(f"<div style='background:#0d1117;border-left:2px solid #58a6ff;padding:10px 14px;border-radius:4px;font-size:0.83rem;color:#c9d1d9;white-space:pre-wrap;'>{fval}</div>", unsafe_allow_html=True)
            else:
                st.markdown("<div style='color:#8b949e;font-size:0.85rem;'>No findings entered for this category.</div>", unsafe_allow_html=True)

    if not has_any_findings:
        st.info("No findings entered yet. Go back to Step 4 to enter results from each tool.")

    st.markdown("</div>", unsafe_allow_html=True)

    # ── Preliminary Notes ──
    if info.get("notes") and info["notes"] != "None":
        st.markdown(f"""
<div class="report-section">
  <h4>📋 Preliminary Notes</h4>
  <div style="color:#c9d1d9;font-size:0.85rem;white-space:pre-wrap;">{info['notes']}</div>
</div>
""", unsafe_allow_html=True)

    # ── Disclaimer ──
    st.markdown("""
<div style="background:#1a0a0a;border:1px solid #7f1d1d;border-radius:8px;padding:14px 18px;margin-top:16px;">
  <div style="color:#fca5a5;font-size:0.75rem;font-weight:700;letter-spacing:1px;margin-bottom:6px;">⚠️ LEGAL DISCLAIMER</div>
  <div style="color:#fca5a5;font-size:0.82rem;">
    This report is generated for law enforcement investigative purposes only. All information must be corroborated
    through official channels before use in legal proceedings. OSINT data is not a substitute for court-admissible
    evidence. Handle per agency data classification policy.
  </div>
</div>
""", unsafe_allow_html=True)

    # ── Export ──
    st.markdown("---")
    st.markdown("### 💾 Export Report")

    report_text = generate_report_text()

    c1, c2, c3 = st.columns(3)
    with c1:
        st.download_button(
            label="⬇️ Download as .txt",
            data=report_text,
            file_name=f"OSINT_Report_{info.get('case_number','CASE').replace(' ','-')}_{datetime.now().strftime('%Y%m%d_%H%M')}.txt",
            mime="text/plain",
            use_container_width=True,
        )
    with c2:
        # Also offer raw JSON export
        export_data = {
            "case_info": info,
            "selected_categories": selected_cats,
            "tools_used": tool_results,
            "findings": findings,
            "generated_at": datetime.now().isoformat(),
        }
        st.download_button(
            label="⬇️ Download as .json",
            data=json.dumps(export_data, indent=2),
            file_name=f"OSINT_Report_{info.get('case_number','CASE').replace(' ','-')}_{datetime.now().strftime('%Y%m%d_%H%M')}.json",
            mime="application/json",
            use_container_width=True,
        )
    with c3:
        if st.button("🔄 Start New Investigation", use_container_width=True):
            for key in list(st.session_state.keys()):
                del st.session_state[key]
            st.rerun()

    st.markdown("---")
    col1, col2 = st.columns([1, 4])
    if col1.button("← Back to Findings"):
        go_to(4)
        st.rerun()

    # Preview raw report
    with st.expander("👁️ Preview Raw Report Text"):
        st.text(report_text)
