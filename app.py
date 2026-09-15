import base64
from pathlib import Path

import pandas as pd
import streamlit as st

from pipeline import CRITICAL_RULE_COUNT, IncidentPipeline

st.set_page_config(
    page_title="Sentinel Triage | Nigeria Cyber Incident Engine",
    page_icon="background.png",
    layout="wide",
    initial_sidebar_state="expanded",
)

BASE_DIR = Path(__file__).resolve().parent
IMAGE_DIR = BASE_DIR / "image"


SEVERITY_STYLES = {
    "Critical": {"color": "#ff4d4d", "bg": "rgba(255,77,77,0.12)", "label": "Critical"},
    "High": {"color": "#ff9f43", "bg": "rgba(255,159,67,0.12)", "label": "High"},
    "Medium": {"color": "#f7d154", "bg": "rgba(247,209,84,0.12)", "label": "Medium"},
    "Low": {"color": "#00c774", "bg": "rgba(0,199,116,0.12)", "label": "Low"},
}

SAMPLE_REPORTS = {
    "Phishing": "Abeg check this link and enter your portal password to claim a grant.",
    "Ransomware": "All files in the finance folder are encrypted and a ransom note appeared.",
    "Credential leak": "Payroll login asked for my password twice. Account locked. Staff ID: STF-8821.",
    "Web defacement": "The public website landing page was replaced with an attacker message.",
    "MITM": "IT found a rogue wifi hotspot in the cafeteria that intercepted staff login traffic, looks like a man-in-the-middle attack.",
    "XSS": "Someone injected a malicious script tag (XSS) into the student portal comment box to steal session cookies.",
    "Firewall breach": "Security saw a port scan then the perimeter firewall was bypassed overnight, attacker reached the DMZ server.",
    "Server pivoting": "After the initial breach the attacker pivoted from the web server and moved laterally to the internal database server.",
    "AI attack": "Someone used a prompt injection to jailbreak our support chatbot and made it leak internal staff data.",
}


def load_background() -> str:
    for name in ("background.jpg", "background.jpeg", "background.png"):
        path = IMAGE_DIR / name
        if path.exists():
            mime = "image/png" if path.suffix.lower() == ".png" else "image/jpeg"
            encoded = base64.b64encode(path.read_bytes()).decode()
            return f"data:{mime};base64,{encoded}"
    return ""


def inject_styles():
    bg = load_background()
    background_layer = (
        f'background-image: linear-gradient(rgba(4,8,6,.55),rgba(4,8,6,.78)), url("{bg}");'
        if bg else
        "background: radial-gradient(circle at top left, #0d1512 0%, #05080a 60%);"
    )

    st.markdown(f"""
    <style>
    :root {{
        --accent: #00a862;
        --accent-dim: rgba(0,168,98,0.14);
        --border: #1e2e28;
        --panel: rgba(13,19,17,0.92);
        --text-primary: #f2f5f3;
        --text-muted: #9fb3aa;
    }}

    .stApp {{
        {background_layer}
        background-size: cover;
        background-position: center;
        background-repeat: no-repeat;
        background-attachment: fixed;
        color: var(--text-primary);
        font-family: 'Inter', 'Segoe UI', sans-serif;
    }}

    #MainMenu, footer, header {{visibility: hidden;}}
    .block-container {{max-width: 1400px; padding-top: 1.5rem;}}

    /* Sidebar */
    [data-testid="stSidebar"] {{
        background: linear-gradient(180deg, #060908 0%, #0a1512 100%);
        border-right: 1px solid var(--border);
    }}
    [data-testid="stSidebar"] * {{color: var(--text-primary) !important;}}
    [data-testid="stSidebar"] .stCaption {{color: var(--text-muted) !important;}}

    /* Header */
    .app-header {{
        position: relative;
        background: linear-gradient(135deg, rgba(6,12,10,.90), rgba(6,16,12,.80));
        border: 1px solid rgba(0,168,98,0.35);
        border-radius: 18px;
        padding: 30px 34px;
        margin-bottom: 20px;
        box-shadow: 0 20px 50px rgba(0,0,0,.45);
    }}
    .app-header-top {{
        display: flex;
        align-items: center;
        justify-content: space-between;
        gap: 20px;
        flex-wrap: wrap;
    }}
    .app-header-brand {{
        display: flex;
        align-items: center;
        gap: 18px;
    }}
    .app-header-icon {{
        width: 58px;
        height: 58px;
        display: flex;
        align-items: center;
        justify-content: center;
        font-size: 1.7rem;
        background: rgba(0,168,98,0.12);
        border: 1px solid rgba(0,168,98,0.5);
        border-radius: 12px;
        flex-shrink: 0;
    }}
    .app-header h1 {{
        color: var(--text-primary);
        font-size: 2.1rem;
        font-weight: 900;
        letter-spacing: 0.5px;
        margin: 0;
        text-transform: uppercase;
    }}
    .app-header h1 span {{color: var(--accent);}}
    .app-header p {{
        color: var(--text-muted);
        margin: 4px 0 0 0;
        font-size: 0.92rem;
    }}
    .status-pill {{
        display: flex;
        align-items: center;
        gap: 8px;
        background: var(--accent-dim);
        border: 1px solid rgba(0,168,98,0.4);
        color: var(--accent);
        font-weight: 700;
        font-size: 0.78rem;
        padding: 8px 14px;
        border-radius: 999px;
        white-space: nowrap;
        height: fit-content;
    }}
    .status-dot {{
        width: 8px; height: 8px; border-radius: 50%;
        background: var(--accent);
        box-shadow: 0 0 6px var(--accent);
    }}

    /* Workflow steps under header */
    .workflow-row {{
        display: flex;
        align-items: center;
        gap: 14px;
        margin-top: 24px;
        padding-top: 20px;
        border-top: 1px solid rgba(30,46,40,0.8);
        flex-wrap: wrap;
    }}
    .workflow-step {{
        display: flex;
        align-items: center;
        gap: 10px;
    }}
    .workflow-step .step-icon {{
        width: 34px;
        height: 34px;
        display: flex;
        align-items: center;
        justify-content: center;
        border-radius: 9px;
        background: rgba(0,168,98,0.10);
        border: 1px solid rgba(0,168,98,0.35);
        font-size: 1rem;
    }}
    .workflow-step .step-label {{
        color: var(--text-primary);
        font-weight: 700;
        font-size: 0.88rem;
    }}
    .workflow-arrow {{
        color: var(--accent);
        font-size: 1.1rem;
        opacity: 0.7;
    }}

    /* Metric strip */
    .metric-row {{display: flex; gap: 14px; margin-bottom: 20px;}}
    .metric-card {{
        flex: 1;
        background: var(--panel);
        border: 1px solid var(--border);
        border-radius: 12px;
        padding: 16px 18px;
    }}
    .metric-card .label {{
        color: var(--text-muted);
        font-size: 0.7rem;
        font-weight: 700;
        text-transform: uppercase;
        letter-spacing: 0.6px;
    }}
    .metric-card .value {{
        color: var(--text-primary);
        font-size: 1.6rem;
        font-weight: 800;
        margin-top: 4px;
    }}

    /* Search bar */
    div[data-testid="stTextInput"] input {{
        background: #0a1210 !important;
        color: var(--text-primary) !important;
        border: 1px solid var(--border) !important;
        border-radius: 999px !important;
        padding: 14px 26px !important;
        font-size: 1.08rem !important;
        min-height: 64px !important;
        height: 64px !important;
        box-shadow: 0 8px 24px rgba(0,0,0,.35);
        width: 100% !important;
    }}
    div[data-testid="stTextInput"] input:focus {{
        border-color: var(--accent) !important;
        width:100%;
        box-shadow: 0 0 0 2px var(--accent-dim), 0 8px 24px rgba(0,0,0,.35) !important;
    }}
    div[data-testid="stTextInput"] > div {{
        border-radius: 999px !important;
        min-height: 64px !important;
        width: 100% !important;
    }}
    .stButton > button[kind="primary"] {{
        border-radius: 999px !important;
    }}
    .stButton > button[kind="secondary"] {{
        background: transparent !important;
        color: var(--text-muted) !important;
        border: 1px solid var(--border) !important;
        border-radius: 999px !important;
        font-weight: 500 !important;
    }}
    .stButton > button[kind="secondary"]:hover {{
        color: var(--accent) !important;
        border-color: rgba(0,168,98,0.4) !important;
    }}

    /* Section labels */
    .section-label {{
        color: var(--text-primary);
        font-weight: 700;
        font-size: 1.02rem;
        margin-bottom: 2px;
    }}
    .section-sub {{
        color: var(--text-muted);
        font-size: 0.85rem;
        margin-bottom: 14px;
    }}

    /* Panel wrapper */
    .panel {{
        background: var(--panel);
        border: 1px solid var(--border);
        border-radius: 14px;
        padding: 20px 22px;
    }}

    /* Inputs */
    .stTextArea textarea, [data-baseweb="select"] > div {{
        background: #060a08 !important;
        color: var(--text-primary) !important;
        border: 1px solid var(--border) !important;
        border-radius: 10px !important;
    }}
    .stTextArea textarea:focus {{
        border-color: var(--accent) !important;
        box-shadow: 0 0 0 1px var(--accent) !important;
    }}
    [data-baseweb="select"] * {{color: var(--text-primary) !important;}}

    /* Buttons */
    .stButton > button {{
        background: var(--accent) !important;
        color: #051a10 !important;
        border: none !important;
        border-radius: 10px !important;
        font-weight: 700 !important;
        min-height: 46px;
        transition: filter 0.15s ease;
    }}
    .stButton > button:hover {{filter: brightness(1.1);}}

    /* Result card */
    .result-card {{
        background: var(--panel);
        border: 1px solid var(--border);
        border-radius: 14px;
        padding: 20px 22px;
        margin-bottom: 14px;
    }}
    .result-heading {{
        color: var(--text-muted);
        font-size: 0.76rem;
        font-weight: 700;
        text-transform: uppercase;
        letter-spacing: 0.6px;
        margin-bottom: 4px;
    }}
    .result-category {{
        color: var(--text-primary);
        font-size: 1.3rem;
        font-weight: 800;
        margin-bottom: 12px;
    }}
    .severity-badge {{
        display: inline-flex;
        align-items: center;
        gap: 6px;
        padding: 6px 14px;
        border-radius: 999px;
        font-weight: 700;
        font-size: 0.82rem;
    }}

    .law-box {{
        background: var(--accent-dim);
        border-left: 4px solid var(--accent);
        padding: 16px 18px;
        border-radius: 8px;
        line-height: 1.55;
    }}
    .law-box b {{color: var(--text-primary);}}

    .stTabs [data-baseweb="tab-list"] {{gap: 6px;}}
    .stTabs [data-baseweb="tab"] {{color: var(--text-muted);}}
    .stTabs [aria-selected="true"] {{color: var(--accent) !important;}}

    [data-testid="stDataFrame"] {{
        border: 1px solid var(--border);
        border-radius: 10px;
        overflow: hidden;
    }}

    hr {{border-color: var(--border) !important;}}

    .app-footer {{
        text-align: center;
        padding: 22px 0 10px 0;
        color: var(--text-muted);
        font-size: 0.74rem;
    }}
    .app-footer b {{color: var(--accent);}}
    </style>
    """, unsafe_allow_html=True)


@st.cache_resource
def load_system():
    df = pd.read_csv(BASE_DIR / "synthetic_incidents.csv")
    pipe = IncidentPipeline()
    pipe.train(df)
    accuracy, report = pipe.evaluate(df)
    return pipe, df, accuracy, report


def render_header():
    st.markdown("""
    <div class="app-header">
        <div class="app-header-top">
            <div class="app-header-brand">
                <div class="app-header-icon">🛡️</div>
                <div>
                    <h1>Nigeria <span>Sentinel</span><span>-Triage</span></h1>
                    <p>Professional cyber incident triage, anonymization, and Nigeria Cybercrimes Act mapping.</p>
                </div>
            </div>
            <div class="workflow-step">
                <div class="step-icon">⚖️</div>
                <div class="step-label">Legal Reference</div>
            </div>
        </div>
    </div>
    """, unsafe_allow_html=True)


def render_severity_badge(severity: str) -> str:
    style = SEVERITY_STYLES.get(severity, SEVERITY_STYLES["Low"])
    return (
        f'<span class="severity-badge" style="color:{style["color"]};'
        f'background:{style["bg"]};border:1px solid {style["color"]}55;">'
        f'{style["label"].upper()} SEVERITY</span>'
    )


def render_sidebar(accuracy: float):
    with st.sidebar:
        st.markdown("### 🛡️ Sentinel Triage")
        st.caption("Nigeria Cyber Incident Engine")
        st.divider()
        st.markdown("**Pipeline stages**")
        st.caption(
            "PII redaction → Classification → Duplicate detection → Legal mapping")
        st.divider()
        st.caption(
            "Defensive and educational use only. Not a substitute for legal advice.")


def render_search_bar():
    if "query" not in st.session_state:
        st.session_state.query = ""

    def set_query(text: str = ""):
        st.session_state.query = text

    _, mid, _ = st.columns([0.35, 4.3, 0.35])
    with mid:
        st.text_input(
            "Incident report",
            key="query",
            placeholder="Search or paste an incident report to triage...",
            label_visibility="collapsed",
        )

        action_cols = st.columns(2, gap="small")
        with action_cols[0]:
            analyze = st.button("Analyze Incident",
                                use_container_width=True, type="primary")
        with action_cols[1]:
            st.button("Clear", use_container_width=True, on_click=set_query)

        chips = list(SAMPLE_REPORTS.items())
        chips_per_row = 5
        for row_start in range(0, len(chips), chips_per_row):
            row_chips = chips[row_start:row_start + chips_per_row]
            chip_cols = st.columns(chips_per_row)
            for col, (label, text) in zip(chip_cols, row_chips):
                with col:
                    st.button(
                        label,
                        key=f"chip_{label}",
                        use_container_width=True,
                        on_click=set_query,
                        args=(text,),
                    )

    return st.session_state.query, analyze


def render_result(pipeline: IncidentPipeline, raw: str):
    if not raw.strip():
        return

    st.markdown('<div class="section-label">Triage Result</div>',
                unsafe_allow_html=True)
    st.markdown(
        '<div class="section-sub">Classification, severity, and legal mapping for the submitted report.</div>',
        unsafe_allow_html=True,
    )

    result = pipeline.process_report(raw)

    st.markdown(f"""
    <div class="result-card">
        <div class="result-heading">Detected Category</div>
        <div class="result-category">{result['category']}</div>
        {render_severity_badge(result['severity'])}
    </div>
    """, unsafe_allow_html=True)

    duplicate_status = (
        f"Duplicate ({result['match_confidence']}% match)"
        if result["is_duplicate"] else "Unique incident"
    )

    st.dataframe(
        pd.DataFrame([
            ["Assigned department", result["department"]],
            ["MITRE ATT&CK technique", result["mitre"]],
            ["Duplicate status", duplicate_status],
            ["Incident cluster", result["cluster_id"]],
        ], columns=["Field", "Value"]),
        use_container_width=True,
        hide_index=True,
    )

    st.markdown("##### Applicable Legal Provision")
    st.markdown(
        f'<div class="law-box"><b>{result["cyber_act_section"]}</b><br><br>{result["legal_description"]}</div>',
        unsafe_allow_html=True,
    )

    col_a, col_b = st.columns(2)
    with col_a:
        with st.expander("Original input"):
            st.code(raw, language="text")
    with col_b:
        with st.expander("Sanitized input"):
            st.code(result["clean_text"], language="text")

    st.caption(
        "Legal mapping is provided for triage context only and is not a legal determination.")


def render_tabs(df: pd.DataFrame):
    queue_tab, legal_tab, notes_tab = st.tabs(
        ["Incident Queue", "Legal Context", "System Notes"])

    with queue_tab:
        st.subheader("Recent Incident Queue")
        st.dataframe(
            df[["report_id", "city", "ground_truth_category",
                "true_cluster_id"]].head(15),
            use_container_width=True,
            hide_index=True,
        )

    with legal_tab:
        st.subheader("Nigeria Cybercrimes Act Reference")
        st.info(
            "The displayed provision is a triage reference. Formal legal interpretation "
            "should be confirmed by a qualified legal professional."
        )

    with notes_tab:
        st.subheader("System Notes")
        st.markdown(
            "- PII is redacted before any sanitized text is shown or stored.\n"
            "- The classifier is trained on synthetic incident reports.\n"
            "- Screenshot or image reports require OCR before text classification.\n"
            "- Duplicate detection uses a fixed cosine-similarity threshold."
        )


def render_footer():
    st.markdown(
        '<div class="app-footer"><b>Sentinel Triage</b> · Defensive / Educational Use · Nigeria</div>',
        unsafe_allow_html=True,
    )


def main():
    inject_styles()
    pipeline, df, _, _ = load_system()

    render_sidebar(0)
    render_header()

    query, analyze = render_search_bar()

    st.markdown("<div style='height: 28px;'></div>", unsafe_allow_html=True)
    render_result(pipeline, query if analyze else "")

    st.divider()
    render_tabs(df)
    render_footer()


if __name__ == "__main__":
    main()
