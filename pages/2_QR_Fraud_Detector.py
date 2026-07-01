from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Dict, Optional

import streamlit as st

from modules.qr_analyzer import analyze_url, decode_qr


@st.cache_data
def _load_css(path: str) -> str:
    """Load CSS from disk for theming."""
    with open(path, "r", encoding="utf-8") as file_handle:
        return file_handle.read()


@st.cache_data
def _cached_decode_qr(image_bytes: bytes) -> Dict[str, Any]:
    """Cached wrapper around QR decoding."""
    return decode_qr(image_bytes)


@st.cache_data
def _cached_analyze_url(url: str) -> Dict[str, Any]:
    """Cached wrapper around URL analysis."""
    return analyze_url(url)


def _init_state() -> None:
    """Initialize session state keys used by the QR page."""
    if "case_log" not in st.session_state:
        st.session_state["case_log"] = []
    if "qr_result" not in st.session_state:
        st.session_state["qr_result"] = None
    if "qr_analysis" not in st.session_state:
        st.session_state["qr_analysis"] = None


def _risk_color(score: int) -> str:
    """Map risk scores to color names."""
    if score <= 25:
        return "#1f8b4c"
    if score <= 50:
        return "#c69026"
    if score <= 75:
        return "#e67e22"
    return "#d43f3a"


css = _load_css("assets/style.css")
st.markdown(f"<style>{css}</style>", unsafe_allow_html=True)

_init_state()

st.title("QR Code Fraud Detection")
mode = st.radio("Select input mode", ["Upload QR image", "Enter URL directly"])

analysis_result: Optional[Dict[str, Any]] = None

if mode == "Upload QR image":
    upload = st.file_uploader("Upload a QR image", type=["png", "jpg", "jpeg", "webp"])
    if upload is not None:
        decoded = _cached_decode_qr(upload.read())
        st.subheader("Decoded Content")
        st.json(decoded)
        if decoded.get("success") and decoded.get("data", {}).get("type") == "url":
            url = decoded["data"]["content"]
            analysis_result = _cached_analyze_url(url)
        elif decoded.get("success"):
            st.info("Decoded content is not a URL. URL analysis skipped.")

if mode == "Enter URL directly":
    url_input = st.text_input("Enter URL to analyze")
    if st.button("Analyze URL") and url_input:
        analysis_result = _cached_analyze_url(url_input)

if analysis_result:
    result = analysis_result.get("data", {})
    st.subheader("Risk Assessment")
    score = int(result.get("risk_score", 0))
    color = _risk_color(score)
    st.metric("Risk Score", score)
    st.markdown(
        f"<div style='font-weight:700;color:{color}'>Risk score indicator</div>",
        unsafe_allow_html=True,
    )

    redirect_chain = result.get("redirect_chain", [])
    if redirect_chain:
        st.subheader("Redirect Chain")
        chain_lines = []
        for idx, hop in enumerate(redirect_chain, start=1):
            chain_lines.append(f"{idx}. {hop.get('url')} (HTTP {hop.get('status_code')})")
        st.markdown("\n".join(chain_lines))

    vt = result.get("vt_result", {})
    col1, col2 = st.columns(2)
    with col1:
        st.metric("VT Malicious", vt.get("malicious", 0))
    with col2:
        st.metric("VT Total Engines", vt.get("total", 0))

    domain_age = result.get("domain_age_days")
    st.metric("Domain Age (days)", domain_age if domain_age is not None else "Unknown")
    if domain_age is not None and domain_age < 90:
        st.error("Domain is younger than 90 days")

    # --- ENHANCED SECURITY REPORT ---
    st.markdown("---")
    st.subheader("🛡️ Detailed Threat Report")
    
    advanced = result.get("advanced_threats", {})
    if advanced.get("ip_address"):
        st.info(f"**Network Trace:** Target IP resolved to `{advanced['ip_address']}`")
        
    prompt_injs = result.get("prompt_injections", [])
    if prompt_injs:
        st.error(f"🚨 **Prompt Injection Detected:** Found signatures: {', '.join(prompt_injs)}")
        
    anoms = result.get("anomalies", [])
    if anoms:
        st.warning(f"⚠️ **Encoded Anomalies Found:** {len(anoms)} payloads")
        for a in anoms:
            st.code(f"Key: {a.get('key')}\nDecoded: {a.get('decoded')}", language="text")
                
    if any([advanced.get("cookies"), advanced.get("scripts"), advanced.get("iframes"), advanced.get("hidden_params")]):
        with st.expander("Web Elements Analysis (Cookies, Scripts, iFrames, Hidden Params)"):
            if advanced.get("cookies"):
                st.write("**Set Cookies:**")
                st.dataframe(advanced["cookies"], use_container_width=True)
            if advanced.get("scripts"):
                st.write(f"**Scripts ({len(advanced['scripts'])}):**")
                for s in advanced["scripts"][:10]: # show top 10
                    st.write(f"- `{s}`")
                if len(advanced['scripts']) > 10:
                    st.write(f"*...and {len(advanced['scripts']) - 10} more*")
            if advanced.get("iframes"):
                st.write(f"**iFrames ({len(advanced['iframes'])}):**")
                for i in advanced["iframes"]:
                    st.write(f"- `{i}`")
            if advanced.get("hidden_params"):
                st.write(f"**Hidden Parameters ({len(advanced['hidden_params'])}):**")
                st.dataframe(advanced["hidden_params"], use_container_width=True)
    # --- END ENHANCED SECURITY REPORT ---

    risk_level = result.get("risk_level", "UNKNOWN")
    if risk_level in {"CRITICAL", "HIGH"}:
        st.error(f"Overall Verdict: {risk_level}")
    elif risk_level == "MEDIUM":
        st.warning(f"Overall Verdict: {risk_level}")
    else:
        st.success(f"Overall Verdict: {risk_level}")

    record = {
        "module": "QR Fraud Detector",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "result": analysis_result.get("data", {}),
    }
    if st.session_state.get("qr_result") != record:
        st.session_state["case_log"].append(record)
        st.session_state["qr_result"] = record
    st.session_state["qr_analysis"] = analysis_result

download_payload = json.dumps(st.session_state.get("qr_analysis") or {}, indent=2)
st.download_button(
    "Download Result JSON",
    data=download_payload,
    file_name="qr_fraud_result.json",
    mime="application/json",
    disabled=st.session_state.get("qr_analysis") is None,
)
