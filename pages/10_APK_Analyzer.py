"""
APK Security Analyzer — Streamlit Frontend
A forensic-grade APK analysis dashboard.
Integrated as a page in the Cyber Trident multi-page app.
"""

import streamlit as st
import json
import tempfile
import os
import time
from pathlib import Path
import plotly.graph_objects as go
import plotly.express as px
import pandas as pd
import sys

# Ensure the APK folder is importable regardless of CWD
_APK_DIR = Path(__file__).resolve().parent.parent / "APK"
if str(_APK_DIR) not in sys.path:
    sys.path.insert(0, str(_APK_DIR))

from apk_engine import analyze_apk

# ─────────────────────────────────────────────────────────────────────────────
# COLOUR PALETTE  (matches global dark theme from config.toml)
# ─────────────────────────────────────────────────────────────────────────────

DARK_BG   = "#0d1117"
CARD_BG   = "#161b22"
BORDER    = "#30363d"
TEXT_PRI  = "#e6edf3"
TEXT_SEC  = "#8b949e"
ACCENT    = "#58a6ff"
RED       = "#f85149"
ORANGE    = "#d29922"
YELLOW    = "#e3b341"
GREEN     = "#3fb950"
PURPLE    = "#bc8cff"

st.markdown(f"""
<style>
  /* ── Fonts ── */
  @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&family=Inter:wght@300;400;500;600;700&display=swap');

  /* ── Header ── */
  .apk-header {{
    background: linear-gradient(135deg, #0d1117 0%, #161b22 50%, #1c2333 100%);
    border: 1px solid {BORDER};
    border-radius: 12px;
    padding: 36px 40px 28px;
    margin-bottom: 28px;
    position: relative;
    overflow: hidden;
  }}
  .apk-header::before {{
    content: '';
    position: absolute;
    top: 0; left: 0; right: 0;
    height: 3px;
    background: linear-gradient(90deg, {ACCENT}, {PURPLE}, {ACCENT});
  }}
  .apk-header h1 {{
    font-family: 'JetBrains Mono', monospace;
    font-size: 26px;
    font-weight: 700;
    color: {TEXT_PRI};
    margin: 0 0 6px;
    letter-spacing: -0.5px;
  }}
  .apk-header .tagline {{
    font-size: 13px;
    color: {TEXT_SEC};
    font-family: 'JetBrains Mono', monospace;
    letter-spacing: 0.5px;
  }}
  .apk-header .badge {{
    display: inline-block;
    background: rgba(88,166,255,0.1);
    border: 1px solid rgba(88,166,255,0.3);
    color: {ACCENT};
    font-size: 10px;
    font-weight: 600;
    padding: 3px 8px;
    border-radius: 4px;
    font-family: 'JetBrains Mono', monospace;
    letter-spacing: 1px;
    margin-right: 8px;
    text-transform: uppercase;
  }}

  /* ── Upload zone ── */
  .stFileUploader > div {{
    border: 2px dashed {BORDER} !important;
    border-radius: 10px !important;
    background: {CARD_BG} !important;
    transition: border-color 0.2s;
  }}
  .stFileUploader > div:hover {{
    border-color: {ACCENT} !important;
  }}

  /* ── Cards ── */
  .card {{
    background: {CARD_BG};
    border: 1px solid {BORDER};
    border-radius: 10px;
    padding: 20px 24px;
    margin-bottom: 16px;
  }}
  .card-title {{
    font-family: 'JetBrains Mono', monospace;
    font-size: 11px;
    font-weight: 700;
    color: {TEXT_SEC};
    letter-spacing: 1.5px;
    text-transform: uppercase;
    margin-bottom: 14px;
    display: flex;
    align-items: center;
    gap: 8px;
  }}
  .card-title .dot {{
    width: 6px; height: 6px;
    border-radius: 50%;
    background: {ACCENT};
    display: inline-block;
  }}

  /* ── Risk gauge ── */
  .verdict-banner {{
    border-radius: 10px;
    padding: 24px 28px;
    margin-bottom: 16px;
    border-left: 4px solid;
    position: relative;
  }}
  .verdict-score {{
    font-family: 'JetBrains Mono', monospace;
    font-size: 56px;
    font-weight: 700;
    line-height: 1;
  }}
  .verdict-label {{
    font-family: 'JetBrains Mono', monospace;
    font-size: 14px;
    font-weight: 700;
    letter-spacing: 2px;
    text-transform: uppercase;
  }}
  .verdict-desc {{
    font-size: 13px;
    color: {TEXT_SEC};
    margin-top: 4px;
  }}

  /* ── Permission pills ── */
  .perm-pill {{
    display: inline-block;
    padding: 3px 10px;
    border-radius: 20px;
    font-size: 11px;
    font-family: 'JetBrains Mono', monospace;
    margin: 3px;
    font-weight: 500;
  }}
  .perm-critical {{ background: rgba(248,81,73,0.15); border: 1px solid rgba(248,81,73,0.4); color: {RED}; }}
  .perm-high {{ background: rgba(210,153,34,0.15); border: 1px solid rgba(210,153,34,0.4); color: {ORANGE}; }}
  .perm-medium {{ background: rgba(227,179,65,0.15); border: 1px solid rgba(227,179,65,0.4); color: {YELLOW}; }}
  .perm-low {{ background: rgba(63,185,80,0.15); border: 1px solid rgba(63,185,80,0.4); color: {GREEN}; }}
  .perm-normal {{ background: rgba(139,148,158,0.1); border: 1px solid {BORDER}; color: {TEXT_SEC}; }}

  /* ── Alert boxes ── */
  .alert {{
    border-radius: 8px;
    padding: 12px 16px;
    margin: 8px 0;
    font-size: 13px;
    display: flex;
    align-items: flex-start;
    gap: 10px;
  }}
  .alert-critical {{
    background: rgba(248,81,73,0.08);
    border: 1px solid rgba(248,81,73,0.3);
    color: #ffa8a4;
  }}
  .alert-high {{
    background: rgba(210,153,34,0.08);
    border: 1px solid rgba(210,153,34,0.3);
    color: #f0c040;
  }}
  .alert-medium {{
    background: rgba(227,179,65,0.08);
    border: 1px solid rgba(227,179,65,0.3);
    color: #e8d057;
  }}
  .alert-info {{
    background: rgba(88,166,255,0.08);
    border: 1px solid rgba(88,166,255,0.3);
    color: #9ecbff;
  }}

  /* ── Metadata table ── */
  .meta-row {{
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 8px 0;
    border-bottom: 1px solid {BORDER};
    font-size: 13px;
  }}
  .meta-row:last-child {{ border-bottom: none; }}
  .meta-key {{ color: {TEXT_SEC}; font-family: 'JetBrains Mono', monospace; font-size: 12px; }}
  .meta-val {{ color: {TEXT_PRI}; font-weight: 500; word-break: break-all; text-align: right; max-width: 60%; }}

  /* ── Hash display ── */
  .hash-box {{
    background: #010409;
    border: 1px solid {BORDER};
    border-radius: 6px;
    padding: 10px 14px;
    font-family: 'JetBrains Mono', monospace;
    font-size: 11px;
    color: {GREEN};
    word-break: break-all;
    margin: 4px 0;
  }}

  /* ── Family match card ── */
  .family-card {{
    background: rgba(248,81,73,0.05);
    border: 1px solid rgba(248,81,73,0.2);
    border-radius: 8px;
    padding: 14px 18px;
    margin: 8px 0;
  }}
  .family-name {{
    font-family: 'JetBrains Mono', monospace;
    font-size: 14px;
    font-weight: 700;
    color: {RED};
  }}
  .match-bar {{
    background: {BORDER};
    border-radius: 4px;
    height: 6px;
    margin: 8px 0;
    overflow: hidden;
  }}
  .match-fill {{
    height: 100%;
    border-radius: 4px;
    background: linear-gradient(90deg, {RED}, {ORANGE});
  }}

  /* ── Dev ID ── */
  .dev-clue {{
    display: flex;
    gap: 12px;
    padding: 7px 0;
    border-bottom: 1px solid {BORDER};
    font-size: 13px;
  }}
  .dev-clue:last-child {{ border-bottom: none; }}
  .dev-source {{
    font-family: 'JetBrains Mono', monospace;
    font-size: 10px;
    color: {ACCENT};
    background: rgba(88,166,255,0.1);
    border: 1px solid rgba(88,166,255,0.2);
    padding: 2px 6px;
    border-radius: 4px;
    white-space: nowrap;
    height: fit-content;
    margin-top: 1px;
  }}

  /* ── Tab styling ── */
  .stTabs [data-baseweb="tab-list"] {{
    background: {CARD_BG};
    border-radius: 8px;
    padding: 4px;
    gap: 2px;
    border: 1px solid {BORDER};
  }}
  .stTabs [data-baseweb="tab"] {{
    background: transparent;
    color: {TEXT_SEC};
    border-radius: 6px;
    padding: 8px 16px;
    font-size: 13px;
    font-weight: 500;
    border: none;
  }}
  .stTabs [aria-selected="true"] {{
    background: {DARK_BG} !important;
    color: {TEXT_PRI} !important;
  }}
  .stTabs [data-baseweb="tab-panel"] {{
    padding-top: 20px;
  }}

  /* ── Misc ── */
  .section-label {{
    font-family: 'JetBrains Mono', monospace;
    font-size: 10px;
    letter-spacing: 2px;
    text-transform: uppercase;
    color: {TEXT_SEC};
    margin-bottom: 10px;
    margin-top: 20px;
  }}
  code {{
    background: #010409 !important;
    color: {GREEN} !important;
    font-family: 'JetBrains Mono', monospace !important;
    font-size: 11px !important;
    padding: 2px 6px !important;
    border-radius: 4px !important;
  }}

  .block-container {{ max-width: 1400px; }}
</style>
""", unsafe_allow_html=True)


# ─────────────────────────────────────────────────────────────────────────────
# HELPER RENDERERS
# ─────────────────────────────────────────────────────────────────────────────

def meta_row(key, val):
    return f'<div class="meta-row"><span class="meta-key">{key}</span><span class="meta-val">{val}</span></div>'


def perm_pill(text, risk):
    css = {"CRITICAL": "perm-critical", "HIGH": "perm-high",
           "MEDIUM": "perm-medium", "LOW": "perm-low"}.get(risk, "perm-normal")
    return f'<span class="perm-pill {css}">{text}</span>'


def alert_box(level, icon, text):
    css = {"CRITICAL": "alert-critical", "HIGH": "alert-high",
           "MEDIUM": "alert-medium", "INFO": "alert-info"}.get(level, "alert-info")
    return f'<div class="alert {css}"><span>{icon}</span><span>{text}</span></div>'


def risk_color(score):
    if score >= 75: return RED
    if score >= 50: return ORANGE
    if score >= 25: return YELLOW
    return GREEN


def card(title_icon, title_text, body_html):
    return f"""
    <div class="card">
      <div class="card-title"><span class="dot"></span>{title_icon} {title_text}</div>
      {body_html}
    </div>"""


def format_bytes(n):
    if n > 1_048_576: return f"{n/1_048_576:.2f} MB"
    if n > 1024: return f"{n/1024:.1f} KB"
    return f"{n} B"


# ─────────────────────────────────────────────────────────────────────────────
# RENDER FUNCTIONS — each tab
# ─────────────────────────────────────────────────────────────────────────────

def render_overview(report):
    risk = report["risk"]
    app  = report.get("app_info", {})
    fi   = report.get("file_info", {})
    col1, col2 = st.columns([2, 3])

    # ── Risk Score ──
    with col1:
        score = risk["score"]
        rc = risk_color(score)
        verdict_icons = {
            "MALICIOUS": "☠️", "SUSPICIOUS": "⚠️",
            "POTENTIALLY UNWANTED": "🔶", "LIKELY CLEAN": "✅"
        }
        icon = verdict_icons.get(risk["verdict"], "❓")
        st.markdown(f"""
        <div class="verdict-banner" style="background:rgba(0,0,0,0.3); border-left-color:{rc}; border: 1px solid {BORDER}; border-left: 4px solid {rc};">
          <div class="verdict-score" style="color:{rc};">{score}</div>
          <div class="verdict-label" style="color:{rc}; margin-top:4px;">{icon} {risk['verdict']}</div>
          <div class="verdict-desc">Risk score out of 100 — based on static analysis</div>
        </div>""", unsafe_allow_html=True)

        fig = go.Figure(go.Indicator(
            mode="gauge+number",
            value=score,
            domain={"x": [0, 1], "y": [0, 1]},
            gauge={
                "axis": {"range": [0, 100], "tickfont": {"color": TEXT_SEC, "size": 10}, "tickcolor": BORDER},
                "bar": {"color": rc, "thickness": 0.3},
                "bgcolor": CARD_BG,
                "borderwidth": 0,
                "steps": [
                    {"range": [0, 25],  "color": "rgba(63,185,80,0.15)"},
                    {"range": [25, 50], "color": "rgba(227,179,65,0.12)"},
                    {"range": [50, 75], "color": "rgba(210,153,34,0.12)"},
                    {"range": [75, 100],"color": "rgba(248,81,73,0.12)"},
                ],
                "threshold": {"line": {"color": rc, "width": 3}, "thickness": 0.8, "value": score}
            },
            number={"font": {"color": rc, "size": 40, "family": "JetBrains Mono"}, "suffix": "/100"}
        ))
        fig.update_layout(
            paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
            height=200, margin=dict(t=20, b=10, l=20, r=20),
            font={"color": TEXT_PRI}
        )
        st.plotly_chart(fig, use_container_width=True)

        bd = risk.get("breakdown", [])
        if bd:
            cats = [b[0] for b in bd]
            vals = [b[1] for b in bd]
            maxs = [b[2] for b in bd]
            colors_bar = [risk_color(int(v / m * 100)) if m > 0 else GREEN for v, m in zip(vals, maxs)]
            fig2 = go.Figure()
            fig2.add_trace(go.Bar(
                x=vals, y=cats, orientation="h",
                marker_color=colors_bar, marker_line_width=0,
                text=[f"{v}/{m}" for v, m in zip(vals, maxs)],
                textposition="inside", textfont={"size": 10, "color": "white", "family": "JetBrains Mono"},
                hovertemplate="%{y}: %{x} pts<extra></extra>"
            ))
            fig2.add_trace(go.Bar(
                x=[m - v for v, m in zip(vals, maxs)], y=cats,
                orientation="h", marker_color="rgba(48,54,61,0.5)",
                marker_line_width=0, hoverinfo="skip"
            ))
            fig2.update_layout(
                barmode="stack",
                paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
                height=240, margin=dict(t=10, b=10, l=0, r=10),
                xaxis={"visible": False}, yaxis={"color": TEXT_SEC, "tickfont": {"size": 10}},
                showlegend=False, bargap=0.25
            )
            st.plotly_chart(fig2, use_container_width=True)

    with col2:
        rows = ""
        rows += meta_row("App Name", app.get("app_name", "Unknown"))
        rows += meta_row("Package", f'<code>{app.get("package_name","—")}</code>')
        rows += meta_row("Version", f'{app.get("version_name","—")} (code {app.get("version_code","—")})')
        rows += meta_row("Min SDK / Target SDK", f'{app.get("min_sdk","—")} / {app.get("target_sdk","—")}')
        rows += meta_row("File Size", format_bytes(fi.get("size_bytes", 0)))
        rows += meta_row("Total Files in APK", str(report["zip_contents"].get("total_files","—")))
        rows += meta_row("DEX Files", str(len(report["zip_contents"].get("dex_files",[]))))
        rows += meta_row("Native Libraries", str(len(report["zip_contents"].get("native_libs",[]))))
        rows += meta_row("Multi-DEX", "⚠️ Yes" if report["zip_contents"].get("multi_dex") else "No")
        rows += meta_row("Main Activity", f'<code>{app.get("main_activity","—")}</code>')
        st.markdown(card("📱", "Application Information", rows), unsafe_allow_html=True)

        h = report.get("hashes", {})
        hash_html = ""
        for k, v in h.items():
            hash_html += f'<div class="section-label">{k.upper()}</div>'
            hash_html += f'<div class="hash-box">{v}</div>'
        st.markdown(card("🔑", "Cryptographic Fingerprint", hash_html), unsafe_allow_html=True)

    comp_data = {
        "Activities": len(app.get("activities", [])),
        "Services": len(app.get("services", [])),
        "Receivers": len(app.get("receivers", [])),
        "Providers": len(app.get("providers", [])),
        "Permissions": report["permissions"].get("total", 0),
    }
    fig3 = go.Figure(go.Bar(
        x=list(comp_data.keys()), y=list(comp_data.values()),
        marker_color=[ACCENT, PURPLE, ORANGE, GREEN, RED],
        marker_line_width=0,
        text=list(comp_data.values()), textposition="outside",
        textfont={"color": TEXT_PRI, "size": 12}
    ))
    fig3.update_layout(
        paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
        height=200, margin=dict(t=10, b=10, l=10, r=10),
        xaxis={"color": TEXT_SEC}, yaxis={"visible": False},
        showlegend=False,
        title={"text": "APK Component Count", "font": {"color": TEXT_SEC, "size": 12, "family": "Inter"}, "x": 0}
    )
    st.plotly_chart(fig3, use_container_width=True)


def render_permissions(report):
    perm = report["permissions"]
    all_perms = perm.get("all", [])
    high_risk = perm.get("high_risk", [])
    combos    = perm.get("combo_matches", [])

    st.markdown(f"""
    <div style="display:flex; gap:16px; margin-bottom:20px;">
      <div class="card" style="flex:1; text-align:center;">
        <div style="font-size:32px; font-family:'JetBrains Mono'; color:{ACCENT}; font-weight:700;">{len(all_perms)}</div>
        <div style="color:{TEXT_SEC}; font-size:12px; margin-top:4px;">Total Permissions</div>
      </div>
      <div class="card" style="flex:1; text-align:center;">
        <div style="font-size:32px; font-family:'JetBrains Mono'; color:{RED}; font-weight:700;">{sum(1 for p in high_risk if p['risk']=='CRITICAL')}</div>
        <div style="color:{TEXT_SEC}; font-size:12px; margin-top:4px;">Critical Risk</div>
      </div>
      <div class="card" style="flex:1; text-align:center;">
        <div style="font-size:32px; font-family:'JetBrains Mono'; color:{ORANGE}; font-weight:700;">{sum(1 for p in high_risk if p['risk']=='HIGH')}</div>
        <div style="color:{TEXT_SEC}; font-size:12px; margin-top:4px;">High Risk</div>
      </div>
      <div class="card" style="flex:1; text-align:center;">
        <div style="font-size:32px; font-family:'JetBrains Mono'; color:{YELLOW}; font-weight:700;">{len(combos)}</div>
        <div style="color:{TEXT_SEC}; font-size:12px; margin-top:4px;">Dangerous Combos</div>
      </div>
    </div>""", unsafe_allow_html=True)

    col1, col2 = st.columns([3, 2])

    with col1:
        st.markdown('<div class="section-label">⚡ High-Risk Permissions Detected</div>', unsafe_allow_html=True)
        if high_risk:
            for p in sorted(high_risk, key=lambda x: {"CRITICAL":0,"HIGH":1,"MEDIUM":2,"LOW":3}.get(x["risk"],4)):
                rc = {"CRITICAL": RED, "HIGH": ORANGE, "MEDIUM": YELLOW, "LOW": GREEN}.get(p["risk"], TEXT_SEC)
                st.markdown(f"""
                <div class="card" style="margin-bottom:8px; border-left: 3px solid {rc};">
                  <div style="display:flex; justify-content:space-between; align-items:center;">
                    <code>{p['permission']}</code>
                    <span class="perm-pill perm-{p['risk'].lower()}">{p['risk']}</span>
                  </div>
                  <div style="color:{TEXT_SEC}; font-size:12px; margin-top:6px;">⚠ {p['reason']}</div>
                </div>""", unsafe_allow_html=True)
        else:
            st.markdown(alert_box("INFO", "✅", "No high-risk individual permissions found."), unsafe_allow_html=True)

        st.markdown('<div class="section-label">💣 Dangerous Permission Combinations</div>', unsafe_allow_html=True)
        if combos:
            for combo in combos:
                rc = {"CRITICAL": RED, "HIGH": ORANGE}.get(combo["severity"], YELLOW)
                families = ", ".join(combo.get("families", []))
                matched_html = "".join(perm_pill(p.split(".")[-1], "HIGH") for p in combo["matched_permissions"])
                st.markdown(f"""
                <div class="card" style="border-left: 3px solid {rc}; margin-bottom:10px;">
                  <div style="display:flex; justify-content:space-between; align-items:flex-start;">
                    <div>
                      <div style="font-weight:600; color:{rc}; margin-bottom:4px;">{combo['name']}</div>
                      <div style="font-size:12px; color:{TEXT_SEC}; margin-bottom:8px;">{combo['description']}</div>
                      <div>{matched_html}</div>
                    </div>
                    <span class="perm-pill perm-{combo['severity'].lower()}">{combo['severity']}</span>
                  </div>
                  <div style="margin-top:10px; font-size:11px; color:{TEXT_SEC};">
                    Seen in: <span style="color:{PURPLE};">{families}</span>
                    {f' · CVE: <code>{combo["cve"]}</code>' if combo.get("cve") else ""}
                    · Match: {combo['match_score']}
                  </div>
                </div>""", unsafe_allow_html=True)
        else:
            st.markdown(alert_box("INFO", "✅", "No dangerous permission combinations detected."), unsafe_allow_html=True)

    with col2:
        risk_counts = {}
        for p in high_risk:
            risk_counts[p["risk"]] = risk_counts.get(p["risk"], 0) + 1
        other = len(all_perms) - len(high_risk)
        if other > 0:
            risk_counts["NORMAL"] = other

        if risk_counts:
            color_map = {"CRITICAL": RED, "HIGH": ORANGE, "MEDIUM": YELLOW, "LOW": GREEN, "NORMAL": TEXT_SEC}
            fig = go.Figure(go.Pie(
                labels=list(risk_counts.keys()),
                values=list(risk_counts.values()),
                hole=0.6,
                marker={"colors": [color_map.get(k, ACCENT) for k in risk_counts.keys()],
                        "line": {"color": DARK_BG, "width": 2}},
                textfont={"color": TEXT_PRI, "size": 11},
            ))
            fig.update_layout(
                paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
                height=280, margin=dict(t=10,b=10,l=10,r=10),
                legend={"font": {"color": TEXT_PRI, "size": 11}, "bgcolor": "rgba(0,0,0,0)"},
                showlegend=True,
                annotations=[{"text": "Permissions", "showarrow": False,
                              "font": {"color": TEXT_SEC, "size": 11}}]
            )
            st.plotly_chart(fig, use_container_width=True)

        st.markdown('<div class="section-label">📋 All Declared Permissions</div>', unsafe_allow_html=True)
        pills_html = ""
        for p in sorted(all_perms):
            risk = next((hr["risk"] for hr in high_risk if hr["permission"] == p), "NORMAL")
            pills_html += perm_pill(p.split(".")[-1], risk)
        st.markdown(f'<div class="card">{pills_html}</div>', unsafe_allow_html=True)


def render_threats(report):
    families = report.get("family_matches", [])
    strings  = report.get("string_findings", [])
    zip_info = report.get("zip_contents", {})

    st.markdown('<div class="section-label">☠️ Malware Family Similarity</div>', unsafe_allow_html=True)
    if families:
        for fam in families:
            rc = risk_color(fam["match_score"])
            matched = ", ".join(fam["matched_permissions"])
            st.markdown(f"""
            <div class="family-card">
              <div style="display:flex; justify-content:space-between; align-items:flex-start;">
                <div class="family-name">☠ {fam['family']}</div>
                <span class="perm-pill perm-critical">{fam['severity']}</span>
              </div>
              <div style="font-size:12px; color:{TEXT_SEC}; margin:6px 0;">{fam['description']}</div>
              <div class="match-bar"><div class="match-fill" style="width:{fam['match_score']}%;"></div></div>
              <div style="display:flex; justify-content:space-between; font-size:11px; color:{TEXT_SEC};">
                <span>Match: <span style="color:{rc}; font-weight:600;">{fam['match_score']}%</span></span>
                <span>Source: {fam['source']}</span>
              </div>
              <div style="font-size:11px; color:{TEXT_SEC}; margin-top:8px;">
                Matched permissions: <span style="color:{ORANGE};">{matched}</span>
              </div>
              {f'<div style="font-size:11px; color:{TEXT_SEC}; margin-top:4px;">Missing: <span style="color:{BORDER};">{", ".join(fam["missing_permissions"])}</span></div>' if fam["missing_permissions"] else ""}
            </div>""", unsafe_allow_html=True)
    else:
        st.markdown(alert_box("INFO", "✅", "No significant similarity to known malware families."), unsafe_allow_html=True)

    st.markdown('<div class="section-label">🔍 Suspicious Code Patterns in DEX</div>', unsafe_allow_html=True)
    valid_findings = [f for f in strings if "error" not in f]
    if valid_findings:
        for f in sorted(valid_findings, key=lambda x: {"CRITICAL":0,"HIGH":1,"MEDIUM":2}.get(x["severity"],3)):
            rc_f = {"CRITICAL": RED, "HIGH": ORANGE, "MEDIUM": YELLOW}.get(f["severity"], TEXT_SEC)
            samples = ", ".join(f'<code>{s}</code>' for s in f.get("sample_matches", [])[:2])
            st.markdown(f"""
            <div class="card" style="border-left: 3px solid {rc_f}; margin-bottom:8px;">
              <div style="display:flex; justify-content:space-between; align-items:center;">
                <span style="font-weight:600; color:{rc_f};">{f['description']}</span>
                <span class="perm-pill perm-{f['severity'].lower()}">{f['severity']}</span>
              </div>
              <div style="font-size:11px; color:{TEXT_SEC}; margin-top:6px;">
                Found in: <code>{f['found_in']}</code> · Matches: {samples}
              </div>
            </div>""", unsafe_allow_html=True)
    else:
        st.markdown(alert_box("INFO", "✅", "No suspicious code patterns found in DEX bytecode."), unsafe_allow_html=True)

    st.markdown('<div class="section-label">📦 Structural Anomalies</div>', unsafe_allow_html=True)
    anom = []
    if zip_info.get("multi_dex"):
        anom.append(alert_box("HIGH", "⚠️", f"Multi-DEX app — {len(zip_info['dex_files'])} DEX files. Legitimate apps rarely need more than 2; malware uses multi-DEX to split payloads and evade detection."))
    for sf in zip_info.get("suspicious_files", []):
        anom.append(alert_box(sf["severity"], "⚠️", f"<code>{sf['file']}</code> — {sf['reason']}"))
    if anom:
        for a in anom:
            st.markdown(a, unsafe_allow_html=True)
    else:
        st.markdown(alert_box("INFO", "✅", "No structural anomalies detected."), unsafe_allow_html=True)


def render_network(report):
    net = report.get("network", {})
    urls = net.get("urls", [])
    ips  = net.get("ips", [])
    doms = net.get("domains", [])
    susp = net.get("suspicious_domains", [])

    st.markdown(f"""
    <div style="display:flex; gap:16px; margin-bottom:20px;">
      <div class="card" style="flex:1; text-align:center;">
        <div style="font-size:28px; font-family:'JetBrains Mono'; color:{ACCENT}; font-weight:700;">{len(urls)}</div>
        <div style="color:{TEXT_SEC}; font-size:12px;">Embedded URLs</div>
      </div>
      <div class="card" style="flex:1; text-align:center;">
        <div style="font-size:28px; font-family:'JetBrains Mono'; color:{ORANGE}; font-weight:700;">{len(ips)}</div>
        <div style="color:{TEXT_SEC}; font-size:12px;">IP Addresses</div>
      </div>
      <div class="card" style="flex:1; text-align:center;">
        <div style="font-size:28px; font-family:'JetBrains Mono'; color:{PURPLE}; font-weight:700;">{len(doms)}</div>
        <div style="color:{TEXT_SEC}; font-size:12px;">Unique Domains</div>
      </div>
      <div class="card" style="flex:1; text-align:center;">
        <div style="font-size:28px; font-family:'JetBrains Mono'; color:{RED}; font-weight:700;">{len(susp)}</div>
        <div style="color:{TEXT_SEC}; font-size:12px;">Suspicious Domains</div>
      </div>
    </div>""", unsafe_allow_html=True)

    col1, col2 = st.columns(2)
    with col1:
        if susp:
            st.markdown('<div class="section-label">🚨 Suspicious Domains (Malware-Associated TLDs)</div>', unsafe_allow_html=True)
            for d in susp[:20]:
                st.markdown(alert_box("HIGH", "🌐", f"<code>{d}</code> — Suspicious TLD detected"), unsafe_allow_html=True)

        if ips:
            st.markdown('<div class="section-label">🌐 Embedded IP Addresses</div>', unsafe_allow_html=True)
            st.markdown(f'<div class="card">{"".join(f"<code>{ip}</code>&nbsp;" for ip in ips[:30])}</div>', unsafe_allow_html=True)

    with col2:
        if urls:
            st.markdown('<div class="section-label">🔗 Embedded URLs (first 20)</div>', unsafe_allow_html=True)
            url_html = ""
            for url in urls[:20]:
                url_html += f'<div style="font-family:JetBrains Mono; font-size:11px; color:{ACCENT}; padding:4px 0; border-bottom:1px solid {BORDER}; word-break:break-all;">{url}</div>'
            st.markdown(f'<div class="card">{url_html}</div>', unsafe_allow_html=True)

        if doms:
            st.markdown('<div class="section-label">🏢 All Unique Domains</div>', unsafe_allow_html=True)
            dom_html = "".join(f'<span class="perm-pill perm-normal">{d}</span>' for d in sorted(set(doms))[:40])
            st.markdown(f'<div class="card">{dom_html}</div>', unsafe_allow_html=True)


def render_certificate(report):
    cert_info = report.get("certificate", {})
    certs = cert_info.get("certificates", [])

    if not certs:
        st.markdown(alert_box("HIGH", "⚠️", "No certificates found or could not be parsed."), unsafe_allow_html=True)
        return

    for i, cert in enumerate(certs):
        rc = RED if cert.get("is_debug") else (ORANGE if cert.get("is_self_signed") else GREEN)
        label = "DEBUG SIGNED" if cert.get("is_debug") else ("SELF-SIGNED" if cert.get("is_self_signed") else "PRODUCTION")
        subj = cert.get("subject", {})
        rows = ""
        for k, v in subj.items():
            rows += meta_row(k, v)
        issuer = cert.get("issuer", {})
        for k, v in issuer.items():
            rows += meta_row(f"Issuer {k}", v)
        rows += meta_row("Not Before", cert.get("not_before", "—"))
        rows += meta_row("Not After", cert.get("not_after", "—"))
        rows += meta_row("Self-Signed", "Yes ⚠️" if cert.get("is_self_signed") else "No")
        rows += meta_row("Debug Key", "Yes ⚠️" if cert.get("is_debug") else "No")

        st.markdown(f"""
        <div class="card" style="border-top: 3px solid {rc};">
          <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:14px;">
            <div class="card-title" style="margin-bottom:0;"><span class="dot"></span>🔐 Certificate #{i+1}</div>
            <span class="perm-pill" style="background:rgba(0,0,0,0.3); border-color:{rc}; color:{rc};">{label}</span>
          </div>
          {rows}
        </div>""", unsafe_allow_html=True)

    hints = cert_info.get("developer_hints", [])
    if hints:
        st.markdown('<div class="section-label">👤 Developer Hints from Certificate</div>', unsafe_allow_html=True)
        for hint in hints:
            icon = "⚠️" if "⚠️" in hint else "ℹ️"
            level = "HIGH" if "⚠️" in hint else "INFO"
            st.markdown(alert_box(level, icon, hint), unsafe_allow_html=True)


def render_developer(report):
    dev = report.get("developer", {})
    clues = dev.get("identity_clues", [])
    flags = dev.get("red_flags", [])
    links = dev.get("store_links", [])

    conf_color = {"HIGH": GREEN, "MEDIUM": YELLOW, "LOW": ORANGE}.get(dev.get("confidence","LOW"), RED)

    col1, col2 = st.columns([3, 2])
    with col1:
        rows = ""
        rows += meta_row("Package Name", f'<code>{dev.get("package_name","—")}</code>')
        rows += meta_row("Identification Confidence", f'<span style="color:{conf_color}; font-weight:600;">{dev.get("confidence","LOW")}</span>')
        st.markdown(card("👤", "Developer Identity", rows), unsafe_allow_html=True)

        st.markdown('<div class="section-label">🔎 Identity Clues</div>', unsafe_allow_html=True)
        if clues:
            clue_html = ""
            for attr, val, source in clues:
                clue_html += f'<div class="dev-clue"><span class="dev-source">{source}</span><div><span style="color:{TEXT_SEC};">{attr}: </span><span style="color:{TEXT_PRI}; font-weight:500;">{val}</span></div></div>'
            st.markdown(f'<div class="card">{clue_html}</div>', unsafe_allow_html=True)
        else:
            st.markdown(alert_box("INFO", "ℹ️", "No developer identity clues could be extracted."), unsafe_allow_html=True)

    with col2:
        if flags:
            st.markdown('<div class="section-label">🚩 Red Flags</div>', unsafe_allow_html=True)
            for f in flags:
                st.markdown(alert_box("HIGH", "🚩", f), unsafe_allow_html=True)

        if links:
            st.markdown('<div class="section-label">🔗 Lookup Links</div>', unsafe_allow_html=True)
            for link in links:
                st.markdown(f"""
                <div class="card" style="margin-bottom:8px;">
                  <a href="{link}" target="_blank" style="color:{ACCENT}; font-size:12px; word-break:break-all; text-decoration:none;">
                    🔗 {link}
                  </a>
                </div>""", unsafe_allow_html=True)

        app = report.get("app_info", {})
        st.markdown('<div class="section-label">🧩 App Components</div>', unsafe_allow_html=True)
        for label, items in [
            ("Activities", app.get("activities",[])),
            ("Services", app.get("services",[])),
            ("Receivers", app.get("receivers",[])),
        ]:
            if items:
                html = f'<div style="color:{TEXT_SEC};font-size:11px;margin-bottom:4px;">{label}</div>'
                html += "".join(f'<div style="font-size:11px;font-family:JetBrains Mono;color:{ACCENT};padding:3px 0;border-bottom:1px solid {BORDER};">{a}</div>' for a in items[:8])
                if len(items) > 8:
                    html += f'<div style="font-size:11px;color:{TEXT_SEC};margin-top:4px;">+{len(items)-8} more…</div>'
                st.markdown(f'<div class="card">{html}</div>', unsafe_allow_html=True)


def render_recommendations(report):
    recs  = report.get("recommendations", [])
    risk  = report.get("risk", {})
    families = report.get("family_matches", [])

    verdict = risk.get("verdict","UNKNOWN")
    vc = risk_color(risk.get("score",0))

    st.markdown(f"""
    <div class="card" style="border-top: 3px solid {vc}; margin-bottom:24px;">
      <div style="font-size:18px; font-weight:700; color:{vc}; margin-bottom:8px;">
        Final Verdict: {verdict}
      </div>
      <div style="font-size:13px; color:{TEXT_SEC}; line-height:1.7;">
        This APK received a risk score of <span style="color:{vc}; font-weight:600;">{risk.get('score',0)}/100</span>
        based on {len(report['permissions'].get('high_risk',[]))} high-risk permissions,
        {len(report.get('string_findings',[]))} suspicious code patterns,
        and {len(families)} malware family matches.
        {"No critical issues were found." if risk.get("score",0) < 25 else "Exercise extreme caution."}
      </div>
    </div>""", unsafe_allow_html=True)

    st.markdown('<div class="section-label">📋 Actionable Recommendations</div>', unsafe_allow_html=True)
    icon_map = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "INFO": "🔵"}
    for i, rec in enumerate(recs, 1):
        icon = icon_map.get(rec["level"], "⚪")
        st.markdown(f"""
        <div class="card" style="margin-bottom:8px;">
          <div style="display:flex; gap:12px; align-items:flex-start;">
            <span style="font-size:16px;">{icon}</span>
            <div>
              <span class="perm-pill perm-{rec['level'].lower()}">{rec['level']}</span>
              <div style="font-size:13px; color:{TEXT_PRI}; margin-top:6px; line-height:1.6;">{rec['action']}</div>
            </div>
          </div>
        </div>""", unsafe_allow_html=True)

    st.markdown('<div class="section-label">🛡️ MITRE ATT&CK for Mobile — Relevant Techniques</div>', unsafe_allow_html=True)
    techniques = []
    perm_all = [p.split(".")[-1] for p in report["permissions"].get("all", [])]
    if "READ_SMS" in perm_all or "RECEIVE_SMS" in perm_all:
        techniques.append(("T1412", "Capture SMS Messages", "Intercept OTPs and 2FA codes"))
    if "RECORD_AUDIO" in perm_all:
        techniques.append(("T1429", "Capture Audio", "Covert microphone access"))
    if "CAMERA" in perm_all:
        techniques.append(("T1512", "Capture Camera", "Covert video/photo capture"))
    if "ACCESS_FINE_LOCATION" in perm_all or "ACCESS_COARSE_LOCATION" in perm_all:
        techniques.append(("T1430", "Location Tracking", "Real-time GPS surveillance"))
    if "READ_CONTACTS" in perm_all:
        techniques.append(("T1432", "Access Contact List", "Harvest device contacts"))
    if "BIND_ACCESSIBILITY_SERVICE" in perm_all:
        techniques.append(("T1418", "Exploit Accessibility", "Screen reader/UI manipulation"))
    if "INSTALL_PACKAGES" in perm_all:
        techniques.append(("T1544", "Remote File Copy", "Download and install payloads"))
    if not techniques:
        techniques.append(("T1407", "Download New Code at Runtime", "General dynamic loading risk"))

    rows = ""
    for tid, name, desc in techniques:
        rows += f"""
        <div style="display:flex; gap:16px; padding:8px 0; border-bottom:1px solid {BORDER}; align-items:center;">
          <code style="color:{PURPLE}; white-space:nowrap;">{tid}</code>
          <div>
            <div style="font-size:13px; font-weight:500; color:{TEXT_PRI};">{name}</div>
            <div style="font-size:11px; color:{TEXT_SEC};">{desc}</div>
          </div>
        </div>"""
    st.markdown(f'<div class="card">{rows}</div>', unsafe_allow_html=True)


# ─────────────────────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────────────────────

# Header
st.markdown("""
<div class="apk-header">
  <div style="margin-bottom:10px;">
    <span class="badge">STATIC ANALYSIS</span>
    <span class="badge">NO API</span>
    <span class="badge">EDUCATIONAL</span>
  </div>
  <h1>🔬 APK Security Analyzer</h1>
  <div class="tagline">// Deep static analysis · Threat intelligence · Developer identification</div>
</div>""", unsafe_allow_html=True)

# Upload
st.markdown("""
<div class="card">
  <div class="card-title"><span class="dot"></span>📂 Upload APK File</div>
  <div style="color:#8b949e; font-size:13px; margin-bottom:12px;">
    Drop an Android application package (.apk) to begin analysis.
    The file is processed entirely locally — no data is sent to external servers.
  </div>
</div>""", unsafe_allow_html=True)

uploaded = st.file_uploader(
    "Drop APK here",
    type=["apk"],
    label_visibility="collapsed",
)

if not uploaded:
    st.markdown(f"""
    <div style="margin-top:32px; text-align:center; padding:48px;">
      <div style="font-size:64px; margin-bottom:16px;">🔬</div>
      <div style="font-size:16px; color:{TEXT_PRI}; font-weight:600; margin-bottom:8px;">Upload an APK to begin</div>
      <div style="font-size:13px; color:{TEXT_SEC}; max-width:480px; margin:0 auto; line-height:1.7;">
        The analyzer performs deep static analysis including permission profiling,
        DEX bytecode scanning, certificate inspection, malware family comparison,
        and developer identification — all without any external API calls.
      </div>
      <div style="margin-top:32px; display:flex; justify-content:center; gap:32px;">
        <div style="text-align:center;">
          <div style="font-size:24px;">🔐</div>
          <div style="font-size:12px; color:{TEXT_SEC}; margin-top:4px;">Permission Analysis</div>
        </div>
        <div style="text-align:center;">
          <div style="font-size:24px;">☠️</div>
          <div style="font-size:12px; color:{TEXT_SEC}; margin-top:4px;">Malware Similarity</div>
        </div>
        <div style="text-align:center;">
          <div style="font-size:24px;">🌐</div>
          <div style="font-size:12px; color:{TEXT_SEC}; margin-top:4px;">Network Indicators</div>
        </div>
        <div style="text-align:center;">
          <div style="font-size:24px;">👤</div>
          <div style="font-size:12px; color:{TEXT_SEC}; margin-top:4px;">Developer ID</div>
        </div>
        <div style="text-align:center;">
          <div style="font-size:24px;">📋</div>
          <div style="font-size:12px; color:{TEXT_SEC}; margin-top:4px;">Recommendations</div>
        </div>
      </div>
    </div>""", unsafe_allow_html=True)
    st.stop()

# ── Analyse ──
with tempfile.NamedTemporaryFile(suffix=".apk", delete=False) as tmp:
    tmp.write(uploaded.read())
    tmp_path = tmp.name

progress_bar = st.progress(0)
status_text  = st.empty()

def update_progress(step, total, msg):
    progress_bar.progress(step / total)
    status_text.markdown(
        f'<div style="font-family:JetBrains Mono; font-size:12px; color:{TEXT_SEC};">'
        f'[{step}/{total}] {msg}</div>',
        unsafe_allow_html=True
    )

with st.spinner(""):
    report = analyze_apk(tmp_path, progress_callback=update_progress)

progress_bar.empty()
status_text.empty()
os.unlink(tmp_path)

if not report.get("success"):
    st.markdown(alert_box("CRITICAL", "❌",
        f"Analysis failed: {report.get('error','Unknown error')}. "
        "Ensure the file is a valid APK and androguard is installed."),
        unsafe_allow_html=True)
    if "traceback" in report:
        with st.expander("Technical details"):
            st.code(report["traceback"])
    st.stop()

# ── Tabs ──
tab1, tab2, tab3, tab4, tab5, tab6, tab7 = st.tabs([
    "📊 Overview",
    "🔐 Permissions",
    "☠️ Threats",
    "🌐 Network",
    "🔏 Certificate",
    "👤 Developer",
    "📋 Report",
])

with tab1: render_overview(report)
with tab2: render_permissions(report)
with tab3: render_threats(report)
with tab4: render_network(report)
with tab5: render_certificate(report)
with tab6: render_developer(report)
with tab7:
    render_recommendations(report)
    st.divider()
    st.markdown('<div class="section-label">💾 Export Full Report (JSON)</div>', unsafe_allow_html=True)
    json_str = json.dumps(report, indent=2, default=str)
    st.download_button(
        label="⬇️ Download JSON Report",
        data=json_str,
        file_name=f"apk_analysis_{report['file_info']['filename']}.json",
        mime="application/json",
    )
    with st.expander("📄 Raw JSON Report"):
        st.code(json_str, language="json")
