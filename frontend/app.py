"""
URL Shield AI - Streamlit frontend.
Talks to the FastAPI backend (BACKEND_URL) and shows the thesis evaluation reports.
"""
import html
import io
import json
import os

import altair as alt
import pandas as pd
import requests
import streamlit as st

BACKEND_URL = os.getenv("BACKEND_URL", "http://127.0.0.1:8000").rstrip("/")
REQUEST_TIMEOUT = 15
PROJECT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REPORTS_DIR = os.getenv("REPORTS_DIR", os.path.join(PROJECT_DIR, "reports"))
THESIS_TITLE = "Design and Implementation of a Machine Learning Based System for Malicious URL Detection"

EXAMPLES = {
    "Google": "google.com",
    "Fake PayPal": "http://paypal.com.account-verify.tk/webscr?cmd=login",
    "Malware": "http://45.13.22.8/bins/mozi.arm7",
    "Wikipedia": "https://en.wikipedia.org/wiki/Phishing",
}

RISK_STYLE = {
    "low": {"tone": "safe", "label": "Safe",
            "text": "No strong indicators of a malicious link were found."},
    "medium": {"tone": "warn", "label": "Suspicious",
               "text": "Some characteristics are typical of malicious links. Open it only if you trust the sender."},
    "high": {"tone": "danger", "label": "Malicious",
             "text": "Strong characteristics of phishing or malware links. Do not open it."},
}

st.set_page_config(page_title="URL Shield", page_icon="🛡️", layout="wide")


def render_html(block: str) -> None:
    """Render raw HTML (lines are stripped so Markdown never turns them into code blocks)."""
    st.markdown(" ".join(line.strip() for line in block.splitlines() if line.strip()), unsafe_allow_html=True)


# --------------------------------------------------------------------------- styles
# Layout: instrument-panel UI - quiet cool neutrals, one teal accent, monospace for anything that is a URL or a number.
render_html("""
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Instrument+Sans:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
<style>
:root {
  --bg: #F5F7F6; --surface: #FFFFFF; --ink: #0F1B1A; --muted: #5A6B68; --line: #DCE3E1;
  --accent: #0B6E69; --accent-soft: #E3F1EF;
  --safe: #15803D; --safe-soft: #E9F6EE; --warn: #B45309; --warn-soft: #FDF3E6;
  --danger: #B91C1C; --danger-soft: #FCEDED;
  --font-ui: 'Instrument Sans', 'Helvetica Neue', Arial, sans-serif;
  --font-mono: 'JetBrains Mono', ui-monospace, 'SF Mono', Menlo, monospace;
}
html, body, .stApp, .stMarkdown, .stTextInput input, .stTextArea textarea, button, [data-testid="stMetric"] {
  font-family: var(--font-ui) !important; }
.stApp { background: var(--bg); color: var(--ink); }
.block-container { padding-top: 3.4rem; max-width: 1120px; }
/* Streamlit's own top strip: keep it transparent so it never covers the page's top bar */
header[data-testid="stHeader"] { background: transparent; height: 2.75rem; pointer-events: none; }
header[data-testid="stHeader"] * { pointer-events: auto; }
h1, h2, h3 { text-wrap: balance; letter-spacing: -0.015em; }
code, .mono { font-family: var(--font-mono) !important; }
[data-testid="stMetricValue"] { font-family: var(--font-mono) !important; font-size: 1.35rem; font-variant-numeric: tabular-nums; }
[data-testid="stMetricLabel"] p { font-size: .74rem; text-transform: uppercase; letter-spacing: .07em; color: var(--muted); }
.stTabs [data-baseweb="tab-list"] { gap: 26px; border-bottom: 1px solid var(--line); }
.stTabs [data-baseweb="tab"] { padding: 10px 0; font-weight: 600; }
.stTabs [data-baseweb="tab"] p { font-size: .95rem; }
.stTextInput input { font-family: var(--font-mono) !important; font-size: .92rem; }
section[data-testid="stSidebar"] { background: var(--surface); border-right: 1px solid var(--line); }

/* top bar */
.topbar { display:flex; align-items:center; justify-content:space-between; gap:16px; flex-wrap:wrap;
  padding: 4px 0 14px; border-bottom: 1px solid var(--line); }
.brand { display:flex; align-items:center; gap:10px; font-weight:700; font-size:1.05rem; letter-spacing:-.01em; }
.brand svg { display:block; }
.status { display:flex; gap:8px; flex-wrap:wrap; font-family: var(--font-mono); font-size:.74rem; color: var(--muted); }
.status span { border:1px solid var(--line); background: var(--surface); padding: 3px 9px; border-radius: 4px; }
.status .live::before { content:""; display:inline-block; width:7px; height:7px; border-radius:50%;
  background: var(--safe); margin-right:7px; vertical-align: 1px; animation: pulse 2.4s ease-in-out infinite; }
.status .down::before { content:""; display:inline-block; width:7px; height:7px; border-radius:50%;
  background: var(--danger); margin-right:7px; vertical-align: 1px; }

/* hero */
.hero { display:grid; grid-template-columns: minmax(0, 1fr) minmax(0, 1.25fr); gap: 40px; align-items:center;
  padding: 34px 0 30px; }
.eyebrow { font-family: var(--font-mono); font-size:.72rem; letter-spacing:.12em; text-transform:uppercase; color: var(--accent); }
.hero h1 { font-size: clamp(2rem, 3.6vw, 2.9rem); line-height: 1.05; font-weight: 700; margin: 10px 0 14px; color: var(--ink); padding:0; }
.hero p.lede { color: var(--muted); font-size: 1rem; line-height: 1.55; max-width: 46ch; margin: 0 0 14px; }
.hero .thesis { font-size: .82rem; color: var(--ink); border-top: 1px solid var(--line); padding-top: 12px; max-width: 52ch; line-height:1.5; }
.hero .thesis b { font-weight: 600; }

/* URL anatomy specimen */
.specimen { background: var(--ink); color: #E6EEEC; border-radius: 10px; padding: 20px 22px 18px; position: relative; overflow: hidden; }
.specimen .head { display:flex; justify-content:space-between; font-family: var(--font-mono); font-size:.7rem;
  color:#8FA5A1; letter-spacing:.06em; text-transform:uppercase; margin-bottom: 16px; }
.specimen .head b { color:#F2A3A3; font-weight:600; }
.anatomy-url { font-family: var(--font-mono); font-size: clamp(.82rem, 1.3vw, 1rem); line-height: 1.9; word-break: break-all; }
.anatomy-url span { border-bottom: 2px solid currentColor; padding-bottom: 2px; }
.anatomy-url .n { color:#6F8783; } .anatomy-url .f { color:#F59E8B; } .anatomy-url .w { color:#F6C177; }
.anatomy-url .o { color:#9FD8C9; }
.parts { margin-top: 16px; display:grid; grid-template-columns: auto auto minmax(0,1fr); gap: 7px 16px;
  font-family: var(--font-mono); font-size: .72rem; align-items: baseline; }
.parts .k { color:#8FA5A1; text-transform: uppercase; letter-spacing: .06em; font-size: .64rem; }
.parts .v { white-space: nowrap; } .parts .s { color:#B9C9C6; }
.parts .f { color:#F59E8B; } .parts .w { color:#F6C177; } .parts .n { color:#6F8783; } .parts .o { color:#9FD8C9; }
.parts .v { max-width: 22ch; overflow: hidden; text-overflow: ellipsis; }
.specimen .head .tag-safe { color:#86EFAC; } .specimen .head .tag-warn { color:#FCD34D; } .specimen .head .tag-danger { color:#FCA5A5; }
.specimen .head .tag-sample { color:#8FA5A1; }
.specimen .meter i.safe { background:#86EFAC; } .specimen .meter i.warn { background:#FCD34D; } .specimen .meter i.danger { background:#F59E8B; }
.parts > * { animation: rise .45s ease-out both; }
.parts > :nth-child(n+4) { animation-delay: .12s } .parts > :nth-child(n+7) { animation-delay: .24s }
.parts > :nth-child(n+10) { animation-delay: .36s } .parts > :nth-child(n+13) { animation-delay: .48s }
.parts > :nth-child(n+16) { animation-delay: .6s }
.scan { position:absolute; top:0; bottom:0; width: 90px; left:-90px; pointer-events:none;
  background: linear-gradient(90deg, transparent, rgba(124, 214, 204, .10), transparent);
  animation: scan 5.5s ease-in-out 1s infinite; }
.specimen .foot { margin-top: 16px; display:flex; align-items:center; gap: 12px; font-family: var(--font-mono); font-size:.72rem; color:#8FA5A1; }
.specimen .meter { flex:1; height: 6px; border-radius: 3px; background: #24302E; position:relative; overflow:hidden; }
.specimen .meter i { position:absolute; inset:0 auto 0 0; background: #F59E8B; border-radius: 3px;
  transform-origin:left; animation: draw 1.1s cubic-bezier(.2,.7,.2,1) .9s both; }
.specimen .foot b { color:#FFD9D1; font-weight:600; }

@keyframes draw { from { transform: scaleX(0); } to { transform: scaleX(1); } }
@keyframes scan { 0% { left:-90px; } 60%, 100% { left: 100%; } }
@keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: .35; } }
@keyframes rise { from { opacity: .25; transform: translateY(4px); } to { opacity: 1; transform: none; } }
@media (prefers-reduced-motion: reduce) { *, *::before { animation: none !important; } }
@media (max-width: 820px) { .hero { grid-template-columns: 1fr; gap: 24px; padding-top: 22px; } }

/* section titles */
.section-title { font-weight: 600; font-size: .78rem; text-transform: uppercase; letter-spacing: .09em; color: var(--muted); margin: 18px 0 10px; }
.small-muted { color: var(--muted); font-size: .82rem; }
.examples { font-size: .8rem; color: var(--muted); padding-top: 9px; }

/* verdict */
.verdict { display:grid; grid-template-columns: minmax(0,1fr) auto; gap: 8px 24px; align-items:end;
  border: 1px solid var(--line); border-radius: 8px; padding: 20px 22px; margin: 14px 0 6px;
  background: var(--surface); animation: rise .35s ease-out; }
.verdict .state { display:flex; align-items:center; gap:10px; font-weight:700; font-size: 1.5rem; letter-spacing:-.01em; }
.verdict .state i { width: 12px; height: 12px; border-radius: 50%; display:inline-block; }
.verdict .desc { color: var(--muted); font-size: .92rem; grid-column: 1 / 2; }
.verdict .url { grid-column: 1 / -1; font-family: var(--font-mono); font-size: .82rem; color: var(--ink);
  word-break: break-all; padding-top: 10px; border-top: 1px dashed var(--line); margin-top: 6px; }
.verdict .prob { grid-row: 1 / 3; grid-column: 2; text-align:right; font-family: var(--font-mono); font-variant-numeric: tabular-nums; }
.verdict .prob b { font-size: 2.4rem; font-weight: 600; line-height: 1; display:block; }
.verdict .prob span { font-size: .7rem; color: var(--muted); text-transform: uppercase; letter-spacing: .08em; }
.tone-safe .state, .tone-safe .prob b { color: var(--safe); } .tone-safe .state i { background: var(--safe); }
.tone-safe { background: var(--safe-soft); border-color: #C5E6D1; }
.tone-warn .state, .tone-warn .prob b { color: var(--warn); } .tone-warn .state i { background: var(--warn); }
.tone-warn { background: var(--warn-soft); border-color: #F3D9B5; }
.tone-danger .state, .tone-danger .prob b { color: var(--danger); } .tone-danger .state i { background: var(--danger); }
.tone-danger { background: var(--danger-soft); border-color: #F1C9C9; }

/* segmented risk scale with thresholds */
.scale { margin: 18px 0 4px; }
.scale .track { position: relative; display:grid; grid-template-columns: 40fr 30fr 30fr; gap: 3px; height: 10px; }
.scale .track span { border-radius: 2px; }
.scale .track span:nth-child(1) { background: #BFE3CC; } .scale .track span:nth-child(2) { background: #F3D9B5; }
.scale .track span:nth-child(3) { background: #F1C2C2; }
.scale .pin { position:absolute; top:-6px; width: 3px; height: 22px; background: var(--ink); border-radius: 2px;
  transform: translateX(-1px); animation: slide .6s cubic-bezier(.2,.7,.2,1); }
.scale .ticks { display:grid; grid-template-columns: 40fr 30fr 30fr; font-family: var(--font-mono); font-size: .68rem; color: var(--muted); margin-top: 6px; }
@keyframes slide { from { left: 0; } }

/* diverging explanation chart */
.why { border: 1px solid var(--line); background: var(--surface); border-radius: 8px; padding: 14px 18px 10px; }
.why .row { display:grid; grid-template-columns: minmax(0, 1.25fr) minmax(0, 1fr) 64px; gap: 14px; align-items:center;
  padding: 8px 0; border-bottom: 1px solid #EEF2F1; }
.why .row:last-child { border-bottom: 0; }
.why .name { font-size: .9rem; } .why .name small { display:block; font-family: var(--font-mono); color: var(--muted); font-size: .74rem; }
.why .axis { position: relative; height: 12px; }
.why .axis::before { content:""; position:absolute; left:50%; top:-6px; bottom:-6px; width:1px; background: var(--line); }
.why .bar { position:absolute; top:0; height: 12px; border-radius: 2px; animation: grow .5s ease-out; }
.why .bar.up { left: 50%; background: var(--danger); transform-origin:left; }
.why .bar.down { right: 50%; background: var(--safe); transform-origin:right; }
.why .val { font-family: var(--font-mono); font-size: .8rem; text-align:right; font-variant-numeric: tabular-nums; }
.why .legend { display:flex; justify-content:space-between; font-size:.72rem; color: var(--muted); padding: 2px 0 6px; }
@keyframes grow { from { transform: scaleX(0); } }

/* known-domain note under the verdict */
.known { display:flex; gap:10px; align-items:flex-start; border:1px solid #C5E6D1; background:#F4FBF6; border-radius:8px;
  padding:10px 14px; margin:8px 0 2px; font-size:.86rem; color: var(--ink); }
.known b { font-family: var(--font-mono); font-weight:600; }
.known .badge { font-family: var(--font-mono); font-size:.66rem; letter-spacing:.08em; text-transform:uppercase;
  background: var(--safe); color:#fff; border-radius:3px; padding:2px 7px; white-space:nowrap; margin-top:2px; }
.panel { border:1px solid var(--line); background: var(--surface); border-radius:8px; padding:14px 18px 6px; }
</style>
""")


# --------------------------------------------------------------------------- API helpers
def api_get(path):
    try:
        r = requests.get(f"{BACKEND_URL}{path}", timeout=REQUEST_TIMEOUT)
        return r.json() if r.status_code == 200 else None
    except requests.exceptions.RequestException:
        return None


def api_post(path, payload):
    """Returns (data, error_message)."""
    try:
        r = requests.post(f"{BACKEND_URL}{path}", json=payload, timeout=REQUEST_TIMEOUT)
    except requests.exceptions.ConnectionError:
        return None, f"Could not reach the backend at {BACKEND_URL}. Start it with `uvicorn app.main:app`."
    except requests.exceptions.Timeout:
        return None, "The backend did not respond in time."
    if r.status_code == 200:
        return r.json(), None
    try:
        detail = r.json().get("detail", r.text)
    except ValueError:
        detail = r.text
    if r.status_code == 503:
        return None, f"The model is not available on the server: {detail}"
    if r.status_code == 422:
        return None, f"Invalid input: {detail}"
    return None, f"Backend error ({r.status_code}): {detail}"


@st.cache_data(ttl=30)
def get_model_info():
    return api_get("/model-info")


def esc(x):
    return html.escape(str(x))


# --------------------------------------------------------------------------- sidebar
info = get_model_info()
with st.sidebar:
    if info:
        st.markdown("<div class='section-title' style='margin-top:4px'>Deployed model</div>", unsafe_allow_html=True)
        st.markdown(f"**{esc(info.get('model_name', '?'))}** · {esc(info.get('run_name', ''))} run")
        if info.get("demo"):
            st.warning("Demo model trained on toy data - results are not meaningful.")
        st.caption(f"{info.get('n_samples') or 0:,} URLs (+{info.get('n_augmented') or 0:,} Tranco, "
                   f"{info.get('n_relabeled') or 0:,} relabelled) · "
                   f"{info.get('n_features', '?')} features · {info.get('trained_at', '')}")
        m = info.get("metrics") or {}
        if m:
            c1, c2 = st.columns(2)
            c1.metric("F1", f"{m.get('f1', 0):.3f}")
            c2.metric("ROC-AUC", f"{m.get('roc_auc', 0):.3f}")
            c1.metric("Precision", f"{m.get('precision', 0):.3f}")
            c2.metric("Recall", f"{m.get('recall', 0):.3f}")
        th = info.get("thresholds") or {"medium": 0.4, "high": 0.7}
        st.divider()
        st.markdown("<div class='section-title'>Risk levels</div>", unsafe_allow_html=True)
        render_html(f"""
        <div style="display:grid;gap:6px;font-size:.88rem">
        <div><span style="display:inline-block;width:9px;height:9px;border-radius:50%;background:var(--safe);margin-right:8px"></span>Safe <span class="mono small-muted">&lt; {th['medium']:.0%}</span></div>
        <div><span style="display:inline-block;width:9px;height:9px;border-radius:50%;background:var(--warn);margin-right:8px"></span>Suspicious <span class="mono small-muted">{th['medium']:.0%}–{th['high']:.0%}</span></div>
        <div><span style="display:inline-block;width:9px;height:9px;border-radius:50%;background:var(--danger);margin-right:8px"></span>Malicious <span class="mono small-muted">≥ {th['high']:.0%}</span></div>
        </div>""")
    else:
        st.info("Model information unavailable (backend offline or model not trained).")
    st.divider()
    st.caption("The URL is analysed statically: it is **never opened or downloaded**, "
               "so even live malware links can be checked safely.")

# --------------------------------------------------------------------------- header
SAMPLE_ANATOMY = [
    {"part": "scheme", "text": "http://", "level": "muted", "notes": ["not used by the model (dataset leakage)"]},
    {"part": "subdomain", "text": "paypal.com.", "level": "flag", "notes": ["brand name outside the real domain"]},
    {"part": "domain", "text": "account-verify", "level": "warn", "notes": ["keywords: verify, account", "1 hyphen(s)"]},
    {"part": "tld", "text": ".tk", "level": "flag", "notes": ["frequently abused top-level domain"]},
    {"part": "path", "text": "/webscr", "level": "flag", "notes": ["known PayPal phishing-kit path"]},
    {"part": "query", "text": "?cmd=login", "level": "warn", "notes": ["keywords: login"]},
]
LEVEL_CLASS = {"flag": "f", "warn": "w", "ok": "o", "muted": "n"}
TONE_CLASS = {"safe": "safe", "warn": "warn", "danger": "danger"}


def specimen(result):
    """URL anatomy card: the analysed URL split into parts, or a sample before the first analysis."""
    if result and result.get("anatomy"):
        parts, style = result["anatomy"], RISK_STYLE[result["risk_level"]]
        tag = f"<b class='tag-{style['tone']}'>{style['label']}</b>"
        if result.get("known_domain"):
            tag = f"<b class='tag-safe'>Safe · known domain</b>"
        p = result["malicious_probability"]
        foot = (f"<span>P(malicious)</span><div class='meter'><i class='{style['tone']}' "
                f"style='width:{p * 100:.1f}%'></i></div><b>{p:.2f}</b>")
    else:
        parts = SAMPLE_ANATOMY
        tag = "<b class='tag-sample'>Sample · phishing</b>"
        foot = "<span>Analyze a link below to see its own anatomy</span>"
    url_html = "".join(f"<span class='{LEVEL_CLASS.get(x['level'], 'n')}'>{esc(x['text'])}</span>" for x in parts)
    rows = "".join(
        f"<span class='k'>{esc(x['part'])}</span>"
        f"<span class='v {LEVEL_CLASS.get(x['level'], 'n')}' title='{esc(x['text'])}'>{esc(x['text'])}</span>"
        f"<span class='s'>{esc(' · '.join(x['notes']))}</span>" for x in parts)
    return (f"<div class='specimen' aria-label='Anatomy of the analysed URL'><div class='scan'></div>"
            f"<div class='head'><span>URL anatomy</span>{tag}</div>"
            f"<div class='anatomy-url'>{url_html}</div><div class='parts'>{rows}</div>"
            f"<div class='foot'>{foot}</div></div>")


specimen_html = specimen(st.session_state.get("last"))
n_feat = info.get("n_features", 33) if info else 33
model_name = (info or {}).get("model_name", "model offline")
status_cls, status_txt = ("live", "API online") if info else ("down", "API offline")
render_html(f"""
<div class="topbar">
  <div class="brand">
    <svg width="22" height="24" viewBox="0 0 22 24" fill="none" aria-hidden="true">
      <path d="M11 1.5 2.5 4.8v6.4c0 5.3 3.6 9.6 8.5 11.3 4.9-1.7 8.5-6 8.5-11.3V4.8L11 1.5Z" fill="#0B6E69"/>
      <path d="M6.5 12.2h3.2l1.4-3.4 2 6.4 1.4-3h1.9" stroke="#fff" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"/>
    </svg>
    URL Shield
  </div>
  <div class="status">
    <span class="{status_cls}">{status_txt}</span>
    <span>{esc(model_name)}</span>
    <span>{n_feat} features</span>
  </div>
</div>
<div class="hero">
  <div>
    <div class="eyebrow">MSc thesis · Computer Science · Vistula University</div>
    <h1>Read a link before you open it.</h1>
    <p class="lede">URL Shield breaks a web address into its parts and scores it with a machine learning model
    trained on 640,000 labelled URLs. The link itself is never visited.</p>
    <div class="thesis"><b>{THESIS_TITLE}</b><br>Akademia Finansów i Biznesu Vistula · Master of Engineering</div>
  </div>
  {specimen_html}
</div>
""")

tab_analyze, tab_batch, tab_eval, tab_about = st.tabs(
    ["Analyze a URL", "Batch analysis", "Model evaluation", "System design"])


# --------------------------------------------------------------------------- tab 1: single URL

LEVEL_COLORS = {"Safe": "#15803D", "Suspicious": "#B45309", "Malicious": "#B91C1C"}


def render_session_overview(history):
    """Summary of all URLs analysed in this session: counts per verdict, score distribution and table."""
    hist = pd.DataFrame(history)
    st.markdown("<div class='section-title' style='margin-top:26px'>Session overview</div>", unsafe_allow_html=True)
    k1, k2, k3, k4, k5 = st.columns(5)
    k1.metric("Analyzed", len(hist))
    for col, lvl in zip((k2, k3, k4), ("Safe", "Suspicious", "Malicious")):
        col.metric(lvl, int((hist["Verdict"] == lvl).sum()))
    k5.metric("Median response", f"{hist['Latency (ms)'].median():.0f} ms")

    c1, c2 = st.columns([2, 3])
    counts = (hist["Verdict"].value_counts().reindex(list(LEVEL_COLORS), fill_value=0)
              .rename_axis("Verdict").reset_index(name="URLs"))
    bars = alt.Chart(counts).mark_bar(cornerRadiusEnd=3).encode(
        x=alt.X("URLs:Q", axis=alt.Axis(tickMinStep=1, title="URLs")),
        y=alt.Y("Verdict:N", sort=list(LEVEL_COLORS), title=None, scale=alt.Scale(paddingInner=0.35)),
        color=alt.Color("Verdict:N", scale=alt.Scale(domain=list(LEVEL_COLORS), range=list(LEVEL_COLORS.values())),
                        legend=None),
        tooltip=["Verdict", "URLs"]).properties(height=170, title="Verdicts")
    c1.altair_chart(bars, use_container_width=True)

    pts = hist.assign(Short=hist["URL"].str.replace(r"^https?://", "", regex=True).str.slice(0, 38))
    dots = alt.Chart(pts).mark_circle(size=110, opacity=.9).encode(
        x=alt.X("Malicious probability:Q", scale=alt.Scale(domain=[0, 1]), axis=alt.Axis(format="%", title="Model probability (malicious)")),
        y=alt.Y("Short:N", sort="-x", title=None, axis=alt.Axis(labelOverlap=False, labelLimit=260)),
        color=alt.Color("Verdict:N", scale=alt.Scale(domain=list(LEVEL_COLORS), range=list(LEVEL_COLORS.values())),
                        legend=None),
        tooltip=["URL", "Verdict", alt.Tooltip("Malicious probability:Q", format=".1%"), "Known domain"])
    rules = alt.Chart(pd.DataFrame({"t": [0.4, 0.7]})).mark_rule(strokeDash=[4, 4], color="#5A6B68").encode(x="t:Q")
    c2.altair_chart((rules + dots).properties(height=max(170, 30 * len(pts)), title="Scores (dashed: 40% / 70% thresholds)"),
                    use_container_width=True)

    st.dataframe(hist, hide_index=True, column_config={"Malicious probability": st.column_config.ProgressColumn(
        format="percent", min_value=0.0, max_value=1.0)})
    b1, b2, _ = st.columns([1.3, 1, 3])
    b1.download_button("Download session (CSV)", hist.to_csv(index=False).encode("utf-8"),
                       "url_shield_session.csv", "text/csv", use_container_width=True)
    if b2.button("Clear history", use_container_width=True):
        st.session_state["history"] = []
        st.session_state.pop("last", None)
        st.rerun()


def render_threshold_explorer(curve, run):
    """Interactive view of the precision / recall trade-off of the decision threshold (test set)."""
    pts = pd.DataFrame(curve["points"])
    st.markdown("<div class='section-title' style='margin-top:26px'>Decision threshold explorer</div>",
                unsafe_allow_html=True)
    st.caption(f"Effect of the decision threshold on the {run} model, computed on the "
               f"{curve['n_positive'] + curve['n_negative']:,} test URLs. A lower threshold catches more malicious "
               "links but raises more false alarms. The dashed lines mark the 40% and 70% risk levels used in the app.")
    t = st.slider("Threshold (malicious probability)", 0.05, 0.95, 0.50, 0.01, key="thr")
    row = pts.iloc[(pts["threshold"] - t).abs().idxmin()]
    m1, m2, m3, m4 = st.columns(4)
    m1.metric("Precision", f"{row['precision']:.3f}")
    m2.metric("Recall", f"{row['recall']:.3f}")
    m3.metric("F1", f"{row['f1']:.3f}")
    m4.metric("False positive rate", f"{row['false_positive_rate']:.3f}")
    st.markdown(
        f"<div class='small-muted'>At {t:.0%}: <b>{int(row['tp']):,}</b> malicious URLs caught, "
        f"<b>{int(row['fn']):,}</b> missed, <b>{int(row['fp']):,}</b> false alarms on "
        f"{curve['n_negative']:,} benign URLs.</div>", unsafe_allow_html=True)
    long = pts.melt(id_vars="threshold", value_vars=["precision", "recall", "f1", "false_positive_rate"],
                    var_name="Metric", value_name="Value").replace(
        {"precision": "Precision", "recall": "Recall", "f1": "F1", "false_positive_rate": "False positive rate"})
    lines = alt.Chart(long).mark_line(strokeWidth=2.2).encode(
        x=alt.X("threshold:Q", axis=alt.Axis(format="%", title="Decision threshold")),
        y=alt.Y("Value:Q", scale=alt.Scale(domain=[0, 1]), title=None),
        color=alt.Color("Metric:N", scale=alt.Scale(
            domain=["Precision", "Recall", "F1", "False positive rate"],
            range=["#0B6E69", "#B45309", "#0F1B1A", "#B91C1C"]), legend=alt.Legend(orient="bottom", title=None)),
        tooltip=[alt.Tooltip("threshold:Q", format=".0%"), "Metric", alt.Tooltip("Value:Q", format=".3f")])
    levels = alt.Chart(pd.DataFrame({"t": [0.4, 0.7]})).mark_rule(strokeDash=[4, 4], color="#94a3b8").encode(x="t:Q")
    current = alt.Chart(pd.DataFrame({"t": [t]})).mark_rule(color="#0F1B1A", strokeWidth=1.5).encode(x="t:Q")
    st.altair_chart((levels + lines + current).properties(height=300), use_container_width=True)


def render_reasons(reasons):
    """Diverging bar chart: right = adds risk, left = removes risk, centred on zero."""
    max_imp = max(abs(r["impact"]) for r in reasons) or 1
    rows = ["<div class='why'><div class='legend'><span>lowers risk</span><span>raises risk</span></div>"]
    for r in sorted(reasons, key=lambda r: -r["impact"]):
        up = r["impact"] > 0
        width = max(2.0, abs(r["impact"]) / max_imp * 50)
        rows.append(
            f"<div class='row'><div class='name'>{esc(r['label'])}<small>{esc(r['value'])}</small></div>"
            f"<div class='axis'><div class='bar {'up' if up else 'down'}' style='width:{width:.1f}%'></div></div>"
            f"<div class='val' style='color:var(--{'danger' if up else 'safe'})'>"
            f"{'+' if up else '−'}{abs(r['impact']) * 100:.1f} pt</div></div>")
    rows.append("</div>")
    st.markdown("".join(rows), unsafe_allow_html=True)


def set_example(url):
    st.session_state["url_input"] = url


with tab_analyze:
    if "history" not in st.session_state:
        st.session_state["history"] = []

    with st.form("analyze_form", border=False):
        c1, c2 = st.columns([5, 1])
        url_input = c1.text_input("URL", key="url_input", label_visibility="collapsed",
                                  placeholder="Paste a link, e.g. https://example.com/login")
        submitted = c2.form_submit_button("Analyze", type="primary", use_container_width=True)

    ex_cols = st.columns([1.1] + [1] * len(EXAMPLES) + [1.6])
    ex_cols[0].markdown("<div class='examples'>Try a sample</div>", unsafe_allow_html=True)
    for col, (label, url) in zip(ex_cols[1:], EXAMPLES.items()):
        col.button(label, on_click=set_example, args=(url,), use_container_width=True)

    if submitted:
        if not url_input.strip():
            st.warning("Please enter a URL first.")
        else:
            with st.spinner("Analyzing..."):
                data, err = api_post("/predict", {"url": url_input.strip()})
            if err:
                st.error(err)
            else:
                st.session_state["last"] = data
                st.session_state["history"].insert(0, {
                    "URL": data["url"], "Verdict": RISK_STYLE[data["risk_level"]]["label"],
                    "Malicious probability": data["malicious_probability"],
                    "Known domain": data.get("known_domain") or "",
                    "Latency (ms)": data["latency_ms"]})
                st.rerun()   # redraw the header so the anatomy card shows this URL

    data = st.session_state.get("last")
    if data:
        style = RISK_STYLE.get(data.get("risk_level", "high"), RISK_STYLE["high"])
        p = data["malicious_probability"]
        known = data.get("known_domain")
        desc = ("Known legitimate domain. The score on the right is the lexical model's own estimate, "
                "shown for transparency." if known else style["text"])
        render_html(f"""
        <div class="verdict tone-{style['tone']}">
          <div class="state"><i></i>{style['label']}</div>
          <div class="prob"><b>{p * 100:.1f}%</b><span>{'model ' if known else ''}P(malicious)</span></div>
          <div class="desc">{desc}</div>
          <div class="url">{esc(data['url'])}</div>
        </div>
        <div class="scale">
          <div class="track"><span></span><span></span><span></span>
            <div class="pin" style="left:{p * 100:.1f}%"></div></div>
          <div class="ticks"><span>safe</span><span>suspicious · 40%</span><span>malicious · 70%</span></div>
        </div>
        """)
        if data.get("known_domain"):
            model_label = RISK_STYLE[data.get("model_risk_level", "low")]["label"]
            render_html(f"""
            <div class="known"><span class="badge">Known domain</span>
            <span><b>{esc(data['known_domain'])}</b> is one of the most popular legitimate websites (Tranco top
            {(info or {}).get('known_domains_top', 10000):,}), so the link is treated as safe. The lexical model alone
            would rate it <b>{model_label.lower()}</b> ({p * 100:.1f}%); the explanation below shows why.</span></div>""")

        st.write("")
        m1, m2, m3, m4 = st.columns(4)
        m1.metric("Model confidence", f"{data['confidence'] * 100:.1f}%")
        m2.metric("Response time", f"{data['latency_ms']:.0f} ms")
        m3.metric("Features checked", (info or {}).get("n_features", 33))
        m4.metric("Model", (info or {}).get("model_name", "-"))

        reasons = data.get("explanation") or []
        st.markdown("<div class='section-title' style='margin-top:14px'>Why this result?</div>",
                    unsafe_allow_html=True)
        if reasons:
            render_reasons(reasons)
            st.caption("Percentage points each characteristic adds to or removes from the malicious probability "
                       "(decision-path decomposition of the Random Forest). Only the strongest signals are shown.")
        else:
            st.caption("Explanations are available after retraining the model (`python -m app.train`).")

    if st.session_state["history"]:
        render_session_overview(st.session_state["history"])

# --------------------------------------------------------------------------- tab 2: batch
with tab_batch:
    st.markdown("<div class='section-title'>Analyze many URLs at once</div>", unsafe_allow_html=True)
    st.caption("Paste one URL per line or upload a .txt / .csv file (first column or a column named 'url'). "
               "Up to 200 URLs per run.")
    c1, c2 = st.columns([3, 2])
    text = c1.text_area("URLs", height=180, label_visibility="collapsed",
                        placeholder="https://github.com\nhttp://secure-update-billing.top/confirm/password.php\n...")
    uploaded = c2.file_uploader("Upload file", type=["txt", "csv"])

    if st.button("Run batch analysis", type="primary"):
        urls = [u.strip() for u in text.splitlines() if u.strip()]
        if uploaded is not None:
            raw = uploaded.getvalue().decode("utf-8", errors="ignore")
            if uploaded.name.lower().endswith(".csv"):
                df_in = pd.read_csv(io.StringIO(raw))
                col = next((c for c in df_in.columns if c.strip().lower() == "url"), df_in.columns[0])
                urls += df_in[col].dropna().astype(str).tolist()
            else:
                urls += [u.strip() for u in raw.splitlines() if u.strip()]
        urls = list(dict.fromkeys(urls))[:200]
        if not urls:
            st.warning("Please provide at least one URL.")
        else:
            with st.spinner(f"Analyzing {len(urls)} URLs..."):
                result, err = api_post("/predict/batch", {"urls": urls})
            if err:
                st.error(err)
            else:
                df = pd.DataFrame(result)
                df["Verdict"] = df["risk_level"].map(
                    lambda r: RISK_STYLE[r]["label"] if r in RISK_STYLE else "Invalid URL")
                k1, k2, k3, k4 = st.columns(4)
                k1.metric("Analyzed", len(df))
                k2.metric("Safe", int((df["risk_level"] == "low").sum()))
                k3.metric("Suspicious", int((df["risk_level"] == "medium").sum()))
                k4.metric("Malicious", int((df["risk_level"] == "high").sum()))
                if "known_domain" not in df:
                    df["known_domain"] = None
                show = df[["url", "Verdict", "malicious_probability", "known_domain", "error"]].rename(
                    columns={"url": "URL", "malicious_probability": "Malicious probability",
                             "known_domain": "Known domain", "error": "Error"})
                st.dataframe(show, hide_index=True, column_config={
                    "Malicious probability": st.column_config.ProgressColumn(
                        format="percent", min_value=0.0, max_value=1.0)})
                st.download_button("Download results (CSV)", show.to_csv(index=False).encode("utf-8"),
                                   "url_shield_results.csv", "text/csv")

# --------------------------------------------------------------------------- tab 3: evaluation
def load_json(path):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


with tab_eval:
    order = ["baseline", "augmented", "cleaned", "final"]
    runs = [r for r in order if os.path.isdir(os.path.join(REPORTS_DIR, r))]
    if not runs:
        st.info("No evaluation reports found. Run `python -m app.train` (and `--no-augment`) in backend/.")
    else:
        st.markdown("<div class='section-title'>Experiment summary</div>", unsafe_allow_html=True)
        rows = []
        for r in runs:
            m = load_json(os.path.join(REPORTS_DIR, r, "metrics.json")) or {}
            ext = load_json(os.path.join(REPORTS_DIR, r, "external_eval.json")) or {}
            best = m.get("best_model")
            bm = (m.get("models") or {}).get(best, {})
            row = {"Run": r, "Best model": best, "F1": bm.get("f1"), "ROC-AUC": bm.get("roc_auc"),
                   "Precision": bm.get("precision"), "Recall": bm.get("recall"),
                   "False positive rate": bm.get("false_positive_rate")}
            for e in ext.get("results", []):
                row[e["source"].split(" (")[0] + " (external)"] = e["value"]
            rows.append(row)
        summary = pd.DataFrame(rows)
        st.dataframe(summary, hide_index=True, column_config={
            c: st.column_config.NumberColumn(format="%.3f") for c in summary.columns
            if c not in ("Run", "Best model")})
        st.caption("Baseline = original Kaggle data. Augmented = + popular Tranco domains in the training set. "
                   "Final = augmented + correction of mislabelled 'benign' phishing URLs. "
                   "External columns: detection rate on fresh OpenPhish phishing URLs and share of the Tranco "
                   "top-10k sites correctly classified as benign.")

        curve_run = next((r for r in reversed(runs)
                          if os.path.exists(os.path.join(REPORTS_DIR, r, "threshold_curve.json"))), None)
        if curve_run:
            render_threshold_explorer(load_json(os.path.join(REPORTS_DIR, curve_run, "threshold_curve.json")), curve_run)
        else:
            st.info("Retrain the model (`python -m app.train`) to enable the decision threshold explorer.")

        run = st.radio("Show detailed results for", runs, index=len(runs) - 1, horizontal=True)
        m = load_json(os.path.join(REPORTS_DIR, run, "metrics.json")) or {}
        if m.get("models"):
            st.markdown("**Model comparison (held-out test set)**")
            dfm = pd.DataFrame(m["models"]).T.drop(columns=["confusion_matrix"], errors="ignore")
            dfm.index.name = "Model"
            st.dataframe(dfm.reset_index(), hide_index=True, column_config={
                c: st.column_config.NumberColumn(format="%.4f") for c in dfm.columns})
        g1, g2 = st.columns(2)
        for col, (fname, cap) in zip([g1, g2, g1], [
                ("roc_curves.png", "ROC curves"), ("confusion_matrix.png", "Confusion matrix (best model)"),
                ("feature_importance.png", "Permutation feature importance")]):
            path = os.path.join(REPORTS_DIR, run, fname)
            if os.path.exists(path):
                col.image(path, caption=cap)
        per_cat = m.get("per_category_detection_rate") or {}
        if per_cat:
            with g2:
                st.markdown("**Detection rate per category**")
                st.dataframe(pd.DataFrame(
                    [{"Category": k, "Test URLs": v[0], "Classified as malicious": v[1]} for k, v in per_cat.items()]),
                    hide_index=True, column_config={"Classified as malicious": st.column_config.ProgressColumn(
                        format="percent", min_value=0.0, max_value=1.0)})

# --------------------------------------------------------------------------- tab 4: design
with tab_about:
    st.markdown("<div class='section-title'>System architecture</div>", unsafe_allow_html=True)
    st.graphviz_chart("""
digraph G {
  rankdir=LR; bgcolor="transparent";
  node [shape=box, style="rounded,filled", fontname="Helvetica", fontsize=11, color="#0B6E69", fillcolor="#E3F1EF"];
  edge [color="#5A6B68", fontname="Helvetica", fontsize=9];
  subgraph cluster_off { label="Offline training pipeline"; style="rounded,dashed"; color="#94a3b8"; fontname="Helvetica";
    data [label="Datasets\\nKaggle · Tranco\\nOpenPhish · URLhaus"];
    prep [label="Cleaning, de-duplication\\n& label-noise correction"];
    feat1 [label="Feature extraction\\n(33 lexical features)"];
    train [label="Training & comparison\\nLR · RF · Gradient Boosting"];
    eval [label="Evaluation\\ntest set + fresh data"];
    data -> prep -> feat1 -> train -> eval;
  }
  model [label="Best model\\n(url_model.pkl)", shape=cylinder, fillcolor="#CFE6E2"];
  train -> model;
  subgraph cluster_on { label="Online system"; style="rounded,dashed"; color="#94a3b8"; fontname="Helvetica";
    ui [label="Streamlit UI\\n(user)", fillcolor="#FFFFFF", color="#0F1B1A"];
    api [label="FastAPI backend\\n/predict · /predict/batch"];
    feat2 [label="Same feature\\nextractor"];
    xai [label="Explanation\\n(decision paths)"];
    allow [label="Known-domain allow-list\\n(Tranco top 10k)"];
    ui -> api [label="URL"]; api -> feat2 -> xai; xai -> allow; allow -> api [label="risk + reasons"]; api -> ui;
  }
  model -> feat2 [style=dashed, label="loaded at start-up"];
}
""")
    c1, c2 = st.columns(2)
    with c1:
        st.markdown("""
**Design decisions**
- **Static lexical analysis** - the URL is never visited, so analysis is fast (~25 ms) and safe.
- **Leakage prevention** - `http(s)://` and `www.` are removed before feature extraction, because the
  dataset stores benign and malicious URLs in different formats.
- **Bias mitigation** - popular Tranco domains are added to training; otherwise every well-known site
  (e.g. google.com) is flagged as malicious.
- **Label-noise correction** - ~3% of the dataset's "benign" URLs are obvious phishing kits
  (e.g. `paypal.com.us.cgi-bin.webscr...login...example.com.br`); they are relabelled before training.
- **Three-level risk** - Safe / Suspicious / Malicious instead of a hard yes/no.
- **Known-domain allow-list** - links directly on the 10,000 most popular domains are treated as safe
  (never subdomains, shorteners, free hosting or paste sites); the model score is still shown.
""")
    with c2:
        st.markdown("""
**Feature groups**
- *Length & structure*: URL / host / path / query length, slashes, dots, subdomains
- *Character statistics*: digits, letters, special characters, entropy
- *Host signals*: raw IP, port, punycode, abused TLDs, URL shorteners, free hosting
- *Content signals*: suspicious keywords, risky file extensions, brand impersonation

**Evaluation**: stratified 80/20 split, accuracy · precision · recall · F1 · ROC-AUC · FPR/FNR,
per-category detection, permutation importance and an external test on fresh threat feeds.
""")

st.markdown("<div class='small-muted' style='margin-top:36px;padding-top:14px;border-top:1px solid var(--line)'>"
            "URL Shield · MSc thesis project · FastAPI, scikit-learn, Streamlit</div>", unsafe_allow_html=True)
