from __future__ import annotations

from datetime import datetime
from pathlib import Path

import pandas as pd
import plotly.express as px
import streamlit as st

from sentinelx_engine import analyze_events

ROOT = Path(__file__).parent
SAMPLE_FILE = ROOT / "sample_data" / "security_events.csv"
REQUIRED_COLUMNS = {
    "event_type",
    "source_ip",
    "username",
    "country",
    "failed_attempts",
    "bytes_out",
    "unusual_hour",
    "process_name",
    "details",
}

st.set_page_config(
    page_title="SentinelX | Security Operations",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown(
    """
    <style>
    @import url('https://fonts.googleapis.com/css2?family=DM+Mono:wght@400;500&family=DM+Sans:wght@400;500;600;700&family=Manrope:wght@500;600;700;800&display=swap');
    html, body, [class*="css"] { font-family: 'DM Sans', sans-serif; }
    .stApp { background: radial-gradient(ellipse at 80% 0%, #112e3d 0%, #091524 42%, #07111f 100%); }
    h1, h2, h3 { font-family: 'Manrope', sans-serif; letter-spacing: -0.035em; }
    [data-testid="stMetric"] { background: linear-gradient(145deg,#102235,#0d1b2a); border: 1px solid #263c52; padding: 15px 17px; border-radius: 12px; }
    [data-testid="stMetricLabel"] { color: #9bb0c5; }
    [data-testid="stMetricValue"] { color: #ecf6ff; }
    [data-testid="stSidebar"] { background: #091523; border-right: 1px solid #20364a; }
    [data-testid="stDataFrame"] { border: 1px solid #263c52; border-radius: 10px; overflow: hidden; }
    .eyebrow { color: #5eead4; font: 500 10px 'DM Mono', monospace; letter-spacing: 1.6px; }
    .hero { background: linear-gradient(115deg,#102b3c,#123244 60%,#10303a); border:1px solid #285064; border-radius:16px; padding:26px 30px; margin: 4px 0 20px; }
    .hero h1 { margin: 8px 0 5px; color:#f2f8ff; font-size: 2.1rem; }
    .hero p { color:#aec2d3; margin:0; max-width:760px; }
    .tag { display:inline-block; color:#8ef5df; border:1px solid #36786f; background:#113e3b; padding:4px 9px; border-radius:30px; font:10px 'DM Mono',monospace; }
    .small-muted { color:#8ea3b9; font-size: 0.82rem; }
    div.stButton > button[kind="primary"] { background: #5eead4; color:#06201f; border:0; font-weight:700; }
    </style>
    """,
    unsafe_allow_html=True,
)


def _load_sample() -> pd.DataFrame:
    frame = pd.read_csv(SAMPLE_FILE)
    if "event_time" in frame.columns:
        frame["event_time"] = pd.to_datetime(frame["event_time"], errors="coerce")
    return frame


def _prepare(frame: pd.DataFrame) -> pd.DataFrame:
    records = frame.fillna("").to_dict(orient="records")
    analyzed = pd.DataFrame(analyze_events(records))
    if "event_time" in analyzed.columns:
        analyzed["event_time"] = pd.to_datetime(analyzed["event_time"], errors="coerce")
    else:
        analyzed["event_time"] = pd.Timestamp.now()
    return analyzed


if "raw_events" not in st.session_state:
    st.session_state.raw_events = _load_sample()
if "alert_status" not in st.session_state:
    st.session_state.alert_status = {}
if "last_import_name" not in st.session_state:
    st.session_state.last_import_name = ""

with st.sidebar:
    st.markdown("## 🛡️ SentinelX")
    st.caption("AI CYBERSECURITY INTELLIGENCE")
    st.divider()
    page = st.radio(
        "WORKSPACE",
        ["Overview", "Alert queue", "Event stream", "Analyze event", "Import data"],
        label_visibility="collapsed",
    )
    st.divider()
    st.markdown("**Environment**")
    st.markdown('<span class="tag">● DEMO / MONITORING</span>', unsafe_allow_html=True)
    st.caption("Synthetic telemetry only")
    if st.button("↻ Reload demo dataset", use_container_width=True):
        st.session_state.raw_events = _load_sample()
        st.session_state.alert_status = {}
        st.rerun()
    st.divider()
    st.caption("SentinelX v0.1.0 · Portfolio MVP")

df = _prepare(st.session_state.raw_events)
alerts = df[df["risk_score"] >= 40].copy()
if not alerts.empty:
    alerts["status"] = alerts["id"].map(st.session_state.alert_status).fillna("new") if "id" in alerts else "new"

if page == "Overview":
    st.markdown('<div class="hero"><div class="eyebrow">SECURITY OPERATIONS CENTER / LIVE WORKSPACE</div><h1>See the signal. Stop the threat.</h1><p>SentinelX combines explainable detection rules and machine-learning anomaly scoring to help analysts prioritize synthetic security events.</p><br><span class="tag">● DETECTION ENGINE ONLINE</span></div>', unsafe_allow_html=True)
    total = len(df)
    open_alerts = int((alerts.get("status", pd.Series(dtype=str)) != "resolved").sum()) if not alerts.empty else 0
    critical = int(((alerts.get("risk_level", pd.Series(dtype=str)) == "critical") & (alerts.get("status", pd.Series(dtype=str)) != "resolved")).sum()) if not alerts.empty else 0
    avg_risk = round(float(df["risk_score"].mean()), 1) if total else 0
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Events analyzed", f"{total:,}", "Synthetic telemetry")
    c2.metric("Open alerts", f"{open_alerts:,}", "Risk score ≥ 40")
    c3.metric("Critical alerts", f"{critical:,}", "Highest priority")
    c4.metric("Average risk", f"{avg_risk}/100", "Across loaded events")
    st.write("")
    left, right = st.columns([1.45, 1])
    with left:
        st.subheader("Event activity")
        if not df.empty:
            trend = df.dropna(subset=["event_time"]).copy()
            if not trend.empty:
                trend["day"] = trend["event_time"].dt.date.astype(str)
                counts = trend.groupby("day", as_index=False).size().rename(columns={"size": "events"})
                fig = px.area(counts, x="day", y="events", markers=True)
                fig.update_traces(line_color="#5eead4", fillcolor="rgba(45,212,191,.15)")
                fig.update_layout(height=280, margin=dict(l=8,r=8,t=15,b=5), paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", font_color="#a8bbce", xaxis_title="", yaxis_title="Events")
                st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("Load demo telemetry or import an event file to begin.")
    with right:
        st.subheader("Alert severity")
        if alerts.empty:
            st.info("No events have crossed the alert threshold.")
        else:
            dist = alerts["risk_level"].value_counts().rename_axis("severity").reset_index(name="count")
            fig = px.pie(dist, names="severity", values="count", hole=.62, color="severity", color_discrete_map={"critical":"#fb7185","high":"#fbbf24","medium":"#60a5fa","low":"#5eead4"})
            fig.update_layout(height=280, margin=dict(l=5,r=5,t=5,b=5), paper_bgcolor="rgba(0,0,0,0)", font_color="#a8bbce", legend_title="")
            st.plotly_chart(fig, use_container_width=True)
    st.subheader("Priority detections")
    if alerts.empty:
        st.info("No alerts yet. Try the demo events or analyze a new event.")
    else:
        view = alerts.sort_values("risk_score", ascending=False)[["event_type","source_ip","username","risk_score","risk_level","detection_reasons"]].head(6)
        view["detection_reasons"] = view["detection_reasons"].apply(lambda reasons: "; ".join(reasons))
        st.dataframe(view, use_container_width=True, hide_index=True)

elif page == "Alert queue":
    st.markdown('<div class="eyebrow">DETECTION / RESPONSE</div>', unsafe_allow_html=True)
    st.title("Alert queue")
    st.caption("Review high-risk activity and record analyst dispositions for this session.")
    if alerts.empty:
        st.success("No alerts in the current dataset.")
    else:
        severity = st.multiselect("Severity", ["critical","high","medium"], default=["critical","high","medium"])
        filtered = alerts[alerts["risk_level"].isin(severity)].sort_values("risk_score", ascending=False)
        for idx, row in filtered.iterrows():
            key = str(row.get("id", f"event-{idx}"))
            current = st.session_state.alert_status.get(key, "new")
            title = f"{str(row['risk_level']).upper()} · {row['event_type']} · {row['source_ip']} · Risk {row['risk_score']}/100"
            with st.expander(title, expanded=(row["risk_level"] == "critical")):
                st.write(f"**User:** {row['username']}  ·  **Country:** {row['country']}  ·  **Process:** {row['process_name']}")
                for reason in row["detection_reasons"]:
                    st.markdown(f"- {reason}")
                new_status = st.selectbox("Disposition", ["new","investigating","resolved"], index=["new","investigating","resolved"].index(current), key=f"status-{key}")
                st.session_state.alert_status[key] = new_status
                st.caption(f"Session-only status: {new_status}")

elif page == "Event stream":
    st.markdown('<div class="eyebrow">COLLECTION / TELEMETRY</div>', unsafe_allow_html=True)
    st.title("Event stream")
    st.caption("Normalized event records with explainable risk scores.")
    level = st.multiselect("Risk level", ["critical","high","medium","low"], default=["critical","high","medium","low"])
    filtered = df[df["risk_level"].isin(level)].sort_values("risk_score", ascending=False)
    display = filtered.copy()
    display["detection_reasons"] = display["detection_reasons"].apply(lambda reasons: "; ".join(reasons))
    columns = [c for c in ["event_time","event_type","source_ip","username","country","risk_score","risk_level","detection_reasons"] if c in display]
    st.dataframe(display[columns], use_container_width=True, hide_index=True)
    st.download_button("⬇ Download analyzed events", display[columns].to_csv(index=False), "sentinelx_events.csv", "text/csv")

elif page == "Analyze event":
    st.markdown('<div class="eyebrow">DETECTION LAB / MANUAL ANALYSIS</div>', unsafe_allow_html=True)
    st.title("Analyze an event")
    st.caption("Submit a synthetic or approved test event and inspect the model's explainable risk assessment.")
    with st.form("event-form"):
        c1, c2 = st.columns(2)
        with c1:
            event_type = st.selectbox("Event type", ["login_success","login_failure","data_transfer","process_alert","api_access"])
            source_ip = st.text_input("Source IP", "192.0.2.25")
            username = st.text_input("Username", "demo-analyst")
            country = st.text_input("Country code", "US")
        with c2:
            failed_attempts = st.number_input("Failed attempts", min_value=0, max_value=1000, value=0)
            bytes_out = st.number_input("Outbound bytes", min_value=0, max_value=2_000_000_000, value=12000, step=1000)
            unusual_hour = st.checkbox("Unusual local activity hour")
            process_name = st.text_input("Process name", "browser")
        details = st.text_area("Context", "Synthetic event created in the SentinelX detection lab.")
        submitted = st.form_submit_button("Analyze security event", type="primary", use_container_width=True)
    if submitted:
        record = {"event_time": datetime.now().isoformat(timespec="seconds"), "event_type":event_type, "source_ip":source_ip, "username":username, "country":country, "failed_attempts":failed_attempts, "bytes_out":bytes_out, "unusual_hour":unusual_hour, "process_name":process_name, "details":details}
        st.session_state.raw_events = pd.concat([st.session_state.raw_events, pd.DataFrame([record])], ignore_index=True)
        result = analyze_events([record])[0]
        st.success(f"Analysis complete — {result['risk_level'].upper()} risk ({result['risk_score']}/100)")
        for reason in result["detection_reasons"]:
            st.markdown(f"- {reason}")
        if not result["detection_reasons"]:
            st.caption("No high-risk indicators were identified by the current demo model.")

elif page == "Import data":
    st.markdown('<div class="eyebrow">DATA INGESTION / APPROVED TELEMETRY</div>', unsafe_allow_html=True)
    st.title("Import security events")
    st.caption("Upload a CSV with the event columns below. Data stays in this Streamlit session and is not written to a persistent database.")
    st.code(", ".join(sorted(REQUIRED_COLUMNS)), language="text")
    upload = st.file_uploader("Choose an event CSV", type=["csv"])
    if upload is not None:
        try:
            incoming = pd.read_csv(upload)
            missing = REQUIRED_COLUMNS - set(incoming.columns)
            if missing:
                st.error("Missing required columns: " + ", ".join(sorted(missing)))
            elif len(incoming) > 50000:
                st.error("The demo importer is limited to 50,000 rows per upload.")
            else:
                st.dataframe(incoming.head(10), use_container_width=True, hide_index=True)
                if st.button("Add imported events", type="primary"):
                    if "event_time" not in incoming:
                        incoming["event_time"] = datetime.now().isoformat(timespec="seconds")
                    st.session_state.raw_events = pd.concat([st.session_state.raw_events, incoming], ignore_index=True)
                    st.session_state.last_import_name = upload.name
                    st.success(f"Imported {len(incoming):,} events from {upload.name}.")
        except Exception as exc:
            st.error(f"Unable to read CSV: {exc}")

st.divider()
st.caption("SentinelX is an educational portfolio MVP. It uses synthetic/demo telemetry and its scores are not proof of compromise or a replacement for a production SIEM/SOC.")
