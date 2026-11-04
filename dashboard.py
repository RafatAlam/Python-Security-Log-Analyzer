"""Phase 3 + 4: Security analysis dashboard with live monitoring alerts.

Launch with: python -m streamlit run dashboard.py
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

import altair as alt
import pandas as pd
import streamlit as st

from src.dashboard_data import (
    alerts_frame, events_frame, filter_by_dates, load_log_text,
    severity_counts, summary_frame, timeline_frame,
)
from src.detector import detect_threats
from src.monitor_engine import read_alert_history


# --------------------------------------------------
# PROJECT PATHS AND SAMPLE LOG FILES
# --------------------------------------------------

PROJECT_ROOT = Path(__file__).resolve().parent
SAMPLE_LOGS = {
    "Dashboard demo (recommended)": "dashboard_demo.log",
    "Phase 2 SSH demo": "phase2_demo.log",
    "Phase 1 SSH demo": "ssh_auth.log",
    "Original custom log": "auth.log",
}

# --------------------------------------------------
# PAGE CONFIGURATION AND STYLING
# --------------------------------------------------

st.set_page_config(
    page_title="Security Log Analyzer | Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown(
    """
    <style>
    .block-container {padding-top: 1.7rem; padding-bottom: 2.5rem;}
    [data-testid="stMetric"] {background: #f5f7fb; border: 1px solid #e6ebf2;
        padding: 1rem; border-radius: .8rem;}
    [data-testid="stMetricLabel"] {color: #526179;}
    @media (prefers-color-scheme: dark) {
      [data-testid="stMetric"] {background: #172235; border-color: #314055;}
      [data-testid="stMetricLabel"] {color: #cad5e2;}
    }
    </style>
    """,
    unsafe_allow_html=True,
)

st.title("🛡️ Security Log Analyzer")
st.caption("Phase 4 · Log analysis, threat detection, and live alert monitoring")

# --------------------------------------------------
# SIDEBAR: SELECT LOG DATA AND DETECTION THRESHOLDS
# --------------------------------------------------

with st.sidebar:
    st.header("Data source")
    source = st.radio(
        "Choose authentication logs",
        ["Bundled sample", "Upload a log file"],
        label_visibility="visible",
    )
    if source == "Bundled sample":
        sample_name = st.selectbox("Sample", list(SAMPLE_LOGS))
        log_path = PROJECT_ROOT / "logs" / SAMPLE_LOGS[sample_name]
        log_year = st.number_input(
            "SSH log year", min_value=2000, max_value=2100,
            value=2026, step=1,
            help="Traditional SSH syslog timestamps do not include a year.",
        )
        raw_bytes = log_path.read_bytes()
    else:
        uploaded = st.file_uploader(
            "Choose a .log or .txt file", type=["log", "txt"],
            help="Logs stay in memory and are not saved to disk by this dashboard.",
        )
        log_year = st.number_input(
            "SSH log year", min_value=2000, max_value=2100,
            value=datetime.now().year, step=1,
            help="Used only for SSH syslog timestamps without a year.",
        )
        raw_bytes = uploaded.getvalue() if uploaded else None

    st.divider()
    st.header("Detection settings")
    with st.expander("Brute force", expanded=True):
        brute_threshold = st.number_input("Failed attempts", 1, 1000, 5, key="brute")
        brute_window = st.number_input("Window (minutes)", 1, 1440, 5, key="brute_window")
    with st.expander("Password spraying"):
        spray_users = st.number_input("Distinct usernames", 1, 1000, 5)
        spray_window = st.number_input("Window (minutes)", 1, 1440, 10, key="spray_window")
    with st.expander("Success after failures"):
        success_failures = st.number_input("Previous failures", 1, 1000, 3)
        success_window = st.number_input("Window (minutes)", 1, 1440, 10, key="success_window")

    st.divider()
    st.caption("The detector uses source IPs and configurable heuristics. Alerts do not prove an attack occurred.")

# --------------------------------------------------
# VALIDATE AND PARSE THE SELECTED AUTHENTICATION LOG
# --------------------------------------------------

if raw_bytes is None:
    st.info("Upload an authentication log to start investigating, or choose a bundled sample.")
    st.stop()

if len(raw_bytes) > 5 * 1024 * 1024:
    st.error("This demo limits log files to 5 MB. Please use a smaller sample.")
    st.stop()

try:
    log_text = raw_bytes.decode("utf-8-sig")
except UnicodeDecodeError:
    st.error("Unable to decode this log as UTF-8. Convert it to UTF-8 and try again.")
    st.stop()

events, invalid_count = load_log_text(log_text, int(log_year))
if not events:
    st.warning(f"No supported authentication entries found. Unsupported lines: {invalid_count}.")
    st.info("Accepted inputs are custom username/ip/status entries and common Linux OpenSSH authentication records.")
    st.stop()

# --------------------------------------------------
# APPLY THE EXISTING PHASE 2 SECURITY RULES
# --------------------------------------------------

all_events = events_frame(events)
alerts = detect_threats(
    events,
    brute_threshold=int(brute_threshold), brute_window=int(brute_window),
    spray_users=int(spray_users), spray_window=int(spray_window),
    success_failures=int(success_failures), success_window=int(success_window),
)
all_alerts = alerts_frame(alerts)
all_summary = summary_frame(events, int(brute_threshold), int(brute_window))

# --------------------------------------------------
# INVESTIGATION FILTERS
# --------------------------------------------------

min_date = all_events["timestamp"].min().date()
max_date = all_events["timestamp"].max().date()

st.subheader("Investigation filters")
col_a, col_b, col_c = st.columns([1.6, 1.4, 1.3])
with col_a:
    ip_choice = st.selectbox("Source IP", ["All IPs"] + sorted(all_events["ip_address"].unique().tolist()))
with col_b:
    selected_dates = st.date_input(
        "Date range", value=(min_date, max_date),
        min_value=min_date, max_value=max_date,
    )
with col_c:
    severity_choice = st.multiselect(
        "Alert severity", ["CRITICAL", "HIGH"],
        default=["CRITICAL", "HIGH"],
    )

if isinstance(selected_dates, tuple) and len(selected_dates) == 2:
    start_date, end_date = selected_dates
else:
    st.info("Select both a start and end date to finish the date range.")
    st.stop()

filtered_events = filter_by_dates(all_events, start_date, end_date)
filtered_alerts = filter_by_dates(all_alerts, start_date, end_date)
if ip_choice != "All IPs":
    filtered_events = filtered_events[filtered_events["ip_address"] == ip_choice]
    filtered_alerts = filtered_alerts[filtered_alerts["ip_address"] == ip_choice]
    filtered_summary = all_summary[all_summary["ip_address"] == ip_choice]
else:
    filtered_summary = all_summary
filtered_alerts = filtered_alerts[filtered_alerts["severity"].isin(severity_choice)]

# Detections use the entire source log. Date/IP/severity filters only change the
# displayed results, so short filters cannot erase the evidence behind alerts.
# --------------------------------------------------
# DASHBOARD SUMMARY METRICS
# --------------------------------------------------

severities = severity_counts(filtered_alerts)
metrics = st.columns(5)
metrics[0].metric("Login events", f"{len(filtered_events):,}")
metrics[1].metric("Successful", f"{(filtered_events['status'] == 'success').sum():,}")
metrics[2].metric("Failed", f"{(filtered_events['status'] == 'failed').sum():,}")
metrics[3].metric("Alert count", f"{len(filtered_alerts):,}")
metrics[4].metric("Critical alerts", f"{severities['CRITICAL']:,}")

st.caption(
    f"Parsed {len(events):,} valid records; skipped {invalid_count:,} unsupported/malformed lines. "
    "Detection is calculated on the complete loaded log; filters change the view only."
)

# --------------------------------------------------
# DASHBOARD TABS
# --------------------------------------------------

activity_tab, alerts_tab, investigate_tab, live_tab = st.tabs(
    ["📈 Login trends", "🚨 Threat alerts", "🔍 IP investigation", "🔔 Live alerts"]
)

# --------------------------------------------------
# TAB 1: LOGIN ACTIVITY OVER TIME
# --------------------------------------------------

with activity_tab:
    interval = st.selectbox(
        "Group login activity by", ["5 minutes", "15 minutes", "1 hour", "1 day"],
        index=1,
    )
    grouping = {"5 minutes": "5min", "15 minutes": "15min", "1 hour": "h", "1 day": "D"}[interval]
    timeline = timeline_frame(filtered_events, grouping)
    st.caption(
        "**X-axis:** Date and time in the log. "
        "**Y-axis:** Number of login attempts in each selected time interval. "
        "**Lines:** Successful logins versus failed logins. "
        "For example, at 9 AM with 1-hour grouping, a value of 7 means "
        "7 login attempts between 9:00 and 9:59 AM."
    )
    if timeline.empty:
        st.info("No events in this selection.")
    else:
        # Long form gives Altair readable series labels and an explicit legend.
        timeline_long = timeline.melt(
            id_vars="timestamp",
            value_vars=["success", "failed"],
            var_name="login_result",
            value_name="login_count",
        )
        timeline_long["login_result"] = timeline_long["login_result"].map(
            {"success": "Successful logins", "failed": "Failed logins"}
        )
        activity_chart = (
            alt.Chart(timeline_long)
            .mark_line(point=True)
            .encode(
                x=alt.X(
                    "timestamp:T",
                    title="Date and time of login activity",
                    axis=alt.Axis(
                        format="%b %d, %I %p",
                        labelAngle=0,
                        labelOverlap="greedy",
                        tickCount=9,
                    ),
                ),
                y=alt.Y(
                    "login_count:Q",
                    title=f"Login attempts per {interval.lower()}",
                    axis=alt.Axis(tickMinStep=1),
                ),
                color=alt.Color("login_result:N", title="Login result"),
                tooltip=[
                    alt.Tooltip("timestamp:T", title="Time", format="%b %d, %Y %I:%M %p"),
                    alt.Tooltip("login_result:N", title="Result"),
                    alt.Tooltip("login_count:Q", title="Login attempts", format="d"),
                ],
            )
            .properties(height=350)
        )
        st.altair_chart(activity_chart, use_container_width=True)

    st.markdown("**Login events**")
    st.dataframe(
        filtered_events.sort_values("timestamp", ascending=False),
        use_container_width=True, hide_index=True,
    )
    st.download_button(
        "Download filtered login events (CSV)",
        data=filtered_events.to_csv(index=False).encode("utf-8"),
        file_name="login_events.csv", mime="text/csv",
    )

# --------------------------------------------------
# TAB 2: DETECTION ALERTS AND HORIZONTAL BAR CHART
# --------------------------------------------------

with alerts_tab:
    rules = sorted(all_alerts["rule"].dropna().unique().tolist())
    chosen_rules = st.multiselect("Detection rules", rules, default=rules)
    visible_alerts = filtered_alerts[filtered_alerts["rule"].isin(chosen_rules)]
    if visible_alerts.empty:
        st.info("No alerts match the current filters. Try another log, date, or severity.")
    else:
        st.dataframe(visible_alerts, use_container_width=True, hide_index=True)
        st.markdown("**Alerts by detection rule**")
        st.caption(
            "**Horizontal axis:** Number of alerts. "
            "**Vertical axis:** Detection rule. "
            "Each bar counts how many times that rule triggered in the filtered alerts. "
            "An IP address can generate multiple alerts."
        )
        rule_labels = {
            "brute_force": "Brute force",
            "password_spraying": "Password spraying",
            "success_after_failures": "Successful login after failures",
        }
        counts_by_rule = (
            visible_alerts["rule"]
            .value_counts()
            .rename_axis("rule")
            .reset_index(name="alert_count")
        )
        counts_by_rule["rule_label"] = (
            counts_by_rule["rule"].map(rule_labels).fillna(counts_by_rule["rule"])
        )
        alerts_chart = (
            alt.Chart(counts_by_rule)
            .mark_bar()
            .encode(
                x=alt.X(
                    "alert_count:Q",
                    title="Number of alerts",
                    axis=alt.Axis(tickMinStep=1),
                ),
                y=alt.Y(
                    "rule_label:N",
                    title="Detection rule",
                    sort="-x",
                    axis=alt.Axis(labelAngle=0, labelLimit=320),
                ),
                tooltip=[
                    alt.Tooltip("rule_label:N", title="Detection rule"),
                    alt.Tooltip("alert_count:Q", title="Number of alerts", format="d"),
                ],
            )
            .properties(height=230)
        )
        st.altair_chart(alerts_chart, use_container_width=True)

    st.download_button(
        "Download filtered threat alerts (CSV)",
        data=visible_alerts.to_csv(index=False).encode("utf-8"),
        file_name="threat_alerts.csv", mime="text/csv",
    )

# --------------------------------------------------
# TAB 3: IP-BASED INVESTIGATION
# --------------------------------------------------

with investigate_tab:
    st.markdown("**IP activity summary**")
    # The source-wide summary uses the current brute force rule, like the CLI.
    st.dataframe(filtered_summary, use_container_width=True, hide_index=True)
    st.download_button(
        "Download IP summary (CSV)",
        data=filtered_summary.to_csv(index=False).encode("utf-8"),
        file_name="security_report.csv", mime="text/csv",
    )
    st.markdown("**Top IPs by failed login attempts**")
    if not filtered_events.empty:
        top_ips = (
            filtered_events.loc[filtered_events["status"] == "failed", "ip_address"]
            .value_counts().head(10)
        )
        if not top_ips.empty:
            st.caption(
                "**Horizontal axis:** Number of failed logins. "
                "**Vertical axis:** Source IP address (top 10 by failures)."
            )
            top_ip_counts = top_ips.rename_axis("ip_address").reset_index(name="failed_logins")
            top_ip_chart = (
                alt.Chart(top_ip_counts)
                .mark_bar()
                .encode(
                    x=alt.X(
                        "failed_logins:Q",
                        title="Number of failed logins",
                        axis=alt.Axis(tickMinStep=1),
                    ),
                    y=alt.Y(
                        "ip_address:N", title="Source IP address", sort="-x",
                        axis=alt.Axis(labelAngle=0, labelLimit=320),
                    ),
                    tooltip=[
                        alt.Tooltip("ip_address:N", title="Source IP"),
                        alt.Tooltip("failed_logins:Q", title="Failed logins", format="d"),
                    ],
                )
                .properties(height=310)
            )
            st.altair_chart(top_ip_chart, use_container_width=True)
        else:
            st.info("No failed logins in the selected window.")
    else:
        st.info("No logins for this selection.")
    st.caption(
        "IP summary values are calculated across the complete loaded file, "
        "not just the selected date range. The timeline and top-IP chart use the date filter."
    )

# ==================================================
# TAB 4: PHASE 4 LIVE ALERTS
# ==================================================

# Live monitoring runs independently in run_monitor.py. This dashboard only reads
# its saved JSONL alert history and refreshes the display every five seconds.
with live_tab:
    st.markdown("### Live Security Alerts")
    st.caption(
        "Run `python run_monitor.py --log logs/live_demo.log` in a separate terminal. "
        "Alerts written to `reports/live_alerts.jsonl` appear here automatically "
        "every 5 seconds. This feed is separate from the uploaded log filters."
    )

    @st.fragment(run_every="5s")
    def show_live_alerts() -> None:
        # Streamlit reruns only this area to show newly saved alerts.
        history_path = PROJECT_ROOT / "reports" / "live_alerts.jsonl"
        recent = read_alert_history(history_path, limit=500)

        if not recent:
            st.info(
                "No live alerts recorded yet. Start run_monitor.py, then append "
                "events with simulate_logins.py in another terminal."
            )
            return

        frame = pd.DataFrame(recent)
        frame["rule"] = frame["rule"].replace({
            "brute_force": "Brute force",
            "password_spraying": "Password spraying",
            "success_after_failures": "Successful login after failures",
        })

        # Most recent notifications first, including the time they were saved.
        frame = frame.iloc[::-1].reset_index(drop=True)
        critical = int((frame["severity"] == "CRITICAL").sum())
        high = int((frame["severity"] == "HIGH").sum())
        a, b, c = st.columns(3)
        a.metric("Saved live alerts", len(frame))
        b.metric("Critical", critical)
        c.metric("High", high)

        st.dataframe(
            frame.rename(columns={
                "observed_at_utc": "Recorded (UTC)",
                "timestamp": "Event time",
                "ip_address": "Source IP",
                "rule": "Detection rule",
                "severity": "Severity",
                "details": "Details",
                "count": "Count",
            }),
            use_container_width=True,
            hide_index=True,
        )
        st.download_button(
            "Download live alerts (CSV)",
            frame.to_csv(index=False).encode("utf-8"),
            file_name="live_alerts.csv",
            mime="text/csv",
            key="live_alerts_export",
        )

    show_live_alerts()


st.divider()
st.caption(
    "Educational demonstration · Do not upload secrets or production authentication logs "
    "to a publicly hosted instance. Uploaded logs are processed in memory; "
    "live alert history is saved locally under reports/."
)
