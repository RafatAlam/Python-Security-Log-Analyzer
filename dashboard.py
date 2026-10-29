
"""Phase 3: Interactive dashboard for security log analysis.

Launch with: python -m streamlit run dashboard.py
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

import altair as alt
import pandas as pd
import streamlit as st

from src.dashboard_data import (
    alerts_frame,
    events_frame,
    filter_by_dates,
    load_log_text,
    severity_counts,
    summary_frame,
    timeline_frame,
)
from src.detector import detect_threats


# --------------------------------------------------
# PROJECT PATHS AND SAMPLE FILES
# --------------------------------------------------

# Resolve file paths relative to the project directory.
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

# Configure the Streamlit page layout and browser title.
st.set_page_config(
    page_title="Security Log Analyzer | Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Add custom styling to the dashboard metric cards.
st.markdown(
    """
    <style>
    .block-container {
        padding-top: 1.7rem;
        padding-bottom: 2.5rem;
    }

    [data-testid="stMetric"] {
        background: #f5f7fb;
        border: 1px solid #e6ebf2;
        padding: 1rem;
        border-radius: .8rem;
    }

    [data-testid="stMetricLabel"] {
        color: #526179;
    }

    @media (prefers-color-scheme: dark) {
        [data-testid="stMetric"] {
            background: #172235;
            border-color: #314055;
        }

        [data-testid="stMetricLabel"] {
            color: #cad5e2;
        }
    }
    </style>
    """,
    unsafe_allow_html=True,
)

st.title("🛡️ Security Log Analyzer")

st.caption(
    "Phase 3 · Authentication activity, "
    "rule-based detection, and investigation"
)


# --------------------------------------------------
# SIDEBAR: DATA SOURCE
# --------------------------------------------------

# Allow users to select bundled authentication logs
# or upload their own supported log files.
with st.sidebar:

    st.header("Data source")

    source = st.radio(
        "Choose authentication logs",
        ["Bundled sample", "Upload a log file"],
    )

    if source == "Bundled sample":

        sample_name = st.selectbox(
            "Sample",
            list(SAMPLE_LOGS),
        )

        # Locate the selected sample log.
        log_path = (
            PROJECT_ROOT / "logs" / SAMPLE_LOGS[sample_name]
        )

        # SSH syslog timestamps do not contain a year,
        # so the user must provide one.
        log_year = st.number_input(
            "SSH log year",
            min_value=2000,
            max_value=2100,
            value=2026,
            step=1,
            help=(
                "Traditional SSH syslog timestamps "
                "do not include a year."
            ),
        )

        raw_bytes = log_path.read_bytes()

    else:

        uploaded = st.file_uploader(
            "Choose a .log or .txt file",
            type=["log", "txt"],
            help=(
                "Logs stay in memory and are not "
                "saved to disk by this dashboard."
            ),
        )

        log_year = st.number_input(
            "SSH log year",
            min_value=2000,
            max_value=2100,
            value=datetime.now().year,
            step=1,
        )

        # Read uploaded files directly into memory.
        raw_bytes = (
            uploaded.getvalue()
            if uploaded
            else None
        )


    # ----------------------------------------------
    # DETECTION SETTINGS
    # ----------------------------------------------

    # Allow users to modify detection thresholds
    # without changing the underlying Python code.
    st.divider()
    st.header("Detection settings")

    # Brute-force detection identifies repeated
    # failed logins from the same IP address.
    with st.expander("Brute force", expanded=True):

        brute_threshold = st.number_input(
            "Failed attempts",
            1,
            1000,
            5,
            key="brute",
        )

        brute_window = st.number_input(
            "Window (minutes)",
            1,
            1440,
            5,
            key="brute_window",
        )

    # Password spraying identifies failures against
    # multiple usernames from a single IP address.
    with st.expander("Password spraying"):

        spray_users = st.number_input(
            "Distinct usernames",
            1,
            1000,
            5,
        )

        spray_window = st.number_input(
            "Window (minutes)",
            1,
            1440,
            10,
            key="spray_window",
        )

    # Detect successful logins after repeated
    # failed attempts from the same IP address.
    with st.expander("Success after failures"):

        success_failures = st.number_input(
            "Previous failures",
            1,
            1000,
            3,
        )

        success_window = st.number_input(
            "Window (minutes)",
            1,
            1440,
            10,
            key="success_window",
        )

    st.divider()

    st.caption(
        "The detector uses source IPs and configurable "
        "heuristics. Alerts do not prove an attack occurred."
    )


# --------------------------------------------------
# LOAD AND VALIDATE AUTHENTICATION LOGS
# --------------------------------------------------

# Stop execution if no log file is available.
if raw_bytes is None:

    st.info(
        "Upload an authentication log to start "
        "investigating, or choose a bundled sample."
    )

    st.stop()


# Limit log files to 5 MB to prevent large uploads
# from slowing down the dashboard.
if len(raw_bytes) > 5 * 1024 * 1024:

    st.error(
        "This demo limits log files to 5 MB. "
        "Please use a smaller sample."
    )

    st.stop()


# Convert the selected log file into UTF-8 text.
try:
    log_text = raw_bytes.decode("utf-8-sig")

except UnicodeDecodeError:

    st.error(
        "Unable to decode this log as UTF-8. "
        "Convert it to UTF-8 and try again."
    )

    st.stop()


# Parse authentication records into LogEvent objects.
# Invalid or unsupported log lines are counted separately.
events, invalid_count = load_log_text(
    log_text,
    int(log_year),
)

if not events:

    st.warning(
        "No supported authentication entries found. "
        f"Unsupported lines: {invalid_count}."
    )

    st.stop()


# --------------------------------------------------
# PROCESS EVENTS AND DETECT THREATS
# --------------------------------------------------

# Convert parsed authentication records into a
# Pandas DataFrame for filtering and visualization.
all_events = events_frame(events)


# Use the existing Phase 2 detection engine to
# identify brute force, password spraying,
# and successful logins following repeated failures.
alerts = detect_threats(
    events,
    brute_threshold=int(brute_threshold),
    brute_window=int(brute_window),
    spray_users=int(spray_users),
    spray_window=int(spray_window),
    success_failures=int(success_failures),
    success_window=int(success_window),
)


# Convert security alerts into a DataFrame.
all_alerts = alerts_frame(alerts)


# Generate an IP-based activity summary using
# the complete authentication log.
all_summary = summary_frame(
    events,
    int(brute_threshold),
    int(brute_window),
)


# --------------------------------------------------
# INVESTIGATION FILTERS
# --------------------------------------------------

# Determine the earliest and latest dates found
# in the authentication log.
min_date = all_events["timestamp"].min().date()
max_date = all_events["timestamp"].max().date()

st.subheader("Investigation filters")

col_a, col_b, col_c = st.columns(
    [1.6, 1.4, 1.3]
)


# Filter authentication activity by source IP.
with col_a:

    ip_choice = st.selectbox(
        "Source IP",
        ["All IPs"]
        + sorted(
            all_events["ip_address"].unique().tolist()
        ),
    )


# Filter authentication activity by date range.
with col_b:

    selected_dates = st.date_input(
        "Date range",
        value=(min_date, max_date),
        min_value=min_date,
        max_value=max_date,
    )


# Allow users to display only selected alert severities.
with col_c:

    severity_choice = st.multiselect(
        "Alert severity",
        ["CRITICAL", "HIGH"],
        default=["CRITICAL", "HIGH"],
    )


# Require both start and end dates before filtering.
if (
    isinstance(selected_dates, tuple)
    and len(selected_dates) == 2
):

    start_date, end_date = selected_dates

else:

    st.info(
        "Select both a start and end date."
    )

    st.stop()


# Filter displayed authentication events and alerts
# without changing the original detection results.
filtered_events = filter_by_dates(
    all_events,
    start_date,
    end_date,
)

filtered_alerts = filter_by_dates(
    all_alerts,
    start_date,
    end_date,
)


# Apply the selected IP filter.
if ip_choice != "All IPs":

    filtered_events = filtered_events[
        filtered_events["ip_address"] == ip_choice
    ]

    filtered_alerts = filtered_alerts[
        filtered_alerts["ip_address"] == ip_choice
    ]

    filtered_summary = all_summary[
        all_summary["ip_address"] == ip_choice
    ]

else:

    filtered_summary = all_summary


# Display only alerts matching selected severity levels.
filtered_alerts = filtered_alerts[
    filtered_alerts["severity"].isin(severity_choice)
]


# --------------------------------------------------
# DASHBOARD SUMMARY METRICS
# --------------------------------------------------

# Calculate total events, login results, and alert
# counts based on the current investigation filters.
severities = severity_counts(filtered_alerts)

metrics = st.columns(5)

metrics[0].metric(
    "Login events",
    f"{len(filtered_events):,}",
)

metrics[1].metric(
    "Successful",
    f"{(filtered_events['status'] == 'success').sum():,}",
)

metrics[2].metric(
    "Failed",
    f"{(filtered_events['status'] == 'failed').sum():,}",
)

metrics[3].metric(
    "Alert count",
    f"{len(filtered_alerts):,}",
)

metrics[4].metric(
    "Critical alerts",
    f"{severities['CRITICAL']:,}",
)


# Inform users how many records were successfully parsed.
st.caption(
    f"Parsed {len(events):,} valid records; "
    f"skipped {invalid_count:,} malformed or unsupported lines. "
    "Detection is calculated on the complete loaded log; "
    "filters change the view only."
)


# --------------------------------------------------
# DASHBOARD TABS
# --------------------------------------------------

# Separate login trends, detected threats,
# and IP investigations into individual tabs.
activity_tab, alerts_tab, investigate_tab = st.tabs(
    [
        "📈 Login trends",
        "🚨 Threat alerts",
        "🔍 IP investigation",
    ]
)


# ==================================================
# TAB 1: LOGIN ACTIVITY
# ==================================================

with activity_tab:

    # Let users choose how authentication activity
    # should be grouped over time.
    interval = st.selectbox(
        "Group login activity by",
        [
            "5 minutes",
            "15 minutes",
            "1 hour",
            "1 day",
        ],
        index=1,
    )

    # Convert selected intervals into Pandas frequencies.
    grouping = {
        "5 minutes": "5min",
        "15 minutes": "15min",
        "1 hour": "h",
        "1 day": "D",
    }[interval]

    # Count successful and failed logins within
    # each selected time interval.
    timeline = timeline_frame(
        filtered_events,
        grouping,
    )

    st.markdown("### Login Activity Over Time")

    st.caption(
        "**X-axis:** Date and time when login attempts occurred. "
        "**Y-axis:** Number of login attempts during each interval. "
        "**Lines:** Successful logins and failed logins."
    )


    # ----------------------------------------------
    # LOGIN ACTIVITY LINE GRAPH
    # ----------------------------------------------

    if timeline.empty:

        st.info(
            "No events in this selection."
        )

    else:

        # Reshape the data so successful and failed
        # logins can be displayed as separate lines.
        timeline_long = timeline.melt(
            id_vars="timestamp",
            value_vars=["success", "failed"],
            var_name="login_result",
            value_name="login_count",
        )

        # Replace internal status values with
        # readable descriptions in the chart legend.
        timeline_long["login_result"] = (
            timeline_long["login_result"].map({
                "success": "Successful logins",
                "failed": "Failed logins",
            })
        )

        # Create the line graph:
        # X-axis = Date and time
        # Y-axis = Number of login attempts
        # Color  = Successful or failed login result
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
                    title=(
                        f"Login attempts per "
                        f"{interval.lower()}"
                    ),
                    axis=alt.Axis(
                        tickMinStep=1,
                    ),
                ),

                color=alt.Color(
                    "login_result:N",
                    title="Login result",
                ),

                # Show additional information when
                # the user hovers over a data point.
                tooltip=[
                    alt.Tooltip(
                        "timestamp:T",
                        title="Time",
                        format="%b %d, %Y %I:%M %p",
                    ),

                    alt.Tooltip(
                        "login_result:N",
                        title="Result",
                    ),

                    alt.Tooltip(
                        "login_count:Q",
                        title="Login attempts",
                        format="d",
                    ),
                ],
            )
            .properties(
                height=350,
            )
        )

        st.altair_chart(
            activity_chart,
            use_container_width=True,
        )

    st.info(
        "How to read this graph: "
        "If the failed-login line reaches 7 at 9 AM "
        "while using 1-hour grouping, it means "
        "7 failed login attempts occurred "
        "between 9:00 AM and 9:59 AM."
    )


    # ----------------------------------------------
    # LOGIN EVENTS TABLE
    # ----------------------------------------------

    # Display matching log entries in reverse
    # chronological order for easier investigation.
    st.markdown("### Login Events")

    st.dataframe(
        filtered_events.sort_values(
            "timestamp",
            ascending=False,
        ),
        use_container_width=True,
        hide_index=True,
    )


    # Export filtered authentication events to CSV.
    st.download_button(
        "Download filtered login events (CSV)",
        data=filtered_events.to_csv(
            index=False
        ).encode("utf-8"),
        file_name="login_events.csv",
        mime="text/csv",
    )


# ==================================================
# TAB 2: THREAT ALERTS
# ==================================================

with alerts_tab:

    # Retrieve available threat detection rules.
    rules = sorted(
        all_alerts["rule"].dropna().unique().tolist()
    )

    # Allow users to display specific detection types.
    chosen_rules = st.multiselect(
        "Detection rules",
        rules,
        default=rules,
    )

    visible_alerts = filtered_alerts[
        filtered_alerts["rule"].isin(chosen_rules)
    ]


    # ----------------------------------------------
    # DETECTED THREATS TABLE
    # ----------------------------------------------

    if visible_alerts.empty:

        st.info(
            "No alerts match the current filters. "
            "Try another log, date, or severity."
        )

    else:

        st.markdown("### Detected Threats")

        st.dataframe(
            visible_alerts,
            use_container_width=True,
            hide_index=True,
        )

        st.markdown("### Alerts by Detection Rule")

        st.caption(
            "**X-axis:** Number of security alerts. "
            "**Y-axis:** Type of security detection. "
            "Each bar shows how many times a rule triggered."
        )


        # ------------------------------------------
        # DETECTION RULE LABELS
        # ------------------------------------------

        # Convert rule identifiers into readable names.
        rule_labels = {
            "brute_force": "Brute force",
            "password_spraying": "Password spraying",
            "success_after_failures": (
                "Successful login after failures"
            ),
        }


        # ------------------------------------------
        # COUNT ALERTS BY DETECTION RULE
        # ------------------------------------------

        # Count how many times each rule was triggered.
        counts_by_rule = (
            visible_alerts["rule"]
            .value_counts()
            .rename_axis("rule")
            .reset_index(name="alert_count")
        )

        counts_by_rule["rule_label"] = (
            counts_by_rule["rule"]
            .map(rule_labels)
            .fillna(counts_by_rule["rule"])
        )


        # ------------------------------------------
        # HORIZONTAL BAR CHART
        # ------------------------------------------

        # Create horizontal bars so detection names
        # remain readable from left to right.
        #
        # X-axis = Number of security alerts
        # Y-axis = Detection rule

        alerts_chart = (
            alt.Chart(counts_by_rule)
            .mark_bar()
            .encode(

                x=alt.X(
                    "alert_count:Q",
                    title="Number of alerts",
                    axis=alt.Axis(
                        tickMinStep=1,
                    ),
                ),

                y=alt.Y(
                    "rule_label:N",
                    title="Detection rule",
                    sort="-x",
                    axis=alt.Axis(
                        labelAngle=0,
                        labelLimit=320,
                    ),
                ),

                tooltip=[
                    alt.Tooltip(
                        "rule_label:N",
                        title="Detection rule",
                    ),

                    alt.Tooltip(
                        "alert_count:Q",
                        title="Number of alerts",
                        format="d",
                    ),
                ],
            )
            .properties(
                height=230,
            )
        )

        st.altair_chart(
            alerts_chart,
            use_container_width=True,
        )


    # Export filtered security alerts to CSV.
    st.download_button(
        "Download filtered threat alerts (CSV)",
        data=visible_alerts.to_csv(
            index=False
        ).encode("utf-8"),
        file_name="threat_alerts.csv",
        mime="text/csv",
    )


# ==================================================
# TAB 3: IP INVESTIGATION
# ==================================================

with investigate_tab:

    # ----------------------------------------------
    # IP ACTIVITY SUMMARY
    # ----------------------------------------------

    # Display per-IP login statistics from the
    # complete source log.
    st.markdown("### IP Activity Summary")

    st.dataframe(
        filtered_summary,
        use_container_width=True,
        hide_index=True,
    )

    # Export the IP summary for further investigation.
    st.download_button(
        "Download IP summary (CSV)",
        data=filtered_summary.to_csv(
            index=False
        ).encode("utf-8"),
        file_name="security_report.csv",
        mime="text/csv",
    )


    # ----------------------------------------------
    # TOP IP ADDRESSES BY FAILED LOGINS
    # ----------------------------------------------

    st.markdown(
        "### Top IPs by Failed Login Attempts"
    )

    if not filtered_events.empty:

        # Count failed login attempts from each IP
        # and select the ten highest counts.
        top_ips = (
            filtered_events.loc[
                filtered_events["status"] == "failed",
                "ip_address",
            ]
            .value_counts()
            .head(10)
        )

        if not top_ips.empty:

            st.caption(
                "**X-axis:** Number of failed logins. "
                "**Y-axis:** Source IP address."
            )

            # Convert the IP counts into a DataFrame
            # that can be visualized using Altair.
            top_ip_counts = (
                top_ips
                .rename_axis("ip_address")
                .reset_index(name="failed_logins")
            )


            # --------------------------------------
            # HORIZONTAL IP BAR CHART
            # --------------------------------------

            # Display IP addresses horizontally.
            #
            # X-axis = Number of failed login attempts
            # Y-axis = Source IP address

            top_ip_chart = (
                alt.Chart(top_ip_counts)
                .mark_bar()
                .encode(

                    x=alt.X(
                        "failed_logins:Q",
                        title="Number of failed logins",
                        axis=alt.Axis(
                            tickMinStep=1,
                        ),
                    ),

                    y=alt.Y(
                        "ip_address:N",
                        title="Source IP address",
                        sort="-x",
                        axis=alt.Axis(
                            labelAngle=0,
                            labelLimit=320,
                        ),
                    ),

                    tooltip=[
                        alt.Tooltip(
                            "ip_address:N",
                            title="Source IP",
                        ),

                        alt.Tooltip(
                            "failed_logins:Q",
                            title="Failed logins",
                            format="d",
                        ),
                    ],
                )
                .properties(
                    height=310,
                )
            )

            st.altair_chart(
                top_ip_chart,
                use_container_width=True,
            )

        else:

            st.info(
                "No failed logins in the selected window."
            )

    else:

        st.info(
            "No logins for this selection."
        )

    # Explain why the summary table and the chart
    # may show different totals when dates are filtered.
    st.caption(
        "IP summary values are calculated across "
        "the complete loaded file, not just the "
        "selected date range. The timeline and "
        "top-IP chart use the date filter."
    )


# --------------------------------------------------
# FOOTER: SECURITY NOTICE
# --------------------------------------------------

# Remind users that this project is designed for
# learning and is not a production monitoring system.
st.divider()

st.caption(
    "Educational demonstration. Do not upload "
    "secrets or production authentication logs "
    "to a publicly hosted instance."
)
