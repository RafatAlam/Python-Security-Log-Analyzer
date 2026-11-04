# Python Security Log Analyzer

A Python cybersecurity portfolio project that analyzes authentication logs, detects suspicious login activity, and provides a Streamlit dashboard. **Phase 4 adds continuous log monitoring, automated alerts, persistent alert history, optional webhook notifications, and an automatically refreshing dashboard.**

## Features

- Parse custom authentication records and common Linux OpenSSH login events.
- Analyze successful and failed logins by IP address and username.
- Detect **brute-force attempts**, **password spraying**, and **successful logins after repeated failures** using configurable time windows.
- Export per-IP summaries and threat alerts as CSV using the command-line analyzer.
- Explore login trends, threat severity, IP activity, and filters in a Streamlit dashboard.
- **Watch newly appended log entries** without restarting the analyzer.
- **Print security notifications immediately**, optionally with a terminal beep.
- **Save live alerts to JSONL** for later review and display them in an automatically refreshed dashboard tab.
- **Auto-refresh every dashboard chart, login counter, detection table, and IP investigation view every five seconds** when monitoring a growing local log.
- Optionally send alerts through a **Discord or Slack webhook**, with explicit opt-in.
- Run automated unit tests for parsing, detection, reporting, dashboard data processing, and live monitoring.

## Technologies

Python 3.10+, `re`, `ipaddress`, `collections`, `datetime`, `pathlib`, `csv`, `argparse`, `json`, `urllib.request`, `unittest`, **Streamlit**, **Pandas**, and **Altair**.

## Project structure

```text
Python-Security-Log-Analyzer/
├── analyzer.py                 # Phase 1–2: batch CLI analyzer
├── dashboard.py                # Phase 3–4: charts and live alerts
├── run_monitor.py              # Phase 4: launch live monitoring
├── simulate_logins.py          # Phase 4: generate demo log activity
├── src/
│   ├── __init__.py
│   ├── models.py
│   ├── parser.py
│   ├── detector.py
│   ├── reporter.py
│   ├── dashboard_data.py
│   └── monitor_engine.py       # File following, live detection, notifications
├── tests/
│   ├── __init__.py
│   ├── test_parser.py
│   ├── test_detector.py
│   ├── test_dashboard_data.py
│   ├── test_monitor_engine.py
│   └── test_live_dashboard.py
├── logs/
│   ├── auth.log
│   ├── ssh_auth.log
│   ├── phase2_demo.log
│   ├── dashboard_demo.log
│   └── live_demo.log           # Created by simulator; ignored by Git
├── reports/
│   └── .gitkeep                 # Reports are generated locally
├── requirements.txt
├── .gitignore
└── README.md
```

## Installation

Install Python 3.10 or newer, then clone the repository and install the dashboard dependencies:

```powershell
git clone https://github.com/YOUR_USERNAME/Python-Security-Log-Analyzer.git
cd Python-Security-Log-Analyzer
python -m pip install -r requirements.txt
```

Replace `YOUR_USERNAME` with your GitHub username. The batch analyzer and live monitor use only the Python standard library; the dashboard additionally needs Streamlit, Pandas, and Altair.

## Phase 4: Live monitoring demonstration

**Use two VS Code terminals in your project root.** The monitor continues running until you stop it with Ctrl+C.

### Terminal 1 — Start monitoring

```powershell
python run_monitor.py --log logs/live_demo.log --beep
```

By default the monitor starts at the **end of the file**: it only processes lines appended after it starts. This prevents re-alerting on old events. You can omit `--beep` for silent operation.

### Terminal 2 — Simulate incoming login events

```powershell
python simulate_logins.py --log logs/live_demo.log --delay 0.5
```

The simulator creates or appends to `logs/live_demo.log` using documentation-only IP ranges. The file is ignored by Git. The monitor should display four alerts from the demo: two brute-force alerts, one password-spraying alert, and one critical alert for a successful login following failures. **The demo log is not real attack traffic.**

Example alerts:

```text
[LIVE HIGH] brute_force | 203.0.113.10 | ...
[LIVE HIGH] brute_force | 198.51.100.20 | ...
[LIVE HIGH] password_spraying | 198.51.100.20 | ...
[LIVE CRITICAL] success_after_failures | 192.0.2.30 | ...
```

New alerts are appended to `reports/live_alerts.jsonl`. This local file is generated automatically and ignored by Git.

### View the live dashboard

Open a **third terminal**:

```powershell
python -m streamlit run dashboard.py
```

Open http://localhost:8501. In the sidebar under **Data source**, select **Live monitoring (auto-refresh)**.

All of the following now refresh automatically about every five seconds as new events are appended to `logs/live_demo.log`:

- Login Trends graph and login-events table
- Successful/failed login counters and detected-threat counters
- Threat Alerts table and horizontal alert chart
- IP Investigation summary and Top IPs bar chart
- Live Alerts tab (reads the independently saved `reports/live_alerts.jsonl`)

The **Show all dates (follow new events)** option is on by default in live mode. It automatically includes newly added dates, including events after midnight. Turn it off to select a fixed date range. IP, severity, detection-rule and time-grouping filters remain usable while live data updates.

The dashboard only **reads** the monitored log; keep `run_monitor.py` running to generate persistent notifications. The plots are recomputed from the log file, so the chart alert count may differ from the monitor's saved notification count after restarts/replays or when thresholds differ. You do not need to upload `live_demo.log` for live mode.

**Important:** The monitor's `--log` path and the dashboard's live mode must refer to the same file: `logs/live_demo.log`. The dashboard reads up to 5 MB per refresh, so use a small log for this demo.

### Monitor an existing log file once

Use `--from-start` to process records already present instead of waiting for new activity. Use `--once` to exit after scanning them:

```powershell
python run_monitor.py --log logs/phase2_demo.log --year 2026 --from-start --once
```

`--from-start` is intended for small demo files and for rebuilding in-memory detection state. The monitor remembers previously saved alert identifiers in its JSONL history and avoids repeating those notifications when replaying the same file.

### Change live detection rules

```powershell
python run_monitor.py --log logs/live_demo.log --threshold 5 --window 5 --spray-users 5 --spray-window 10 --success-failures 3 --success-window 10
```

### Optional Discord or Slack webhook alerts

Webhook notifications are **off by default**. They send alert metadata (including the IP address and detection details) to the chosen external service. Only enable them for authorized, non-sensitive logs.

**Windows PowerShell:**

```powershell
$env:SECURITY_LOG_WEBHOOK_URL = "https://YOUR-WEBHOOK-URL"
python run_monitor.py --log logs/live_demo.log --webhook --webhook-format discord
```

For Slack, use `--webhook-format slack`. Keep webhook URLs secret. Do **not** commit them to your repository, paste real URLs into the README, or print them in your demo video. The webhook is optional: terminal notifications and local JSONL alerts work without it.

## Phase 1–2: Batch command-line analysis

Run the original analyzer:

```powershell
python analyzer.py
```

Analyze existing SSH records:

```powershell
python analyzer.py --log logs/phase2_demo.log --year 2026
```

The batch analyzer creates `reports/security_report.csv` and `reports/threat_alerts.csv`.

## Phase 3: Interactive dashboard

```powershell
python -m streamlit run dashboard.py
```

The dashboard shows:

- **Login trends** line graph: X-axis = time; Y-axis = logins per chosen interval; lines = successful and failed logins.
- **Threat alerts** horizontal bar graph: X-axis = number of alerts; Y-axis = detection rule.
- **IP investigation** horizontal bar graph: X-axis = failed login counts; Y-axis = source IP addresses.
- **Live alerts**: saved alerts from the running Phase 4 monitor, refreshing every five seconds.
- **Live monitoring (auto-refresh)**: every dashboard tab and summary metric reloads `logs/live_demo.log` every five seconds, not just the saved alert feed.

The dashboard supports uploading `.log` or `.txt` files, changing date/IP/severity filters, tuning detection thresholds, and exporting filtered CSV data. To view incoming events without manual refresh or uploads, select the live monitoring data source.

## Detection rules

| Detection | Default threshold | Severity |
|---|---|---|
| Brute force | 5+ failed attempts from one IP in 5 minutes | HIGH |
| Password spraying | Failures against 5+ different usernames from one IP in 10 minutes | HIGH |
| Success after failures | Successful login after 3+ failures from the same IP in 10 minutes | CRITICAL |

These are heuristics. A flag does not confirm malicious activity, and shared IP addresses can produce false positives.

## Testing

Run all automated tests from the **project root**:

```powershell
python -m unittest discover -s tests -p "test_*.py" -v
```

The suite includes tests for log parsing, Linux SSH formats, detection windows, CSV reports, dashboard data transforms, freshly appended events in the live dashboard, partial lines, truncation, deduplication, JSONL persistence, and webhook payloads.

## Security and limitations

- Use only synthetic, authorized, or properly sanitized authentication logs.
- Local live-alert history contains IP addresses and detection details. The file is ignored by Git, but **is still stored on your computer**; delete it if it contains information that should not be retained.
- The monitor must remain running to catch new activity; this is not an installed Windows service.
- The monitor assumes records are appended in chronological event-time order per IP. It skips late/out-of-order records, and the current parser supports only known custom and OpenSSH formats.
- Traditional Linux SSH syslog timestamps omit the year; use `--year` for archived logs. Automatic year rollover and timezone conversion are not implemented.
- File following handles incomplete lines and common rotation/truncation cases, but may miss writes during shutdown or unusually fast file rotation.
- Saved alert IDs are used to prevent duplicate notifications upon replay; the monitor's rolling detection context is in memory. For reliable state reconstruction after restarts, use `--from-start` with a small known log.
- The live dashboard reads local `logs/live_demo.log` and `reports/live_alerts.jsonl`; remote deployment requires shared persistent storage or a database/queue integration.
- The live dashboard rereads the entire log file on each 5-second refresh (up to 5 MB), so this design is for demos and small logs rather than high-volume production monitoring.
- Optional webhooks send data outside your computer. Do not enable them with sensitive records unless you have permission.
- This is an educational prototype, not production monitoring or an incident-response system.
