
# Python Security Log Analyzer

A Python-based cybersecurity tool that analyzes authentication logs, detects suspicious login activity, and generates security reports. The project supports custom authentication logs and Linux SSH logs, using rule-based detection to identify potential security threats.

An interactive Streamlit dashboard provides visualizations of login activity, security alerts, and IP-based investigations.

## Features

### Authentication Log Analysis
- Parse custom authentication logs and Linux SSH logs.
- Extract timestamps, usernames, IP addresses, and login results.
- Track successful and failed login attempts.
- Group authentication activity by IP address and username.
- Identify malformed or unsupported log entries.

### Threat Detection
- Detect repeated failed login attempts that may indicate brute-force attacks.
- Identify password-spraying attempts across multiple usernames.
- Flag successful logins following repeated failed attempts.
- Analyze login activity using configurable time windows.
- Assign severity levels to detected threats.
- Generate detailed security alerts for further investigation.

### Interactive Security Dashboard
- Visualize successful and failed logins over time.
- Display authentication activity using interactive line graphs.
- View security alerts with horizontal bar charts.
- Filter authentication events by date range and IP address.
- Filter security alerts by severity and detection rule.
- Investigate IP addresses with high numbers of failed logins.
- Adjust detection thresholds directly from the dashboard.
- Upload supported authentication log files for analysis.
- Download filtered security reports as CSV files.

## Technologies Used

- **Python:** Main programming language.
- **Streamlit:** Interactive web dashboard.
- **Pandas:** Data processing, filtering, and aggregation.
- **Altair:** Interactive charts and data visualizations.
- **Regular Expressions (`re`):** Authentication log parsing.
- **Collections (`Counter`, `defaultdict`):** Tracking and organizing login activity.
- **Datetime:** Time-based threat detection and log analysis.
- **Pathlib:** File handling and directory management.
- **CSV:** Exporting security reports.
- **Argparse:** Command-line configuration.
- **Unittest:** Automated testing of project functionality.

## Project Structure

```text
Python-Security-Log-Analyzer/
├── analyzer.py
├── dashboard.py
├── src/
│   ├── __init__.py
│   ├── models.py
│   ├── parser.py
│   ├── detector.py
│   ├── reporter.py
│   └── dashboard_data.py
├── tests/
│   ├── __init__.py
│   ├── test_parser.py
│   ├── test_detector.py
│   └── test_dashboard_data.py
├── logs/
│   ├── auth.log
│   ├── ssh_auth.log
│   ├── phase2_demo.log
│   └── dashboard_demo.log
├── reports/
│   └── .gitkeep
├── requirements.txt
├── .gitignore
└── README.md
```

## Installation

### Requirements

- Python 3.10 or newer
- pip

### Clone the Repository

```bash
git clone https://github.com/YOUR_USERNAME/Python-Security-Log-Analyzer.git
cd Python-Security-Log-Analyzer
```

Replace `YOUR_USERNAME` with your GitHub username.

### Install Dependencies

Install the required Python libraries:

```bash
python -m pip install -r requirements.txt
```

The dashboard uses Streamlit, Pandas, and Altair. The command-line analyzer uses Python's standard library.

## Usage

### Run the Command-Line Analyzer

Analyze the default authentication log:

```bash
python analyzer.py
```

Analyze Linux SSH authentication logs:

```bash
python analyzer.py --log logs/ssh_auth.log --year 2026
```

Run the advanced threat detection demonstration:

```bash
python analyzer.py --log logs/phase2_demo.log --year 2026
```

### Configure Detection Thresholds

Customize detection thresholds and time windows using command-line arguments:

```bash
python analyzer.py --log logs/phase2_demo.log --year 2026 --threshold 5 --window 5 --spray-users 5 --spray-window 10 --success-failures 3 --success-window 10
```

### Launch the Security Dashboard

Start the Streamlit dashboard:

```bash
python -m streamlit run dashboard.py
```

The dashboard will open in your browser at:

```text
http://localhost:8501
```

You can select bundled sample logs or upload your own supported authentication logs.

## Threat Detection

The analyzer uses three primary detection rules.

| Detection Rule | Description | Severity |
|---|---|---|
| Brute Force | 5 or more failed logins from the same IP within 5 minutes | HIGH |
| Password Spraying | Failed login attempts against 5 or more distinct usernames from the same IP within 10 minutes | HIGH |
| Success After Failures | A successful login following 3 or more failures from the same IP within 10 minutes | CRITICAL |

Detection thresholds and time windows can be modified through the command line or the dashboard.

Alerts indicate potentially suspicious behavior and do not independently confirm malicious activity.

## Security Dashboard

The Streamlit dashboard provides an interactive interface for investigating authentication logs and reviewing detected threats.

### Login Trends

Displays authentication activity over time using an interactive line graph.

- **X-axis:** Date and time of authentication activity.
- **Y-axis:** Number of login attempts within the selected interval.
- **Lines:** Successful and failed login attempts.

Available time intervals include:
- 5 minutes
- 15 minutes
- 1 hour
- 1 day

The dashboard also includes a table of authentication events and an option to export the filtered results.

### Threat Alerts

Displays detected security threats and their severity levels.

The horizontal bar chart shows:
- **X-axis:** Number of security alerts.
- **Y-axis:** Detection rule.

The dashboard supports filtering by detection rule and severity.

Each alert includes its timestamp, source IP address, detection type, severity, and supporting details.

### IP Investigation

Provides an overview of authentication activity associated with individual IP addresses.

Features include:
- Successful and failed login counts.
- IP-based authentication summaries.
- Top IP addresses by failed login attempts.
- Interactive horizontal bar charts.
- CSV exports for further investigation.

### Investigation Filters

The dashboard supports filtering by:
- Source IP address
- Date range
- Alert severity
- Detection rule

Detection rules are evaluated against the complete loaded log. Filters change which events and alerts are displayed.

The IP summary table uses statistics from the complete log, while the login timeline and top-IP chart respect the selected date range.

## Security Reports

The command-line analyzer generates two CSV reports inside the `reports/` directory.

### Security Report

`reports/security_report.csv`

Contains:
- Source IP addresses
- Successful login counts
- Failed login counts
- Maximum failed attempts within the configured time window
- Alert status

### Threat Alerts

`reports/threat_alerts.csv`

Contains:
- Detection timestamps
- Source IP addresses
- Detection rules
- Severity levels
- Attempt counts
- Alert descriptions

The dashboard also allows users to download filtered authentication events, threat alerts, and IP summaries directly through the interface.

Generated CSV reports are excluded from Git tracking through `.gitignore`.

## Running Tests

This project uses Python's built-in `unittest` framework to validate authentication log parsing, threat detection, report generation, and dashboard data processing.

Run all tests from the project's root directory:

```bash
python -m unittest discover -s tests -p "test_*.py" -v
```

The test suite includes 31 automated tests covering:

- Custom authentication log parsing
- Linux SSH log parsing
- Successful and failed login analysis
- Brute-force detection
- Password-spraying detection
- Successful logins following failed attempts
- Time-window detection
- CSV report generation
- Invalid log handling
- Detection threshold validation
- Dashboard data processing and filtering

If all tests pass, the terminal displays:

```text
----------------------------------------------------------------------
Ran 31 tests

OK
```

## Example Authentication Logs

### Custom Authentication Log

```text
2026-01-15 09:14:03 username=alex ip=192.0.2.10 status=failed
2026-01-15 09:14:18 username=alex ip=192.0.2.10 status=failed
2026-01-15 09:14:41 username=alex ip=192.0.2.10 status=success
```

### Linux SSH Authentication Log

```text
Jan 15 09:14:03 server sshd[1234]: Failed password for invalid user admin from 203.0.113.25 port 55234 ssh2
Jan 15 09:14:18 server sshd[1235]: Failed password for root from 203.0.113.25 port 55235 ssh2
Jan 15 09:14:41 server sshd[1236]: Accepted password for alex from 192.0.2.10 port 55236 ssh2
```

Traditional SSH syslog timestamps do not include a year. The analyzer allows users to specify a year when processing these logs.

## Testing with Sample Data

The `logs/` directory contains synthetic authentication logs for testing different security scenarios.

Available sample files include:

- `auth.log` — Basic authentication activity.
- `ssh_auth.log` — Linux SSH authentication records.
- `phase2_demo.log` — Brute-force, password-spraying, and success-after-failures scenarios.
- `dashboard_demo.log` — Larger authentication dataset for dashboard visualizations.

To test the dashboard:

1. Launch Streamlit.
2. Select a bundled sample log.
3. Review successful and failed login statistics.
4. Explore the Login Trends, Threat Alerts, and IP Investigation tabs.
5. Change the date range and detection thresholds.
6. Download filtered CSV reports.

You can also upload a supported `.log` or `.txt` file to analyze your own authorized sample data.

## Security Considerations

- Use synthetic or properly sanitized authentication logs.
- Do not commit credentials or sensitive authentication information.
- Detection rules may produce false positives.
- Shared IP addresses can affect detection accuracy.
- Not all Linux authentication log formats are supported.
- Uploaded dashboard logs are processed in memory.
- Do not upload sensitive production logs to a publicly hosted dashboard.
- This project is intended for educational purposes and is not a replacement for production security monitoring systems.