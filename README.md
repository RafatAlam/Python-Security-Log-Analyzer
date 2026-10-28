
# Python Security Log Analyzer

A Python-based cybersecurity tool that analyzes authentication logs, detects suspicious login activity, and generates security reports. The project supports custom authentication logs and Linux SSH logs, using rule-based detection to identify potential security threats.

## Features

- Parse authentication logs containing timestamps, usernames, IP addresses, and login results.
- Support custom authentication logs and Linux SSH logs.
- Track successful and failed login attempts.
- Group failed login attempts by IP address and username.
- Detect suspicious login patterns using configurable thresholds.
- Identify brute-force attacks and password-spraying attempts.
- Flag successful logins following repeated failed attempts.
- Assign severity levels to detected threats.
- Generate CSV reports for further investigation.
- Validate functionality through automated unit tests.

## Technologies Used

- **Python:** Main programming language.
- **Regular Expressions (`re`):** Parse authentication log entries.
- **Collections (`Counter`, `defaultdict`):** Organize and count login activity.
- **Datetime:** Analyze login attempts within specific time windows.
- **Pathlib:** Handle file paths and directories.
- **CSV:** Generate security reports.
- **Argparse:** Configure detection thresholds through command-line arguments.
- **Unittest:** Test log parsing, threat detection, and report generation.

## Project Structure

```text
Python-Security-Log-Analyzer/
├── analyzer.py
├── src/
│   ├── __init__.py
│   ├── models.py
│   ├── parser.py
│   ├── detector.py
│   └── reporter.py
├── tests/
│   ├── __init__.py
│   ├── test_parser.py
│   └── test_detector.py
├── logs/
│   ├── auth.log
│   ├── ssh_auth.log
│   └── phase2_demo.log
├── reports/
│   ├── security_report.csv
│   └── threat_alerts.csv
├── requirements.txt
├── .gitignore
└── README.md
```

## Installation

### Requirements

- Python 3.10 or newer
- No external dependencies required.

### Clone the Repository

```bash
git clone https://github.com/YOUR_USERNAME/Python-Security-Log-Analyzer.git
cd Python-Security-Log-Analyzer
```

Replace `YOUR_USERNAME` with your GitHub username.

## Usage

### Run the Analyzer

Analyze the default authentication log:

```bash
python analyzer.py
```

Analyze Linux SSH authentication logs:

```bash
python analyzer.py --log logs/ssh_auth.log --year 2026
```

Run the Phase 2 threat detection demonstration:

```bash
python analyzer.py --log logs/phase2_demo.log --year 2026
```

### Configure Detection Thresholds

Detection thresholds and time windows can be customized using command-line arguments:

```bash
python analyzer.py --log logs/phase2_demo.log --year 2026 --threshold 5 --window 5 --spray-users 5 --spray-window 10 --success-failures 3 --success-window 10
```

## Threat Detection

The analyzer uses three primary detection rules to identify potentially suspicious authentication activity.

| Detection Rule | Description | Severity |
|---|---|---|
| Brute Force | 5 or more failed login attempts from one IP within 5 minutes | HIGH |
| Password Spraying | Failed login attempts against 5 or more distinct usernames from one IP within 10 minutes | HIGH |
| Success After Failures | Successful login following 3 or more failures from the same IP within 10 minutes | CRITICAL |

Detection thresholds can be modified through command-line arguments.

Alerts indicate potentially suspicious behavior and do not independently confirm malicious activity.

## Security Reports

The analyzer generates two CSV reports inside the `reports/` directory.

### Security Report

`reports/security_report.csv`

Contains:
- IP addresses
- Successful login counts
- Failed login counts
- Maximum failed attempts within the configured window
- Detection status

### Threat Alerts

`reports/threat_alerts.csv`

Contains:
- Detection timestamps
- Source IP addresses
- Detection rules
- Severity levels
- Attempt counts
- Alert descriptions

Both reports are automatically generated when the analyzer runs successfully.

## Running Tests

This project uses Python's built-in `unittest` framework to validate log parsing, threat detection, and report generation.

Run all tests from the project's root directory:

```bash
python -m unittest discover -s tests -p "test_*.py" -v
```

The test suite includes 21 tests covering:

- Authentication log parsing
- Linux SSH log parsing
- Successful and failed login analysis
- Brute-force detection
- Password-spraying detection
- Successful logins following failed attempts
- Time-window detection
- CSV report generation
- Invalid log handling
- Detection threshold validation

If all tests pass, the terminal displays:

```text
----------------------------------------------------------------------
Ran 21 tests

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