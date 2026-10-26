# Python Security Log Analyzer

A Python-based cybersecurity tool that analyzes authentication logs, detects suspicious login activity, tracks failed login attempts by IP address, and generates security reports.

## Features

- Parse authentication logs containing timestamps, usernames, IP addresses, and login results.
- Count successful and failed login attempts.
- Track failed login attempts by IP address.
- Detect suspicious activity using configurable thresholds.
- Export security reports to CSV.
- Run automated unit tests.

## Technologies

- Python
- Regular Expressions (`re`)
- Collections (`Counter`, `defaultdict`)
- Pathlib
- CSV
- Unittest

## Project Structure

```text
python-security-log-analyzer/
├── logs/
│   └── auth.log
├── reports/
│   └── security_report.csv
├── analyzer.py
├── test_analyzer.py
├── requirements.txt
└── README.md