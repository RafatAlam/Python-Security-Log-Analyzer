# Python Security Log Analyzer

A Python-based cybersecurity project that parses authentication logs, summarizes login activity, detects repeated failed logins within a rolling time window, and exports a CSV report.

## Features

- Parse timestamped authentication records.
- Count successful and failed logins.
- Group failed attempts by IP address and username.
- Detect IP addresses with repeated failed logins within a configurable time window.
- Export per-IP findings to CSV.
- Count malformed log records.
- Run automated unit tests with `unittest`.

## Technologies

- Python 3.9+
- `re` for log parsing
- `collections.Counter` and `defaultdict` for aggregation
- `datetime` for time-window analysis
- `csv` and `pathlib` for report and file handling
- `unittest` for automated testing

## Project Structure

```text
python-security-log-analyzer/
├── logs/
│   └── auth.log
├── reports/
├── analyzer.py
├── test_analyzer.py
├── requirements.txt
└── README.md
```

## Getting Started

No third-party packages are required. Install Python 3.9 or newer, clone the repository, and move into the project directory.

```bash
git clone <repository-url>
cd python-security-log-analyzer
```

Run the analyzer with the default sample log:

```bash
python analyzer.py
```

By default, the analyzer flags IP addresses with at least five failed login attempts in a five-minute rolling window. The CSV report is written to `reports/security_report.csv`.

### Configure Detection

Set a different threshold or time window:

```bash
python analyzer.py --threshold 3 --window 5
```

Use a different log or report path:

```bash
python analyzer.py --log logs/auth.log --report reports/security_report.csv
```

## Log Format

Each supported record follows this format:

```text
2026-01-15 09:14:03 username=alex ip=192.0.2.10 status=failed
```

The timestamp format is `YYYY-MM-DD HH:MM:SS`. Status must be `success` or `failed`.

## Run Tests

```bash
python -m unittest -v
```
