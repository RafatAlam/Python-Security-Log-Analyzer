#!/usr/bin/env python3
"""Command-line entry point for the Python Security Log Analyzer."""

from __future__ import annotations

import argparse
from datetime import datetime
from pathlib import Path

from src.parser import load_events
from src.detector import analyze_events, detect_threats
from src.reporter import write_csv_report, write_alert_report, print_summary


DEFAULT_LOG = Path("logs/auth.log")
DEFAULT_REPORT = Path("reports/security_report.csv")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Analyze authentication logs for repeated failed logins."
    )
    parser.add_argument(
        "--log",
        type=Path,
        default=DEFAULT_LOG,
        help=f"Path to the authentication log (default: {DEFAULT_LOG})",
    )
    parser.add_argument(
        "--report",
        type=Path,
        default=DEFAULT_REPORT,
        help=f"CSV output path (default: {DEFAULT_REPORT})",
    )
    parser.add_argument(
        "--threshold",
        type=int,
        default=5,
        help="Failed attempts needed to trigger an alert (default: 5)",
    )
    parser.add_argument(
        "--window",
        type=int,
        default=5,
        help="Rolling detection window in minutes (default: 5)",
    )
    parser.add_argument(
        "--year", type=int, default=datetime.now().year,
        help="Year for SSH syslog timestamps (which omit the year)",
    )
    parser.add_argument(
        "--alerts-report", type=Path, default=Path("reports/threat_alerts.csv"),
        help="Detailed threat alert CSV path",
    )
    parser.add_argument("--spray-users", type=int, default=5,
                        help="Distinct usernames for password-spraying detection")
    parser.add_argument("--spray-window", type=int, default=10,
                        help="Password-spraying window in minutes")
    parser.add_argument("--success-failures", type=int, default=3,
                        help="Failures preceding a successful login")
    parser.add_argument("--success-window", type=int, default=10,
                        help="Success-after-failures window in minutes")
    args = parser.parse_args()

    if any(v < 1 for v in (
        args.threshold, args.window, args.spray_users, args.spray_window,
        args.success_failures, args.success_window
    )):
        parser.error("All detection thresholds and windows must be positive integers")
    if not args.log.is_file():
        parser.error(f"Log file not found: {args.log}")

    try:
        events, invalid_count = load_events(args.log, year=args.year)
    except OSError as error:
        parser.error(f"Could not read log file: {error}")

    analysis = analyze_events(events, args.threshold, args.window)

    try:
        write_csv_report(args.report, events, analysis)
    except OSError as error:
        parser.error(f"Could not write report: {error}")

    alerts = detect_threats(
        events, args.threshold, args.window,
        args.spray_users, args.spray_window,
        args.success_failures, args.success_window,
    )
    try:
        write_alert_report(args.alerts_report, alerts)
    except OSError as error:
        parser.error(f"Could not write alert report: {error}")

    print_summary(
        analysis, args.report, invalid_count, args.threshold, args.window
    )
    print(f"\nThreat alerts: {len(alerts)}")
    for alert in alerts:
        print(f"  [{alert['severity']}] {alert['rule']} "
              f"| {alert['ip_address']} | {alert['timestamp']} "
              f"| {alert['details']}")
    print(f"Detailed alert report saved to: {args.alerts_report}")


if __name__ == "__main__":
    main()
