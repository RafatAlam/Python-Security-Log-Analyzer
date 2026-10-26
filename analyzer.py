#!/usr/bin/env python3
"""Analyze authentication logs and report potentially suspicious login activity."""

from __future__ import annotations

import argparse
import csv
import re
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path


DEFAULT_LOG = Path("logs/auth.log")
DEFAULT_REPORT = Path("reports/security_report.csv")
TIMESTAMP_FORMAT = "%Y-%m-%d %H:%M:%S"

# Example:
# 2026-01-15 09:14:03 username=alex ip=192.0.2.10 status=failed
LOG_PATTERN = re.compile(
    r"^(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\s+"
    r"username=(?P<username>\S+)\s+"
    r"ip=(?P<ip>\S+)\s+"
    r"status=(?P<status>success|failed)$",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class LogEvent:
    timestamp: datetime
    username: str
    ip: str
    status: str


def parse_log_line(line: str) -> LogEvent | None:
    """Parse one supported log line. Return None for malformed records."""
    match = LOG_PATTERN.match(line.strip())
    if not match:
        return None

    try:
        timestamp = datetime.strptime(
            match.group("timestamp"), TIMESTAMP_FORMAT
        )
    except ValueError:
        return None

    return LogEvent(
        timestamp=timestamp,
        username=match.group("username"),
        ip=match.group("ip"),
        status=match.group("status").lower(),
    )


def load_events(log_path: Path) -> tuple[list[LogEvent], int]:
    """Load valid events and count malformed or unsupported lines."""
    events: list[LogEvent] = []
    invalid_count = 0

    with log_path.open("r", encoding="utf-8") as log_file:
        for line in log_file:
            if not line.strip():
                continue
            event = parse_log_line(line)
            if event is None:
                invalid_count += 1
            else:
                events.append(event)

    return events, invalid_count


def find_suspicious_ips(
    events: list[LogEvent],
    threshold: int = 5,
    window_minutes: int = 5,
) -> dict[str, dict[str, object]]:
    """
    Flag IPs with at least `threshold` failed attempts within a rolling window.

    The returned dictionary includes each flagged IP's total failed attempts,
    maximum failures within the window, and the window's end timestamp.
    """
    if threshold < 1:
        raise ValueError("threshold must be at least 1")
    if window_minutes < 1:
        raise ValueError("window_minutes must be at least 1")

    failures_by_ip: dict[str, list[datetime]] = defaultdict(list)
    for event in events:
        if event.status == "failed":
            failures_by_ip[event.ip].append(event.timestamp)

    window = timedelta(minutes=window_minutes)
    alerts: dict[str, dict[str, object]] = {}

    for ip, timestamps in failures_by_ip.items():
        timestamps.sort()
        left = 0
        max_count = 0
        max_end: datetime | None = None

        for right, current_time in enumerate(timestamps):
            while timestamps[left] < current_time - window:
                left += 1
            count = right - left + 1
            if count > max_count:
                max_count = count
                max_end = current_time

        if max_count >= threshold:
            alerts[ip] = {
                "total_failed_attempts": len(timestamps),
                "max_failures_in_window": max_count,
                "window_end": max_end.strftime(TIMESTAMP_FORMAT)
                if max_end
                else "",
            }

    return alerts


def analyze_events(
    events: list[LogEvent],
    threshold: int = 5,
    window_minutes: int = 5,
) -> dict[str, object]:
    """Calculate summary statistics and suspicious-IP details."""
    successful = sum(event.status == "success" for event in events)
    failed = sum(event.status == "failed" for event in events)
    failed_by_ip = Counter(
        event.ip for event in events if event.status == "failed"
    )
    failed_by_username = Counter(
        event.username for event in events if event.status == "failed"
    )

    return {
        "total_events": len(events),
        "successful_logins": successful,
        "failed_logins": failed,
        "failed_by_ip": failed_by_ip,
        "failed_by_username": failed_by_username,
        "alerts": find_suspicious_ips(events, threshold, window_minutes),
    }


def write_csv_report(
    report_path: Path,
    events: list[LogEvent],
    analysis: dict[str, object],
) -> None:
    """Write one row per IP address, including summary and alert details."""
    report_path.parent.mkdir(parents=True, exist_ok=True)
    failed_by_ip = analysis["failed_by_ip"]
    alerts = analysis["alerts"]

    all_ips = sorted({event.ip for event in events})
    with report_path.open("w", newline="", encoding="utf-8") as report_file:
        writer = csv.DictWriter(
            report_file,
            fieldnames=[
                "ip_address",
                "successful_logins",
                "failed_logins",
                "max_failures_in_window",
                "window_end",
                "alert",
            ],
        )
        writer.writeheader()

        for ip in all_ips:
            ip_events = [event for event in events if event.ip == ip]
            alert_info = alerts.get(ip, {})
            writer.writerow(
                {
                    "ip_address": ip,
                    "successful_logins": sum(
                        event.status == "success" for event in ip_events
                    ),
                    "failed_logins": failed_by_ip.get(ip, 0),
                    "max_failures_in_window": alert_info.get(
                        "max_failures_in_window", 0
                    ),
                    "window_end": alert_info.get("window_end", ""),
                    "alert": "SUSPICIOUS" if ip in alerts else "none",
                }
            )


def print_summary(
    analysis: dict[str, object],
    report_path: Path,
    invalid_count: int,
    threshold: int,
    window_minutes: int,
) -> None:
    """Print the analysis summary and any alerts."""
    print("\n=== Python Security Log Analyzer ===")
    print(f"Valid events:       {analysis['total_events']}")
    print(f"Successful logins:  {analysis['successful_logins']}")
    print(f"Failed logins:      {analysis['failed_logins']}")
    print(f"Invalid log lines:  {invalid_count}")
    print(
        f"Detection rule:     {threshold} failed attempts "
        f"within {window_minutes} minutes"
    )

    alerts = analysis["alerts"]
    if alerts:
        print("\nPotentially suspicious IP addresses:")
        for ip, details in sorted(alerts.items()):
            print(
                f"  {ip}: {details['max_failures_in_window']} failures "
                f"within the window; "
                f"{details['total_failed_attempts']} total failed attempts"
            )
    else:
        print("\nNo IP addresses met the configured alert threshold.")

    print(f"\nCSV report saved to: {report_path}")


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
    args = parser.parse_args()

    if args.threshold < 1 or args.window < 1:
        parser.error("--threshold and --window must be positive integers")
    if not args.log.is_file():
        parser.error(f"Log file not found: {args.log}")

    try:
        events, invalid_count = load_events(args.log)
    except OSError as error:
        parser.error(f"Could not read log file: {error}")

    analysis = analyze_events(events, args.threshold, args.window)

    try:
        write_csv_report(args.report, events, analysis)
    except OSError as error:
        parser.error(f"Could not write report: {error}")

    print_summary(
        analysis, args.report, invalid_count, args.threshold, args.window
    )


if __name__ == "__main__":
    main()
