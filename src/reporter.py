"""Generate CSV reports and a terminal summary."""

from __future__ import annotations

import csv
from pathlib import Path

from .models import LogEvent


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


def write_alert_report(report_path: Path, alerts: list[dict[str, str | int]]) -> None:
    """Write detailed detections to a second CSV report."""
    report_path.parent.mkdir(parents=True, exist_ok=True)
    fields = ["timestamp", "ip_address", "rule", "severity", "count", "details"]
    with report_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(alerts)


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
