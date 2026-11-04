#!/usr/bin/env python3
"""Phase 4: Watch authentication logs and create real-time security alerts.

Examples:
    python run_monitor.py
    python run_monitor.py --log logs/phase2_demo.log --from-start --once --year 2026
    python run_monitor.py --log logs/live_demo.log --beep
"""

from __future__ import annotations

import argparse
import os
import time
from datetime import datetime
from pathlib import Path

from src.monitor_engine import (
    FileFollower, LiveThreatMonitor, alert_key, notify_alert,
    read_alert_history,
)


# --------------------------------------------------
# MONITOR CONFIGURATION
# --------------------------------------------------

DEFAULT_LOG = Path("logs/live_demo.log")
DEFAULT_ALERT_REPORT = Path("reports/live_alerts.jsonl")


def main() -> None:
    """Monitor new log entries until interrupted (Ctrl+C)."""
    parser = argparse.ArgumentParser(
        description="Watch a growing authentication log and notify on new threats."
    )
    parser.add_argument("--log", type=Path, default=DEFAULT_LOG,
                        help=f"Log file to watch (default: {DEFAULT_LOG})")
    parser.add_argument("--report", type=Path, default=DEFAULT_ALERT_REPORT,
                        help="JSONL alert-history file")
    parser.add_argument("--year", type=int, default=datetime.now().year,
                        help="Year for Linux SSH syslog records")
    parser.add_argument("--interval", type=float, default=0.5,
                        help="Poll interval in seconds (default: 0.5)")
    parser.add_argument("--from-start", action="store_true",
                        help="Process preexisting lines rather than only appended lines")
    parser.add_argument("--once", action="store_true",
                        help="Process available lines once and exit (use with --from-start)")
    parser.add_argument("--beep", action="store_true",
                        help="Play an audible notification for each new alert")
    parser.add_argument("--webhook", action="store_true",
                        help="Send alerts to SECURITY_LOG_WEBHOOK_URL (opt in)")
    parser.add_argument("--webhook-format", choices=["discord", "slack"],
                        default="discord", help="Webhook payload format")

    # Match the configurable detection settings in analyzer.py and dashboard.py.
    parser.add_argument("--threshold", type=int, default=5)
    parser.add_argument("--window", type=int, default=5)
    parser.add_argument("--spray-users", type=int, default=5)
    parser.add_argument("--spray-window", type=int, default=10)
    parser.add_argument("--success-failures", type=int, default=3)
    parser.add_argument("--success-window", type=int, default=10)
    args = parser.parse_args()

    if args.interval <= 0:
        parser.error("--interval must be greater than 0")
    if any(v < 1 for v in (
        args.threshold, args.window, args.spray_users, args.spray_window,
        args.success_failures, args.success_window,
    )):
        parser.error("Detection thresholds and windows must be positive")

    webhook_url = None
    if args.webhook:
        webhook_url = os.getenv("SECURITY_LOG_WEBHOOK_URL")
        if not webhook_url or not webhook_url.startswith("https://"):
            parser.error(
                "--webhook requires SECURITY_LOG_WEBHOOK_URL set to an HTTPS URL"
            )

    # Previously saved alerts prevent duplicate notifications on replay.
    previous = read_alert_history(args.report, limit=100_000)
    seen = {alert_key(alert) for alert in previous}
    detector = LiveThreatMonitor(
        year=args.year,
        brute_threshold=args.threshold,
        brute_window=args.window,
        spray_users=args.spray_users,
        spray_window=args.spray_window,
        success_failures=args.success_failures,
        success_window=args.success_window,
        seen_alerts=seen,
    )
    follower = FileFollower(args.log, from_start=args.from_start)

    print(f"Watching: {args.log.resolve()}")
    print("Mode: from beginning" if args.from_start else "Mode: new lines only")
    print(f"Alerts saved to: {args.report.resolve()}")
    if not args.once:
        print("Press Ctrl+C to stop. Use a second terminal to append demo events.")

    try:
        while True:
            try:
                new_lines = follower.read_new_lines()
            except (OSError, ValueError) as error:
                print(f"Unable to read log file: {error}")
                if args.once:
                    break
                time.sleep(args.interval)
                continue

            for line in new_lines:
                for alert in detector.process_line(line):
                    notify_alert(
                        alert,
                        report_path=args.report,
                        beep=args.beep,
                        webhook_url=webhook_url,
                        webhook_format=args.webhook_format,
                    )

            if args.once:
                break
            time.sleep(args.interval)
    except KeyboardInterrupt:
        print("\nMonitoring stopped.")
    finally:
        print(
            f"Processed: {detector.valid_records} valid events; "
            f"{detector.invalid_records} invalid lines; "
            f"{detector.out_of_order_records} out-of-order events skipped."
        )


if __name__ == "__main__":
    main()
