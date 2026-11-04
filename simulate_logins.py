#!/usr/bin/env python3
"""Append synthetic login events for testing the Phase 4 live monitor.

Run in a separate VS Code terminal while `run_monitor.py` is watching the file:
    python simulate_logins.py
"""

from __future__ import annotations

import argparse
import time
from datetime import datetime
from pathlib import Path


# --------------------------------------------------
# SYNTHETIC ACTIVITY (DOCUMENTATION-ONLY IP ADDRESSES)
# --------------------------------------------------

DEMO_EVENTS = [
    ("alex", "192.0.2.50", "success"),
    ("sam", "192.0.2.51", "success"),
    *(("root", "203.0.113.10", "failed") for _ in range(5)),
    *((user, "198.51.100.20", "failed")
      for user in ["alice", "bob", "charlie", "diana", "eric"]),
    *(("alex", "192.0.2.30", "failed") for _ in range(3)),
    ("alex", "192.0.2.30", "success"),
    ("sam", "192.0.2.51", "failed"),
    ("sam", "192.0.2.51", "success"),
]


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Append synthetic authentication events at a chosen pace."
    )
    parser.add_argument("--log", type=Path, default=Path("logs/live_demo.log"))
    parser.add_argument("--delay", type=float, default=0.5,
                        help="Seconds to pause between lines (default: 0.5)")
    args = parser.parse_args()
    if args.delay < 0:
        parser.error("--delay must be nonnegative")

    args.log.parent.mkdir(parents=True, exist_ok=True)
    print(f"Appending {len(DEMO_EVENTS)} synthetic entries to {args.log}")
    with args.log.open("a", encoding="utf-8") as handle:
        for username, ip, status in DEMO_EVENTS:
            # Real current timestamps show data arriving in real time.
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            handle.write(
                f"{timestamp} username={username} ip={ip} status={status}\n"
            )
            handle.flush()
            print(f"{timestamp}  {ip:<16} {username:<9} {status}", flush=True)
            time.sleep(args.delay)
    print("Demo finished. Review reports/live_alerts.jsonl or the dashboard.")


if __name__ == "__main__":
    main()
