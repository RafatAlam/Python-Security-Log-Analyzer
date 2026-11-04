"""Phase 4: Incremental log following, live threat detection, and notifications.

This module has no Streamlit dependency. It reuses the Phase 2 parser and
threat-detection rules so CLI monitoring matches the existing analyzer.
"""

from __future__ import annotations

import json
import sys
import urllib.error
import urllib.request
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from .detector import detect_threats
from .models import LogEvent
from .parser import parse_log_line


# --------------------------------------------------
# INCREMENTAL FILE READING
# --------------------------------------------------

class FileFollower:
    """Return newly completed lines without rereading the entire file.

    Starts at the end by default so previously stored lines are not treated
    as fresh activity. Handles split writes, truncation, and file replacement.
    """

    def __init__(self, path: Path, from_start: bool = False) -> None:
        self.path = Path(path)
        self._offset = 0
        self._pending = b""
        self._identity: tuple[int, int] | None = None

        try:
            info = self.path.stat()
        except FileNotFoundError:
            return  # A new log file may appear after the monitor starts.

        self._identity = (info.st_dev, info.st_ino)
        if not from_start:
            self._offset = info.st_size

    def read_new_lines(self) -> list[str]:
        """Read complete lines appended since the previous poll."""
        try:
            info = self.path.stat()
        except FileNotFoundError:
            # After rotation, wait for the replacement to appear.
            self._identity = None
            self._offset = 0
            self._pending = b""
            return []

        identity = (info.st_dev, info.st_ino)
        if self._identity is None:
            self._identity = identity
        elif self._identity != identity or info.st_size < self._offset:
            # The file was replaced or truncated; treat new content as new.
            self._identity = identity
            self._offset = 0
            self._pending = b""

        with self.path.open("rb") as handle:
            handle.seek(self._offset)
            new_bytes = handle.read()
            self._offset = handle.tell()

        if not new_bytes:
            return []

        buffer = self._pending + new_bytes
        chunks = buffer.split(b"\n")
        self._pending = chunks.pop()

        if len(self._pending) > 256 * 1024:
            # A single absurdly long line should not grow memory without bound.
            self._pending = b""
            raise ValueError("An incomplete log line exceeded 256 KB")

        return [chunk.rstrip(b"\r").decode("utf-8", errors="replace")
                for chunk in chunks if chunk.strip()]


# --------------------------------------------------
# LIVE DETECTION ENGINE
# --------------------------------------------------

def alert_key(alert: dict[str, Any]) -> tuple[str, str, str]:
    """Identify an alert independently of description or observation time."""
    return (str(alert["ip_address"]), str(alert["rule"]),
            str(alert["timestamp"]))


class LiveThreatMonitor:
    """Evaluate arriving events with the existing Phase 2 detection rules.

    Maintains rolling event histories per IP. Input should arrive in event-time
    order for each IP; late/out-of-order events are skipped to avoid misleading
    time-window correlations. Repeated scans do not re-emit the same alert.
    """

    def __init__(
        self,
        *,
        year: int,
        brute_threshold: int = 5,
        brute_window: int = 5,
        spray_users: int = 5,
        spray_window: int = 10,
        success_failures: int = 3,
        success_window: int = 10,
        seen_alerts: set[tuple[str, str, str]] | None = None,
    ) -> None:
        params = (brute_threshold, brute_window, spray_users,
                  spray_window, success_failures, success_window)
        if any(value < 1 for value in params):
            raise ValueError("All detection thresholds and windows must be positive")

        self.year = year
        self.brute_threshold = brute_threshold
        self.brute_window = brute_window
        self.spray_users = spray_users
        self.spray_window = spray_window
        self.success_failures = success_failures
        self.success_window = success_window
        self._max_window = timedelta(minutes=max(brute_window, spray_window,
                                                 success_window))
        self._histories: dict[str, deque[LogEvent]] = defaultdict(deque)
        self._seen = set(seen_alerts or ())
        self.valid_records = 0
        self.invalid_records = 0
        self.out_of_order_records = 0

    def process_line(self, line: str) -> list[dict[str, Any]]:
        """Parse one new record and return only newly triggered alerts."""
        if not line.strip():
            return []

        event = parse_log_line(line, year=self.year)
        if event is None:
            self.invalid_records += 1
            return []

        events = self._histories[event.ip]
        if events and event.timestamp < events[-1].timestamp:
            self.out_of_order_records += 1
            return []

        self.valid_records += 1
        events.append(event)
        cutoff = event.timestamp - self._max_window
        while events and events[0].timestamp < cutoff:
            events.popleft()

        # Existing detector implements the same three Phase 2 rules.
        detections = detect_threats(
            list(events),
            brute_threshold=self.brute_threshold,
            brute_window=self.brute_window,
            spray_users=self.spray_users,
            spray_window=self.spray_window,
            success_failures=self.success_failures,
            success_window=self.success_window,
        )

        current_timestamp = event.timestamp.strftime("%Y-%m-%d %H:%M:%S")
        new_alerts: list[dict[str, Any]] = []
        for alert in detections:
            # Only emit detections that actually triggered at this new event.
            if alert["timestamp"] != current_timestamp:
                continue
            key = alert_key(alert)
            if key not in self._seen:
                self._seen.add(key)
                new_alerts.append(alert)

        return new_alerts


# --------------------------------------------------
# ALERT HISTORY: JSON LINES
# --------------------------------------------------

def read_alert_history(path: Path, limit: int = 500) -> list[dict[str, Any]]:
    """Read the latest saved alerts for the dashboard or restart deduplication.

    Ignores malformed or partial JSON lines (for example, during concurrent
    access while the monitor is writing an alert).
    """
    if limit < 1:
        raise ValueError("limit must be positive")
    result: deque[dict[str, Any]] = deque(maxlen=limit)
    try:
        with Path(path).open("r", encoding="utf-8") as handle:
            for line in handle:
                try:
                    record = json.loads(line)
                except (json.JSONDecodeError, UnicodeError):
                    continue
                if isinstance(record, dict) and all(
                    key in record for key in ("ip_address", "rule", "timestamp")
                ):
                    result.append(record)
    except FileNotFoundError:
        pass
    return list(result)


def append_alert_history(path: Path, alert: dict[str, Any]) -> dict[str, Any]:
    """Append one alert to the persistent JSONL audit trail."""
    record = {
        "observed_at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        **alert,
    }
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8", newline="\n") as handle:
        handle.write(json.dumps(record, ensure_ascii=True) + "\n")
    return record


# --------------------------------------------------
# NOTIFICATIONS
# --------------------------------------------------

def send_webhook(alert: dict[str, Any], url: str, format_name: str) -> None:
    """Send an optional Slack or Discord webhook (stdlib only).

    Explicit opt-in is required because an external webhook transmits alert
    metadata, which may be sensitive even without raw log lines.
    """
    message = (
        f"[{alert['severity']}] {alert['rule']} | {alert['ip_address']} | "
        f"{alert['timestamp']} | {alert['details']}"
    )
    if format_name == "discord":
        payload = {"content": message}
    elif format_name == "slack":
        payload = {"text": message}
    else:
        raise ValueError("Webhook format must be 'discord' or 'slack'")

    request = urllib.request.Request(
        url, data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"}, method="POST",
    )
    with urllib.request.urlopen(request, timeout=5) as response:
        response.read()


def notify_alert(
    alert: dict[str, Any],
    *,
    report_path: Path,
    beep: bool = False,
    webhook_url: str | None = None,
    webhook_format: str = "discord",
) -> dict[str, Any]:
    """Persist an alert first, then notify through configured channels."""
    record = append_alert_history(report_path, alert)
    print(
        f"[LIVE {alert['severity']}] {alert['rule']} | {alert['ip_address']} | "
        f"{alert['timestamp']} | {alert['details']}", flush=True,
    )

    if beep:
        if sys.platform == "win32":
            import winsound
            winsound.MessageBeep()
        else:
            print("\a", end="", flush=True)

    if webhook_url:
        try:
            send_webhook(alert, webhook_url, webhook_format)
        except (OSError, urllib.error.URLError, ValueError) as error:
            # Notification failure does not delete an alert saved locally.
            print(f"Webhook delivery failed: {type(error).__name__}",
                  file=sys.stderr, flush=True)
    return record
