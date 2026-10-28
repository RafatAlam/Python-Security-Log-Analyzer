"""Parse synthetic records and common Linux OpenSSH authentication logs."""

from __future__ import annotations

import ipaddress
import re
from datetime import datetime
from pathlib import Path

from .models import LogEvent


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


# Common syslog-style OpenSSH messages. The year is not included in these logs.
SSH_PATTERN = re.compile(
    r"^(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+"
    r"(?P<clock>\d{2}:\d{2}:\d{2})\s+\S+\s+"
    r"sshd\[\d+\]:\s+"
    r"(?P<result>Failed|Accepted)\s+\S+\s+for\s+"
    r"(?P<invalid>invalid user\s+)?(?P<username>\S+)\s+"
    r"from\s+(?P<ip>\S+)\s+port\s+\d+(?:\s+.*)?$"
)


def parse_log_line(line: str, year: int | None = None) -> LogEvent | None:
    """Parse a custom record or common Linux OpenSSH login event.

    Syslog SSH timestamps omit the year, so pass the year explicitly when
    analyzing archived logs. The default is the current local year.
    """
    line = line.strip()
    match = LOG_PATTERN.fullmatch(line)
    if match:
        try:
            timestamp = datetime.strptime(match.group("timestamp"), TIMESTAMP_FORMAT)
            ipaddress.ip_address(match.group("ip"))
        except ValueError:
            return None
        return LogEvent(timestamp, match.group("username"), match.group("ip"),
                        match.group("status").lower())

    match = SSH_PATTERN.fullmatch(line)
    if not match:
        return None
    if year is None:
        year = datetime.now().year
    try:
        timestamp = datetime.strptime(
            f"{year} {match.group('month')} {match.group('day')} {match.group('clock')}",
            "%Y %b %d %H:%M:%S",
        )
        ipaddress.ip_address(match.group("ip"))
    except ValueError:
        return None
    return LogEvent(timestamp, match.group("username"), match.group("ip"),
                    "failed" if match.group("result") == "Failed" else "success")


def load_events(log_path: Path, year: int | None = None) -> tuple[list[LogEvent], int]:
    """Load valid events and count malformed or unsupported lines."""
    events: list[LogEvent] = []
    invalid_count = 0

    with log_path.open("r", encoding="utf-8") as log_file:
        for line in log_file:
            if not line.strip():
                continue
            event = parse_log_line(line, year=year)
            if event is None:
                invalid_count += 1
            else:
                events.append(event)

    return events, invalid_count
