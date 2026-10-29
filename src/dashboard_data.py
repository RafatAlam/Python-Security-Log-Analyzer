"""Data preparation helpers for the interactive dashboard (no Streamlit dependency)."""

from __future__ import annotations

from datetime import datetime
from typing import Iterable

import pandas as pd

from .models import LogEvent
from .parser import parse_log_line
from .detector import analyze_events, detect_threats

EVENT_COLUMNS = ["timestamp", "ip_address", "username", "status"]
ALERT_COLUMNS = ["timestamp", "ip_address", "rule", "severity", "count", "details"]
SUMMARY_COLUMNS = [
    "ip_address", "successful_logins", "failed_logins",
    "max_failures_in_window", "window_end", "alert",
]


def load_log_text(text: str, year: int) -> tuple[list[LogEvent], int]:
    """Parse log text in memory, without writing uploaded records to disk."""
    events: list[LogEvent] = []
    invalid_count = 0
    for line in text.splitlines():
        if not line.strip():
            continue
        parsed = parse_log_line(line, year=year)
        if parsed is None:
            invalid_count += 1
        else:
            events.append(parsed)
    return events, invalid_count


def events_frame(events: Iterable[LogEvent]) -> pd.DataFrame:
    """Create a consistently shaped DataFrame even for an empty log."""
    rows = [
        {"timestamp": e.timestamp, "ip_address": e.ip,
         "username": e.username, "status": e.status}
        for e in events
    ]
    df = pd.DataFrame(rows, columns=EVENT_COLUMNS)
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    return df.sort_values("timestamp").reset_index(drop=True)


def alerts_frame(alerts: list[dict]) -> pd.DataFrame:
    df = pd.DataFrame(alerts, columns=ALERT_COLUMNS)
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    return df.sort_values("timestamp", ascending=False).reset_index(drop=True)


def summary_frame(events: list[LogEvent], threshold: int, window: int) -> pd.DataFrame:
    """Use the Phase 2 analysis function for a per-IP activity table."""
    analysis = analyze_events(events, threshold, window)
    summary = []
    for ip in sorted({event.ip for event in events}):
        detected = analysis["alerts"].get(ip, {})
        summary.append({
            "ip_address": ip,
            "successful_logins": sum(e.ip == ip and e.status == "success" for e in events),
            "failed_logins": analysis["failed_by_ip"].get(ip, 0),
            "max_failures_in_window": detected.get("max_failures_in_window", 0),
            "window_end": detected.get("window_end", ""),
            "alert": "SUSPICIOUS" if ip in analysis["alerts"] else "none",
        })
    return pd.DataFrame(summary, columns=SUMMARY_COLUMNS)


def timeline_frame(events: pd.DataFrame, frequency: str = "15min") -> pd.DataFrame:
    """Count successful and failed logins by time interval."""
    if frequency not in {"5min", "15min", "h", "D"}:
        raise ValueError("Unsupported time grouping")
    if events.empty:
        return pd.DataFrame(columns=["timestamp", "success", "failed"])
    timeline = (
        events.groupby([pd.Grouper(key="timestamp", freq=frequency), "status"])
        .size()
        .unstack(fill_value=0)
        .reindex(columns=["success", "failed"], fill_value=0)
        .reset_index()
    )
    return timeline


def filter_by_dates(df: pd.DataFrame, start, end) -> pd.DataFrame:
    """Keep rows on inclusive calendar dates, without losing any time-of-day."""
    if df.empty:
        return df.copy()
    mask = df["timestamp"].dt.date.between(start, end)
    return df.loc[mask].copy()


def severity_counts(alerts: pd.DataFrame) -> dict[str, int]:
    return {
        "CRITICAL": int((alerts["severity"] == "CRITICAL").sum()),
        "HIGH": int((alerts["severity"] == "HIGH").sum()),
    }
