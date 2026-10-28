"""Analyze activity and detect suspicious authentication patterns."""

from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime, timedelta

from .models import LogEvent
from .parser import TIMESTAMP_FORMAT


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


def detect_threats(
    events: list[LogEvent],
    brute_threshold: int = 5,
    brute_window: int = 5,
    spray_users: int = 5,
    spray_window: int = 10,
    success_failures: int = 3,
    success_window: int = 10,
) -> list[dict[str, str | int]]:
    """Detect brute force, password spraying, and success after failures.

    All rules group by source IP. Time windows are inclusive; events are
    sorted first so unsorted log files work. Alerts are deduplicated per
    IP/rule/window episode, except a new success can trigger a new alert.
    """
    settings = [brute_threshold, brute_window, spray_users,
                spray_window, success_failures, success_window]
    if any(value < 1 for value in settings):
        raise ValueError("Detection thresholds and windows must be positive")

    grouped: dict[str, list[LogEvent]] = defaultdict(list)
    for event in events:
        grouped[event.ip].append(event)

    alerts: list[dict[str, str | int]] = []

    def add_alert(ip: str, rule: str, severity: str, when: datetime,
                  count: int, detail: str) -> None:
        alerts.append({
            "timestamp": when.strftime(TIMESTAMP_FORMAT),
            "ip_address": ip,
            "rule": rule,
            "severity": severity,
            "count": count,
            "details": detail,
        })

    for ip, ip_events in grouped.items():
        ip_events.sort(key=lambda e: e.timestamp)
        failed: list[LogEvent] = []
        brute_active = False
        spray_active = False
        for event in ip_events:
            if event.status == "failed":
                failed.append(event)

                brute_start = event.timestamp - timedelta(minutes=brute_window)
                recent_brute = [e for e in failed if e.timestamp >= brute_start]
                if len(recent_brute) >= brute_threshold:
                    if not brute_active:
                        add_alert(ip, "brute_force", "HIGH", event.timestamp,
                                  len(recent_brute),
                                  f"{len(recent_brute)} failed logins in {brute_window} minutes")
                    brute_active = True
                else:
                    brute_active = False

                spray_start = event.timestamp - timedelta(minutes=spray_window)
                recent_spray = [e for e in failed if e.timestamp >= spray_start]
                users = {e.username for e in recent_spray}
                if len(users) >= spray_users:
                    if not spray_active:
                        add_alert(ip, "password_spraying", "HIGH", event.timestamp,
                                  len(users),
                                  f"Failures against {len(users)} usernames in {spray_window} minutes")
                    spray_active = True
                else:
                    spray_active = False
            else:
                start = event.timestamp - timedelta(minutes=success_window)
                prior = [e for e in failed if e.timestamp >= start]
                if len(prior) >= success_failures:
                    add_alert(ip, "success_after_failures", "CRITICAL",
                              event.timestamp, len(prior),
                              f"Successful login for {event.username} after "
                              f"{len(prior)} failures from this IP in {success_window} minutes")

    return sorted(alerts, key=lambda a: (a["timestamp"], a["ip_address"], a["rule"]))
