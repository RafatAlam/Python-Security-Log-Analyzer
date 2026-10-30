"""Unit tests for Phase 3 data preparation (no Streamlit server required)."""

import unittest
from datetime import date, datetime
from pathlib import Path

from src.dashboard_data import (
    alerts_frame, events_frame, filter_by_dates, load_log_text,
    severity_counts, summary_frame, timeline_frame,
)
from src.detector import detect_threats
from src.models import LogEvent


class DashboardDataTests(unittest.TestCase):
    def setUp(self):
        self.events = [
            LogEvent(datetime(2026, 1, 15, 9, 0), "root", "192.0.2.10", "failed"),
            LogEvent(datetime(2026, 1, 15, 9, 2), "root", "192.0.2.10", "failed"),
            LogEvent(datetime(2026, 1, 15, 9, 3), "root", "192.0.2.10", "success"),
            LogEvent(datetime(2026, 1, 16, 11, 0), "sam", "198.51.100.5", "success"),
        ]

    def test_load_text_with_malformed_line(self):
        records = (
            "2026-01-15 09:14:03 username=alex ip=192.0.2.10 status=failed\n"
            "invalid text\n"
        )
        events, invalid = load_log_text(records, 2026)
        self.assertEqual(len(events), 1)
        self.assertEqual(invalid, 1)

    def test_parse_ssh_year(self):
        text = "Jan 15 09:14:03 host sshd[123]: Failed password for root from 192.0.2.10 port 123 ssh2"
        events, invalid = load_log_text(text, 2024)
        self.assertEqual(invalid, 0)
        self.assertEqual(events[0].timestamp.year, 2024)

    def test_events_frame_is_sorted(self):
        frame = events_frame(list(reversed(self.events)))
        self.assertEqual(frame.iloc[0]["status"], "failed")
        self.assertEqual(frame.iloc[-1]["username"], "sam")

    def test_empty_frames_keep_columns(self):
        events = events_frame([])
        alerts = alerts_frame([])
        self.assertEqual(len(events), 0)
        self.assertEqual(len(alerts), 0)
        self.assertIn("timestamp", events.columns)
        self.assertIn("severity", alerts.columns)

    def test_date_filter_includes_whole_day(self):
        frame = events_frame(self.events)
        filtered = filter_by_dates(frame, date(2026, 1, 15), date(2026, 1, 15))
        self.assertEqual(len(filtered), 3)

    def test_timeline_groups_counts(self):
        timeline = timeline_frame(events_frame(self.events), "5min")
        self.assertEqual(int(timeline.iloc[0]["failed"]), 2)
        self.assertEqual(int(timeline.iloc[0]["success"]), 1)

    def test_invalid_frequency(self):
        with self.assertRaises(ValueError):
            timeline_frame(events_frame(self.events), "not-a-frequency")

    def test_summary_report(self):
        summary = summary_frame(self.events, threshold=2, window=5)
        row = summary.loc[summary["ip_address"] == "192.0.2.10"].iloc[0]
        self.assertEqual(row["failed_logins"], 2)
        self.assertEqual(row["alert"], "SUSPICIOUS")

    def test_alert_severity_counts(self):
        alerts = alerts_frame([
            {"timestamp": "2026-01-15 09:02:00", "ip_address": "192.0.2.10",
             "rule": "brute_force", "severity": "HIGH", "count": 2, "details": "demo"},
        ])
        self.assertEqual(severity_counts(alerts), {"CRITICAL": 0, "HIGH": 1})

    def test_synthetic_dashboard_demo_generates_all_three_rules(self):
        sample = Path(__file__).resolve().parents[1] / "logs" / "dashboard_demo.log"
        events, invalid = load_log_text(sample.read_text(encoding="utf-8"), 2026)
        self.assertEqual(invalid, 0)
        self.assertGreater(len(events), 200)
        rules = {alert["rule"] for alert in detect_threats(events)}
        self.assertEqual(rules, {
            "brute_force", "password_spraying", "success_after_failures",
        })


if __name__ == "__main__":
    unittest.main()
