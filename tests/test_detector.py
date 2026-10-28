import tempfile
import unittest
from datetime import datetime, timedelta
from pathlib import Path

from src.models import LogEvent
from src.detector import analyze_events, find_suspicious_ips, detect_threats
from src.reporter import write_csv_report


class AnalyzerTests(unittest.TestCase):
    def setUp(self):
        self.events = [
            LogEvent(datetime(2026, 1, 15, 9, 0, 0), "alex", "192.0.2.10", "failed"),
            LogEvent(datetime(2026, 1, 15, 9, 1, 0), "alex", "192.0.2.10", "failed"),
            LogEvent(datetime(2026, 1, 15, 9, 2, 0), "alex", "192.0.2.10", "failed"),
            LogEvent(datetime(2026, 1, 15, 9, 3, 0), "alex", "192.0.2.10", "success"),
            LogEvent(datetime(2026, 1, 15, 9, 0, 0), "sam", "198.51.100.7", "success"),
        ]

    def test_detects_threshold_within_window(self):
        alerts = find_suspicious_ips(self.events, threshold=3, window_minutes=5)
        self.assertIn("192.0.2.10", alerts)
        self.assertEqual(alerts["192.0.2.10"]["max_failures_in_window"], 3)

    def test_does_not_alert_below_threshold(self):
        alerts = find_suspicious_ips(self.events, threshold=4, window_minutes=5)
        self.assertNotIn("192.0.2.10", alerts)

    def test_counts_login_results(self):
        result = analyze_events(self.events, threshold=3, window_minutes=5)
        self.assertEqual(result["total_events"], 5)
        self.assertEqual(result["successful_logins"], 2)
        self.assertEqual(result["failed_logins"], 3)

    def test_rejects_invalid_threshold(self):
        with self.assertRaises(ValueError):
            find_suspicious_ips(self.events, threshold=0)

    def test_writes_csv_report(self):
        result = analyze_events(self.events, threshold=3, window_minutes=5)
        with tempfile.TemporaryDirectory() as temp_dir:
            report = Path(temp_dir) / "reports" / "report.csv"
            write_csv_report(report, self.events, result)
            content = report.read_text(encoding="utf-8")
            self.assertIn("ip_address", content)
            self.assertIn("SUSPICIOUS", content)
            self.assertIn("192.0.2.10", content)


def ev(minute, ip, user, status):
    return LogEvent(datetime(2026, 1, 15, 9, 0) + timedelta(minutes=minute),
                    user, ip, status)

class Phase2DetectionTests(unittest.TestCase):
    def test_brute_force(self):
        events = [ev(i, "192.0.2.1", "root", "failed") for i in range(5)]
        alerts = detect_threats(events)
        self.assertEqual([a["rule"] for a in alerts], ["brute_force"])

    def test_password_spraying(self):
        events = [ev(i, "192.0.2.2", f"user{i}", "failed") for i in range(5)]
        alerts = detect_threats(events)
        self.assertIn("password_spraying", [a["rule"] for a in alerts])

    def test_success_after_failures(self):
        events = [ev(i, "192.0.2.3", "alex", "failed") for i in range(3)]
        events.append(ev(3, "192.0.2.3", "alex", "success"))
        alerts = detect_threats(events)
        self.assertEqual([a["rule"] for a in alerts], ["success_after_failures"])
        self.assertEqual(alerts[0]["severity"], "CRITICAL")

    def test_no_alert_outside_window(self):
        events = [ev(i * 10, "192.0.2.4", "root", "failed") for i in range(5)]
        self.assertEqual(detect_threats(events), [])

    def test_no_cross_ip_merging(self):
        events = [ev(0, f"192.0.2.{i}", "root", "failed") for i in range(1, 8)]
        self.assertEqual(detect_threats(events), [])

    def test_unsorted_events(self):
        events = [ev(i, "192.0.2.5", "root", "failed") for i in reversed(range(5))]
        self.assertIn("brute_force", [a["rule"] for a in detect_threats(events)])

    def test_no_repeat_alert_in_same_burst(self):
        events = [ev(i, "192.0.2.6", "root", "failed") for i in range(7)]
        alerts = [a for a in detect_threats(events) if a["rule"] == "brute_force"]
        self.assertEqual(len(alerts), 1)

    def test_invalid_config(self):
        with self.assertRaises(ValueError):
            detect_threats([], spray_users=0)
