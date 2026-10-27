import tempfile
import unittest
from datetime import datetime
from pathlib import Path

from analyzer import (
    LogEvent,
    analyze_events,
    find_suspicious_ips,
    load_events,
    parse_log_line,
    write_csv_report,
)


class ParseLogLineTests(unittest.TestCase):
    def test_parses_valid_failed_event(self):
        event = parse_log_line(
            "2026-01-15 09:14:03 username=alex "
            "ip=192.0.2.10 status=failed"
        )
        self.assertIsNotNone(event)
        self.assertEqual(event.username, "alex")
        self.assertEqual(event.ip, "192.0.2.10")
        self.assertEqual(event.status, "failed")

    def test_rejects_malformed_line(self):
        self.assertIsNone(parse_log_line("this is not a valid log entry"))

    def test_rejects_invalid_timestamp(self):
        self.assertIsNone(
            parse_log_line(
                "2026-99-99 09:14:03 username=alex "
                "ip=192.0.2.10 status=failed"
            )
        )


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


class LoadEventsTests(unittest.TestCase):
    def test_loads_valid_and_counts_invalid_lines(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "auth.log"
            path.write_text(
                "2026-01-15 09:14:03 username=alex "
                "ip=192.0.2.10 status=failed\n"
                "bad line\n",
                encoding="utf-8",
            )
            events, invalid_count = load_events(path)
            self.assertEqual(len(events), 1)
            self.assertEqual(invalid_count, 1)


if __name__ == "__main__":
    unittest.main()
