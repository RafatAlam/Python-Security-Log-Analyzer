"""Tests for Phase 4 incremental monitoring, alerts, and persistence."""

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from src.monitor_engine import (
    FileFollower, LiveThreatMonitor, alert_key,
    append_alert_history, notify_alert, read_alert_history, send_webhook,
)


# --------------------------------------------------
# HELPER: GENERATE SYNTHETIC CUSTOM LOG ENTRIES
# --------------------------------------------------

def event(ip, user="root", status="failed", second=0):
    return (
        f"2026-11-03 09:00:{second:02d} "
        f"username={user} ip={ip} status={status}"
    )


class FileFollowerTests(unittest.TestCase):
    def test_reads_only_new_lines_by_default(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "auth.log"
            path.write_text("old\n", encoding="utf-8")
            follower = FileFollower(path)
            self.assertEqual(follower.read_new_lines(), [])
            with path.open("a", encoding="utf-8") as handle:
                handle.write("new\n")
            self.assertEqual(follower.read_new_lines(), ["new"])
            self.assertEqual(follower.read_new_lines(), [])

    def test_from_start_reads_existing_lines(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "auth.log"
            path.write_text("first\nsecond\n", encoding="utf-8")
            self.assertEqual(FileFollower(path, from_start=True).read_new_lines(),
                             ["first", "second"])

    def test_handles_partial_writes(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "auth.log"
            path.write_bytes(b"")
            follower = FileFollower(path)
            with path.open("ab") as handle:
                handle.write(b"incomplete")
            self.assertEqual(follower.read_new_lines(), [])
            with path.open("ab") as handle:
                handle.write(b" line\r\nnext\n")
            self.assertEqual(follower.read_new_lines(), ["incomplete line", "next"])

    def test_truncation_resets_offset(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "auth.log"
            path.write_text("x" * 80 + "\n", encoding="utf-8")
            follower = FileFollower(path, from_start=True)
            self.assertEqual(len(follower.read_new_lines()), 1)
            path.write_text("replaced\n", encoding="utf-8")
            self.assertEqual(follower.read_new_lines(), ["replaced"])

    def test_waits_for_missing_file(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "new.log"
            follower = FileFollower(path)
            self.assertEqual(follower.read_new_lines(), [])
            path.write_text("appeared\n", encoding="utf-8")
            self.assertEqual(follower.read_new_lines(), ["appeared"])


class LiveMonitorTests(unittest.TestCase):
    def test_brute_force_generates_one_alert(self):
        detector = LiveThreatMonitor(year=2026)
        alerts = []
        for i in range(7):
            alerts.extend(detector.process_line(event("203.0.113.10", second=i)))
        self.assertEqual([a["rule"] for a in alerts], ["brute_force"])
        self.assertEqual(detector.valid_records, 7)

    def test_password_spraying_detected(self):
        detector = LiveThreatMonitor(year=2026)
        alerts = []
        for i, user in enumerate(["alice", "bob", "charlie", "diana", "eric"]):
            alerts.extend(detector.process_line(event("198.51.100.20", user, second=i)))
        rules = {a["rule"] for a in alerts}
        self.assertIn("password_spraying", rules)
        self.assertIn("brute_force", rules)

    def test_success_after_failures(self):
        detector = LiveThreatMonitor(year=2026)
        for i in range(3):
            self.assertEqual(detector.process_line(event("192.0.2.30", second=i)), [])
        alerts = detector.process_line(event("192.0.2.30", status="success", second=3))
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["rule"], "success_after_failures")
        self.assertEqual(alerts[0]["severity"], "CRITICAL")

    def test_invalid_and_out_of_order_records(self):
        detector = LiveThreatMonitor(year=2026)
        self.assertEqual(detector.process_line("invalid log entry"), [])
        self.assertEqual(detector.invalid_records, 1)
        detector.process_line(event("192.0.2.4", second=20))
        self.assertEqual(detector.process_line(event("192.0.2.4", second=1)), [])
        self.assertEqual(detector.out_of_order_records, 1)

    def test_different_ips_do_not_merge(self):
        detector = LiveThreatMonitor(year=2026)
        alerts = []
        for i in range(5):
            alerts.extend(detector.process_line(event(f"192.0.2.{i+1}", second=i)))
        self.assertEqual(alerts, [])

    def test_seen_alerts_not_emitted_again_after_restart(self):
        first = LiveThreatMonitor(year=2026)
        previously_sent = []
        for i in range(5):
            previously_sent.extend(first.process_line(event("192.0.2.10", second=i)))
        seen = {alert_key(a) for a in previously_sent}
        second = LiveThreatMonitor(year=2026, seen_alerts=seen)
        again = []
        for i in range(5):
            again.extend(second.process_line(event("192.0.2.10", second=i)))
        self.assertEqual(again, [])

    def test_rollover_to_new_burst(self):
        detector = LiveThreatMonitor(year=2026, brute_threshold=3, brute_window=1)
        lines = [
            "2026-11-03 09:00:00 username=root ip=203.0.113.1 status=failed",
            "2026-11-03 09:00:10 username=root ip=203.0.113.1 status=failed",
            "2026-11-03 09:00:20 username=root ip=203.0.113.1 status=failed",
            "2026-11-03 09:02:00 username=root ip=203.0.113.1 status=failed",
            "2026-11-03 09:02:10 username=root ip=203.0.113.1 status=failed",
            "2026-11-03 09:02:20 username=root ip=203.0.113.1 status=failed",
        ]
        alerts = []
        for line in lines:
            alerts.extend(detector.process_line(line))
        self.assertEqual(sum(a["rule"] == "brute_force" for a in alerts), 2)

    def test_invalid_config(self):
        with self.assertRaises(ValueError):
            LiveThreatMonitor(year=2026, spray_users=0)


class AlertHistoryTests(unittest.TestCase):
    def setUp(self):
        self.sample_alert = {
            "timestamp": "2026-11-03 09:00:04",
            "ip_address": "192.0.2.10", "rule": "brute_force",
            "severity": "HIGH", "count": 5, "details": "5 failed logins",
        }

    def test_persist_and_read_history(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "reports" / "alerts.jsonl"
            append_alert_history(path, self.sample_alert)
            alerts = read_alert_history(path)
            self.assertEqual(len(alerts), 1)
            self.assertEqual(alerts[0]["rule"], "brute_force")
            self.assertIn("observed_at_utc", alerts[0])

    def test_missing_history_returns_empty(self):
        self.assertEqual(read_alert_history(Path("/unlikely-path/nope/file.jsonl")), [])

    def test_ignores_malformed_history(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "alerts.jsonl"
            path.write_text('broken\n{"foo": 1}\n' +
                            json.dumps(self.sample_alert) + "\n", encoding="utf-8")
            self.assertEqual(len(read_alert_history(path)), 1)

    def test_notifier_persists_even_if_webhook_fails(self):
        with tempfile.TemporaryDirectory() as temp, patch(
            "src.monitor_engine.send_webhook", side_effect=OSError("network issue")
        ):
            path = Path(temp) / "alerts.jsonl"
            with patch("builtins.print"):
                notify_alert(self.sample_alert, report_path=path,
                             webhook_url="https://example.invalid/receiver")
            self.assertEqual(len(read_alert_history(path)), 1)

    @patch("src.monitor_engine.urllib.request.urlopen")
    def test_discord_webhook_payload(self, mocked_urlopen):
        send_webhook(self.sample_alert, "https://example.invalid/hook", "discord")
        request = mocked_urlopen.call_args.args[0]
        body = json.loads(request.data.decode("utf-8"))
        self.assertIn("content", body)
        self.assertIn("192.0.2.10", body["content"])


if __name__ == "__main__":
    unittest.main()
