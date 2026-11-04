"""Tests for the auto-refresh dashboard's underlying log snapshots."""

import tempfile
import unittest
from pathlib import Path

from src.dashboard_data import read_live_log, events_frame, summary_frame, timeline_frame
from src.detector import detect_threats


class LiveDashboardTests(unittest.TestCase):
    def test_missing_log_is_empty_not_an_error(self):
        with tempfile.TemporaryDirectory() as folder:
            events, invalid = read_live_log(Path(folder) / "missing.log", 2026)
            self.assertEqual((events, invalid), ([], 0))

    def test_snapshot_updates_after_file_append(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "live.log"
            with path.open("w", encoding="utf-8") as handle:
                handle.write("2026-11-03 09:00:00 username=alex ip=192.0.2.10 status=success\n")
            first, invalid = read_live_log(path, 2026)
            self.assertEqual((len(first), invalid), (1, 0))
            with path.open("a", encoding="utf-8") as handle:
                for i in range(5):
                    handle.write(
                        f"2026-11-03 09:0{i+1}:00 username=root "
                        "ip=203.0.113.10 status=failed\n"
                    )
            second, invalid = read_live_log(path, 2026)
            self.assertEqual((len(second), invalid), (6, 0))
            alerts = detect_threats(second)
            self.assertIn("brute_force", {a["rule"] for a in alerts})
            timeline = timeline_frame(events_frame(second), "h")
            self.assertEqual(int(timeline.iloc[0]["failed"]), 5)
            summary = summary_frame(second, threshold=5, window=5)
            detected = summary.loc[summary["ip_address"] == "203.0.113.10"].iloc[0]
            self.assertEqual(int(detected["failed_logins"]), 5)

    def test_incomplete_last_line_waits_for_newline(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "live.log"
            path.write_text(
                "2026-11-03 09:00:00 username=alex ip=192.0.2.10 status=success\n"
                "2026-11-03 09:01:00 username=root ip=203.0.113.10 status=fail",
                encoding="utf-8",
            )
            events, invalid = read_live_log(path, 2026)
            self.assertEqual((len(events), invalid), (1, 0))
            with path.open("a", encoding="utf-8") as handle:
                handle.write("ed\n")
            events, invalid = read_live_log(path, 2026)
            self.assertEqual((len(events), invalid), (2, 0))

    def test_truncation_reflects_new_contents(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "live.log"
            path.write_text(
                "2026-11-03 09:00:00 username=alex ip=192.0.2.10 status=success\n",
                encoding="utf-8",
            )
            self.assertEqual(len(read_live_log(path, 2026)[0]), 1)
            path.write_text("", encoding="utf-8")
            self.assertEqual(read_live_log(path, 2026), ([], 0))

    def test_size_limit_enforced(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "live.log"
            path.write_bytes(b"x" * 100)
            with self.assertRaises(ValueError):
                read_live_log(path, 2026, max_bytes=50)


if __name__ == "__main__":
    unittest.main()
