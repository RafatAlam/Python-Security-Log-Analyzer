import tempfile
import unittest
from pathlib import Path

from src.parser import load_events, parse_log_line


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


class SSHParsingTests(unittest.TestCase):
    def test_failed_invalid_user(self):
        line = "Jan 15 09:14:03 server sshd[1234]: Failed password for invalid user admin from 203.0.113.25 port 55234 ssh2"
        event = parse_log_line(line, year=2026)
        self.assertEqual((event.username, event.ip, event.status), ("admin", "203.0.113.25", "failed"))
        self.assertEqual(event.timestamp.year, 2026)

    def test_successful_publickey(self):
        line = "Jan 15 09:18:20 server sshd[1240]: Accepted publickey for sam from 198.51.100.7 port 55240 ssh2"
        self.assertEqual(parse_log_line(line, year=2026).status, "success")

    def test_malformed_ssh_record(self):
        self.assertIsNone(parse_log_line("Jan 15 server sshd: nonsense", year=2026))

    def test_invalid_ip(self):
        line = "Jan 15 09:14:03 server sshd[1234]: Failed password for root from not-an-ip port 55234 ssh2"
        self.assertIsNone(parse_log_line(line, year=2026))
