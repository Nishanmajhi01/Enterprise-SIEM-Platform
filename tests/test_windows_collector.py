"""Offline parser checks. Run: python3 -m unittest discover -s tests -p 'test_windows_collector.py'"""
import importlib.util
import pathlib
import unittest

FILE = pathlib.Path(__file__).resolve().parents[1] / "agents" / "windows-collector.py"
spec = importlib.util.spec_from_file_location("windows_collector", FILE)
collector = importlib.util.module_from_spec(spec)
spec.loader.exec_module(collector)


class WindowsCollectorTests(unittest.TestCase):
    def sample(self, source="192.168.1.30"):
        return (
            "2026-09-17T19:44:23+00:00 windows11Target "
            "Microsoft-Windows-Security-Auditing[888]: An account failed to log on. "
            "Subject: #011Account Name:#011#011WINDOWS11TARGET$ "
            "Account For Which Logon Failed: #011Security ID:#011#011S-1-0-0 "
            "#011Account Name:#011#011victim #011Account Domain:#011#011WINDOWS11TARGET "
            "Failure Information: #011Failure Reason:#011#011Unknown user name or bad password. "
            "Network Information: #011Source Network Address:#011#011" + source
        )

    def test_remote_source_and_target_username(self):
        event = collector.parse_event(self.sample())
        self.assertEqual(event["eventType"], "WINDOWS_SECURITY_4625")
        self.assertEqual(event["sourceIP"], "192.168.1.30")
        self.assertEqual(event["username"], "victim")

    def test_missing_remote_source(self):
        event = collector.parse_event(self.sample("-"))
        self.assertEqual(event["sourceIP"], "UNKNOWN")
        self.assertFalse(event["raw"]["sourceIPKnown"])

    def test_unrelated_audit_message_is_ignored(self):
        self.assertIsNone(collector.parse_event(self.sample().replace(
            "An account failed to log on.", "Auditing settings on object were changed."
        )))


if __name__ == "__main__":
    unittest.main()
