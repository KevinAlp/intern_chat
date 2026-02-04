from __future__ import annotations

import unittest

from src.messaging.protocol import parse_command


class ProtocolParsingTests(unittest.TestCase):
    def test_parse_msg_keeps_payload(self) -> None:
        command = parse_command("MSG bob hello world\n")
        self.assertEqual(command.name, "MSG")
        self.assertEqual(command.args, ("bob", "hello world"))

    def test_parse_history_with_limit(self) -> None:
        command = parse_command("HISTORY bob 50\n")
        self.assertEqual(command.name, "HISTORY")
        self.assertEqual(command.args, ("bob", "50"))

    def test_parse_auth(self) -> None:
        command = parse_command("AUTH alice supersecret\n")
        self.assertEqual(command.name, "AUTH")
        self.assertEqual(command.args, ("alice", "supersecret"))

    def test_reject_invalid_read(self) -> None:
        with self.assertRaises(ValueError):
            parse_command("READ nope\n")

    def test_reject_unknown(self) -> None:
        with self.assertRaises(ValueError):
            parse_command("BOGUS\n")


if __name__ == "__main__":
    unittest.main()
