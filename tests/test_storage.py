from __future__ import annotations

import tempfile
import unittest

from src.messaging.storage import Storage


class StorageTests(unittest.TestCase):
    def test_auth_register_then_authenticate(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db_path = f"{tmp}/chat.db"
            storage = Storage(db_path)
            self.assertEqual(storage.authenticate_or_register("alice", "password123"), "registered")
            self.assertEqual(
                storage.authenticate_or_register("alice", "password123"), "authenticated"
            )
            self.assertEqual(storage.authenticate_or_register("alice", "wrongpass"), "invalid")
            storage.close()

    def test_pending_and_history(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db_path = f"{tmp}/chat.db"
            storage = Storage(db_path)
            storage.authenticate_or_register("alice", "password123")
            storage.authenticate_or_register("bob", "password123")

            msg1 = storage.store_message("alice", "bob", "hello")
            msg2 = storage.store_message("bob", "alice", "hi")
            pending_bob = storage.pending_messages_for("bob")
            self.assertEqual([item.message_id for item in pending_bob], [msg1])

            storage.mark_delivered(msg1)
            pending_bob_after = storage.pending_messages_for("bob")
            self.assertEqual(len(pending_bob_after), 0)

            history = storage.conversation_history("alice", "bob", 20)
            self.assertEqual([item.message_id for item in history], [msg1, msg2])
            storage.close()

    def test_blocking(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db_path = f"{tmp}/chat.db"
            storage = Storage(db_path)
            storage.authenticate_or_register("alice", "password123")
            storage.authenticate_or_register("bob", "password123")

            self.assertFalse(storage.is_blocked("bob", "alice"))
            storage.block_user("bob", "alice")
            self.assertTrue(storage.is_blocked("bob", "alice"))
            storage.unblock_user("bob", "alice")
            self.assertFalse(storage.is_blocked("bob", "alice"))
            storage.close()


if __name__ == "__main__":
    unittest.main()
