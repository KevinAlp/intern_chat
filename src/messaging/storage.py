from __future__ import annotations

import hashlib
import hmac
import os
import sqlite3
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


PBKDF2_ITERATIONS = 180_000


@dataclass(frozen=True)
class StoredMessage:
    message_id: int
    sender: str
    recipient: str
    body: str
    created_at: int


def _hash_password(password: str) -> str:
    salt = os.urandom(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        PBKDF2_ITERATIONS,
    )
    return f"pbkdf2_sha256${PBKDF2_ITERATIONS}${salt.hex()}${digest.hex()}"


def _verify_password(password: str, encoded: str) -> bool:
    algo, raw_iterations, salt_hex, digest_hex = encoded.split("$", 3)
    if algo != "pbkdf2_sha256":
        return False
    expected = bytes.fromhex(digest_hex)
    digest = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        bytes.fromhex(salt_hex),
        int(raw_iterations),
    )
    return hmac.compare_digest(expected, digest)


class Storage:
    def __init__(self, db_path: str) -> None:
        path = Path(db_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._lock = threading.Lock()
        self._initialize()

    def _initialize(self) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS users (
                    username TEXT PRIMARY KEY,
                    password_hash TEXT NOT NULL,
                    created_at INTEGER NOT NULL
                )
                """
            )
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS messages (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    sender TEXT NOT NULL,
                    recipient TEXT NOT NULL,
                    body TEXT NOT NULL,
                    created_at INTEGER NOT NULL,
                    delivered_at INTEGER,
                    read_at INTEGER
                )
                """
            )
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS blocks (
                    blocker TEXT NOT NULL,
                    blocked TEXT NOT NULL,
                    created_at INTEGER NOT NULL,
                    PRIMARY KEY (blocker, blocked)
                )
                """
            )

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    def authenticate_or_register(self, username: str, password: str) -> str:
        now = int(time.time())
        with self._lock, self._conn:
            row = self._conn.execute(
                "SELECT password_hash FROM users WHERE username = ?",
                (username,),
            ).fetchone()
            if row is None:
                self._conn.execute(
                    "INSERT INTO users (username, password_hash, created_at) VALUES (?, ?, ?)",
                    (username, _hash_password(password), now),
                )
                return "registered"
            if _verify_password(password, row["password_hash"]):
                return "authenticated"
            return "invalid"

    def user_exists(self, username: str) -> bool:
        with self._lock:
            row = self._conn.execute(
                "SELECT 1 FROM users WHERE username = ?",
                (username,),
            ).fetchone()
            return row is not None

    def list_users(self) -> list[str]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT username FROM users ORDER BY username ASC"
            ).fetchall()
        return [row["username"] for row in rows]

    def store_message(self, sender: str, recipient: str, body: str) -> int:
        now = int(time.time())
        with self._lock, self._conn:
            cursor = self._conn.execute(
                """
                INSERT INTO messages (sender, recipient, body, created_at)
                VALUES (?, ?, ?, ?)
                """,
                (sender, recipient, body, now),
            )
            return int(cursor.lastrowid)

    def get_message_owner(self, message_id: int) -> Optional[tuple[str, str]]:
        with self._lock:
            row = self._conn.execute(
                "SELECT sender, recipient FROM messages WHERE id = ?",
                (message_id,),
            ).fetchone()
        if row is None:
            return None
        return row["sender"], row["recipient"]

    def mark_delivered(self, message_id: int) -> None:
        now = int(time.time())
        with self._lock, self._conn:
            self._conn.execute(
                "UPDATE messages SET delivered_at = COALESCE(delivered_at, ?) WHERE id = ?",
                (now, message_id),
            )

    def mark_read(self, message_id: int) -> None:
        now = int(time.time())
        with self._lock, self._conn:
            self._conn.execute(
                "UPDATE messages SET read_at = COALESCE(read_at, ?) WHERE id = ?",
                (now, message_id),
            )

    def pending_messages_for(self, username: str) -> list[StoredMessage]:
        with self._lock:
            rows = self._conn.execute(
                """
                SELECT id, sender, recipient, body, created_at
                FROM messages
                WHERE recipient = ? AND delivered_at IS NULL
                ORDER BY id ASC
                """,
                (username,),
            ).fetchall()
        return [
            StoredMessage(
                message_id=row["id"],
                sender=row["sender"],
                recipient=row["recipient"],
                body=row["body"],
                created_at=row["created_at"],
            )
            for row in rows
        ]

    def conversation_history(self, user_a: str, user_b: str, limit: int) -> list[StoredMessage]:
        with self._lock:
            rows = self._conn.execute(
                """
                SELECT id, sender, recipient, body, created_at
                FROM messages
                WHERE (sender = ? AND recipient = ?)
                   OR (sender = ? AND recipient = ?)
                ORDER BY id DESC
                LIMIT ?
                """,
                (user_a, user_b, user_b, user_a, limit),
            ).fetchall()
        history = [
            StoredMessage(
                message_id=row["id"],
                sender=row["sender"],
                recipient=row["recipient"],
                body=row["body"],
                created_at=row["created_at"],
            )
            for row in rows
        ]
        history.reverse()
        return history

    def block_user(self, blocker: str, blocked: str) -> None:
        now = int(time.time())
        with self._lock, self._conn:
            self._conn.execute(
                """
                INSERT OR IGNORE INTO blocks (blocker, blocked, created_at)
                VALUES (?, ?, ?)
                """,
                (blocker, blocked, now),
            )

    def unblock_user(self, blocker: str, blocked: str) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                "DELETE FROM blocks WHERE blocker = ? AND blocked = ?",
                (blocker, blocked),
            )

    def is_blocked(self, blocker: str, blocked: str) -> bool:
        with self._lock:
            row = self._conn.execute(
                "SELECT 1 FROM blocks WHERE blocker = ? AND blocked = ?",
                (blocker, blocked),
            ).fetchone()
        return row is not None
