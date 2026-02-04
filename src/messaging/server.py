"""
Simple TCP messaging server for private intranet usage.
"""

from __future__ import annotations

import argparse
import logging
import re
import signal
import socket
import ssl
import threading
import time
from collections import defaultdict, deque
from typing import Deque, Dict, Optional

from .protocol import (
    Command,
    format_delivered,
    format_error,
    format_from,
    format_info,
    format_ok,
    format_pong,
    format_read,
    parse_command,
)
from .storage import Storage


MAX_LINE_BYTES = 16_384
MAX_MESSAGE_BYTES = 4_096
USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{3,32}$")
RATE_LIMIT_MESSAGES = 20
RATE_LIMIT_WINDOW_SECONDS = 10
DEFAULT_HISTORY_LIMIT = 20
MAX_HISTORY_LIMIT = 200


class LineReceiver:
    """Receive full lines from a TCP stream, buffering partial data."""

    def __init__(self, sock: socket.socket, max_line_bytes: int = MAX_LINE_BYTES) -> None:
        self.sock = sock
        self.buffer = bytearray()
        self.max_line_bytes = max_line_bytes

    def recv_line(self) -> Optional[str]:
        while True:
            nl_index = self.buffer.find(b"\n")
            if nl_index != -1:
                line = self.buffer[: nl_index + 1]
                del self.buffer[: nl_index + 1]
                return line.decode("utf-8", errors="replace")
            if len(self.buffer) > self.max_line_bytes:
                raise ValueError("line too long")
            try:
                chunk = self.sock.recv(4096)
            except socket.timeout:
                return None
            if not chunk:
                return ""
            self.buffer.extend(chunk)
            if len(self.buffer) > self.max_line_bytes:
                raise ValueError("line too long")


class ClientConnection:
    def __init__(self, sock: socket.socket, address: tuple[str, int]) -> None:
        self.sock = sock
        self.address = address
        self.username: Optional[str] = None
        self.protocol_version: Optional[str] = None
        self.receiver = LineReceiver(sock)
        self.send_lock = threading.Lock()

    def send(self, data: str) -> None:
        with self.send_lock:
            self.sock.sendall(data.encode("utf-8"))

    def close(self) -> None:
        try:
            self.sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        self.sock.close()


class MessageServer:
    def __init__(
        self,
        host: str,
        port: int,
        db_path: str,
        tls_context: Optional[ssl.SSLContext] = None,
    ) -> None:
        self.host = host
        self.port = port
        self.logger = logging.getLogger("server")
        self.clients: Dict[str, ClientConnection] = {}
        self.rate_limiter: dict[str, Deque[int]] = defaultdict(deque)
        self.lock = threading.Lock()
        self.stop_event = threading.Event()
        self.server_sock: Optional[socket.socket] = None
        self.tls_context = tls_context
        self.storage = Storage(db_path)

    def start(self) -> None:
        self.server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_sock.bind((self.host, self.port))
        self.server_sock.listen()
        self.server_sock.settimeout(1.0)
        self.logger.info("Server listening on %s:%s", self.host, self.port)

        while not self.stop_event.is_set():
            try:
                client_sock, address = self.server_sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break

            if self.tls_context:
                try:
                    client_sock = self.tls_context.wrap_socket(client_sock, server_side=True)
                except ssl.SSLError:
                    client_sock.close()
                    self.logger.warning("TLS handshake failed with %s", address)
                    continue

            client_sock.settimeout(1.0)
            client = ClientConnection(client_sock, address)
            thread = threading.Thread(target=self.handle_client, args=(client,), daemon=True)
            thread.start()

        self.logger.info("Server shutting down")
        self.close_all_clients()
        self.storage.close()
        if self.server_sock:
            self.server_sock.close()

    def stop(self) -> None:
        self.stop_event.set()
        if self.server_sock:
            try:
                self.server_sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass

    def close_all_clients(self) -> None:
        with self.lock:
            clients = list(self.clients.values())
            self.clients.clear()
        for client in clients:
            client.close()

    def handle_client(self, client: ClientConnection) -> None:
        self.logger.info("Connection from %s", client.address)
        try:
            self.handle_client_loop(client)
        except (ConnectionResetError, BrokenPipeError):
            self.logger.info("Connection lost with %s", client.address)
        finally:
            self.unregister_client(client)
            client.close()

    def handle_client_loop(self, client: ClientConnection) -> None:
        while not self.stop_event.is_set():
            try:
                line = client.receiver.recv_line()
            except ValueError as exc:
                client.send(format_error(str(exc), "BAD_REQUEST"))
                break

            if line is None:
                continue
            if line == "":
                break

            try:
                command = parse_command(line)
            except ValueError as exc:
                client.send(format_error(str(exc), "BAD_REQUEST"))
                continue

            self.process_command(client, command)

    def process_command(self, client: ClientConnection, command: Command) -> None:
        if command.name == "HELLO":
            version = command.args[0]
            if version != "1":
                client.send(format_error("unsupported protocol version", "BAD_VERSION"))
                return
            client.protocol_version = version
            client.send(format_ok("hello"))
            return

        if command.name == "AUTH":
            username, password = command.args
            if client.username is not None:
                client.send(format_error("already authenticated", "ALREADY_AUTHENTICATED"))
                return
            if not USERNAME_RE.match(username):
                client.send(format_error("invalid username format", "INVALID_USERNAME"))
                return
            if len(password) < 8:
                client.send(format_error("password too short", "WEAK_PASSWORD"))
                return
            auth_state = self.storage.authenticate_or_register(username, password)
            if auth_state == "invalid":
                client.send(format_error("invalid credentials", "AUTH_FAILED"))
                return
            if not self.register_client(client, username):
                client.send(format_error("username already connected", "ALREADY_CONNECTED"))
                return
            action = "registered" if auth_state == "registered" else "authenticated"
            client.send(format_ok(action))
            self.deliver_pending_messages(client)
            self.broadcast_info(f"user_online {username}", except_user=username)
            return

        if client.username is None:
            client.send(format_error("please authenticate with AUTH first", "NOT_AUTHENTICATED"))
            return

        if command.name == "MSG":
            target, message = command.args
            self.route_message(client, target, message)
            return

        if command.name == "LIST":
            self.send_user_list(client)
            return

        if command.name == "HISTORY":
            target = command.args[0]
            limit = DEFAULT_HISTORY_LIMIT
            if len(command.args) == 2:
                limit = int(command.args[1])
            self.send_history(client, target, limit)
            return

        if command.name == "READ":
            self.mark_read(client, int(command.args[0]))
            return

        if command.name == "BLOCK":
            self.block_user(client, command.args[0])
            return

        if command.name == "UNBLOCK":
            self.unblock_user(client, command.args[0])
            return

        if command.name == "PING":
            client.send(format_pong())
            return

        if command.name == "QUIT":
            client.send(format_ok("bye"))
            raise ConnectionResetError()

    def register_client(self, client: ClientConnection, username: str) -> bool:
        with self.lock:
            if username in self.clients:
                return False
            self.clients[username] = client
            client.username = username
        self.logger.info("User connected: %s", username)
        return True

    def unregister_client(self, client: ClientConnection) -> None:
        if client.username is None:
            return
        username = client.username
        with self.lock:
            existing = self.clients.get(username)
            if existing is client:
                del self.clients[username]
        self.logger.info("User disconnected: %s", username)
        self.broadcast_info(f"user_offline {username}", except_user=username)

    def _under_rate_limit(self, username: str) -> bool:
        now = int(time.time())
        history = self.rate_limiter[username]
        while history and (now - history[0]) >= RATE_LIMIT_WINDOW_SECONDS:
            history.popleft()
        if len(history) >= RATE_LIMIT_MESSAGES:
            return False
        history.append(now)
        return True

    def route_message(self, sender: ClientConnection, target: str, message: str) -> None:
        sender_name = sender.username or ""
        if not USERNAME_RE.match(target):
            sender.send(format_error("invalid target username", "INVALID_TARGET"))
            return
        if target == sender_name:
            sender.send(format_error("cannot message yourself", "INVALID_TARGET"))
            return
        if len(message.encode("utf-8")) > MAX_MESSAGE_BYTES:
            sender.send(format_error("message too long", "MESSAGE_TOO_LONG"))
            return
        if not self._under_rate_limit(sender_name):
            sender.send(format_error("rate limit exceeded", "RATE_LIMIT"))
            return
        if not self.storage.user_exists(target):
            sender.send(format_error("unknown target", "UNKNOWN_TARGET"))
            return
        if self.storage.is_blocked(target, sender_name):
            sender.send(format_error("recipient blocked you", "BLOCKED"))
            return

        message_id = self.storage.store_message(sender_name, target, message)

        with self.lock:
            target_client = self.clients.get(target)

        if target_client:
            try:
                timestamp = int(time.time())
                target_client.send(format_from(message_id, sender_name, timestamp, message))
                self.storage.mark_delivered(message_id)
                sender.send(format_delivered(message_id))
            except (ConnectionResetError, BrokenPipeError, OSError):
                sender.send(format_ok(f"queued {message_id}"))
        else:
            sender.send(format_ok(f"queued {message_id}"))

    def deliver_pending_messages(self, client: ClientConnection) -> None:
        username = client.username
        if username is None:
            return
        pending = self.storage.pending_messages_for(username)
        for entry in pending:
            try:
                client.send(
                    format_from(entry.message_id, entry.sender, entry.created_at, entry.body)
                )
                self.storage.mark_delivered(entry.message_id)
                with self.lock:
                    sender_client = self.clients.get(entry.sender)
                if sender_client:
                    sender_client.send(format_delivered(entry.message_id))
            except (ConnectionResetError, BrokenPipeError, OSError):
                break

    def mark_read(self, client: ClientConnection, message_id: int) -> None:
        owner = self.storage.get_message_owner(message_id)
        if owner is None:
            client.send(format_error("unknown message", "UNKNOWN_MESSAGE"))
            return
        sender_name, recipient_name = owner
        current = client.username or ""
        if current not in {sender_name, recipient_name}:
            client.send(format_error("forbidden", "FORBIDDEN"))
            return

        self.storage.mark_read(message_id)
        if current == recipient_name:
            with self.lock:
                sender_client = self.clients.get(sender_name)
            if sender_client:
                sender_client.send(format_read(message_id, recipient_name))
        client.send(format_ok(f"read {message_id}"))

    def send_history(self, client: ClientConnection, target: str, limit: int) -> None:
        username = client.username or ""
        if not USERNAME_RE.match(target):
            client.send(format_error("invalid target username", "INVALID_TARGET"))
            return
        if not self.storage.user_exists(target):
            client.send(format_error("unknown target", "UNKNOWN_TARGET"))
            return
        bounded_limit = max(1, min(limit, MAX_HISTORY_LIMIT))
        entries = self.storage.conversation_history(username, target, bounded_limit)
        client.send(format_info(f"history_count {len(entries)}"))
        for entry in entries:
            client.send(
                format_info(
                    f"history {entry.message_id} {entry.sender} {entry.created_at} {entry.body}"
                )
            )

    def block_user(self, client: ClientConnection, target: str) -> None:
        username = client.username or ""
        if target == username:
            client.send(format_error("cannot block yourself", "INVALID_TARGET"))
            return
        if not USERNAME_RE.match(target):
            client.send(format_error("invalid target username", "INVALID_TARGET"))
            return
        if not self.storage.user_exists(target):
            client.send(format_error("unknown target", "UNKNOWN_TARGET"))
            return
        self.storage.block_user(username, target)
        client.send(format_ok(f"blocked {target}"))

    def unblock_user(self, client: ClientConnection, target: str) -> None:
        username = client.username or ""
        if not USERNAME_RE.match(target):
            client.send(format_error("invalid target username", "INVALID_TARGET"))
            return
        self.storage.unblock_user(username, target)
        client.send(format_ok(f"unblocked {target}"))

    def send_user_list(self, client: ClientConnection) -> None:
        with self.lock:
            online = sorted(self.clients.keys())
        known = self.storage.list_users()
        client.send(format_info("online: " + ", ".join(online)))
        client.send(format_info("known: " + ", ".join(known)))

    def broadcast_info(self, message: str, except_user: Optional[str] = None) -> None:
        with self.lock:
            recipients = [
                c for name, c in self.clients.items() if except_user is None or name != except_user
            ]
        for client in recipients:
            try:
                client.send(format_info(message))
            except OSError:
                pass


def build_tls_context(cert_path: str, key_path: str) -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=cert_path, keyfile=key_path)
    return context


def main() -> None:
    parser = argparse.ArgumentParser(description="Simple TCP messaging server")
    parser.add_argument("--host", default="0.0.0.0", help="bind address")
    parser.add_argument("--port", type=int, default=9000, help="TCP port")
    parser.add_argument("--db-path", default="./data/chat.db", help="SQLite database path")
    parser.add_argument("--tls-cert", default=None, help="TLS certificate path (PEM)")
    parser.add_argument("--tls-key", default=None, help="TLS private key path (PEM)")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
    )

    tls_context: Optional[ssl.SSLContext] = None
    if args.tls_cert or args.tls_key:
        if not args.tls_cert or not args.tls_key:
            raise SystemExit("Both --tls-cert and --tls-key are required for TLS")
        tls_context = build_tls_context(args.tls_cert, args.tls_key)

    server = MessageServer(args.host, args.port, args.db_path, tls_context=tls_context)

    def handle_sigint(_signum: int, _frame: object) -> None:
        server.logger.info("SIGINT received, stopping")
        server.stop()

    signal.signal(signal.SIGINT, handle_sigint)
    server.start()


if __name__ == "__main__":
    main()
