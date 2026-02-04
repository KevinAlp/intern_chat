"""
Simple TCP messaging client for private intranet usage.
"""

from __future__ import annotations

import argparse
import getpass
import re
import socket
import ssl
import sys
import threading
from typing import Optional

from .protocol import format_error


MAX_LINE_BYTES = 16_384
USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{3,32}$")


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


class Client:
    def __init__(
        self,
        host: str,
        port: int,
        username: str,
        password: str,
        ssl_context: Optional[ssl.SSLContext],
    ) -> None:
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.ssl_context = ssl_context
        base_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        if ssl_context:
            self.sock = ssl_context.wrap_socket(base_sock, server_hostname=host)
        else:
            self.sock = base_sock
        self.sock.settimeout(1.0)
        self.receiver = LineReceiver(self.sock)
        self.stop_event = threading.Event()
        self.send_lock = threading.Lock()

    def connect(self) -> None:
        self.sock.connect((self.host, self.port))
        self.send_line("HELLO 1")
        self.send_line(f"AUTH {self.username} {self.password}")

    def send_line(self, line: str) -> None:
        with self.send_lock:
            self.sock.sendall((line + "\n").encode("utf-8"))

    def handle_server_line(self, line: str) -> None:
        text = line.rstrip("\n")
        if text.startswith("FROM "):
            parts = text.split(" ", 4)
            if len(parts) == 5 and parts[1].isdigit():
                message_id = int(parts[1])
                sender = parts[2]
                message = parts[4]
                print(f"FROM {sender}: {message} (id={message_id})")
                try:
                    self.send_line(f"READ {message_id}")
                except OSError:
                    self.stop_event.set()
            else:
                print(text)
            return
        print(text)

    def recv_loop(self) -> None:
        while not self.stop_event.is_set():
            try:
                line = self.receiver.recv_line()
            except ValueError as exc:
                print(format_error(str(exc), "BAD_RESPONSE").rstrip("\n"))
                self.stop_event.set()
                return
            if line is None:
                continue
            if line == "":
                print("INFO server disconnected")
                self.stop_event.set()
                return
            self.handle_server_line(line)

    def normalize_input(self, raw: str) -> Optional[str]:
        if not raw:
            return None
        if raw.startswith("/"):
            parts = raw.split(" ", 2)
            cmd = parts[0].lower()
            if cmd == "/msg" and len(parts) == 3:
                return f"MSG {parts[1]} {parts[2]}"
            if cmd == "/list":
                return "LIST"
            if cmd == "/history" and len(parts) in {2, 3}:
                return "HISTORY " + " ".join(parts[1:])
            if cmd == "/block" and len(parts) == 2:
                return f"BLOCK {parts[1]}"
            if cmd == "/unblock" and len(parts) == 2:
                return f"UNBLOCK {parts[1]}"
            if cmd == "/ping":
                return "PING"
            if cmd == "/quit":
                return "QUIT"
            if cmd == "/help":
                print("Commands: /msg /list /history /block /unblock /ping /quit")
                return None
            print(format_error("unknown local command").rstrip("\n"))
            return None

        upper = raw.upper()
        if (
            upper.startswith("MSG ")
            or upper.startswith("HISTORY ")
            or upper.startswith("READ ")
            or upper.startswith("BLOCK ")
            or upper.startswith("UNBLOCK ")
            or upper in {"LIST", "PING", "QUIT"}
        ):
            return raw
        print(format_error("unknown command").rstrip("\n"))
        return None

    def run(self) -> None:
        receiver_thread = threading.Thread(target=self.recv_loop, daemon=True)
        receiver_thread.start()
        try:
            while not self.stop_event.is_set():
                try:
                    raw = input()
                except EOFError:
                    raw = "/quit"
                command = self.normalize_input(raw.strip())
                if not command:
                    continue
                self.send_line(command)
                if command.upper() == "QUIT":
                    self.stop_event.set()
                    break
        finally:
            self.close()

    def close(self) -> None:
        try:
            self.sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        self.sock.close()


def validate_username(username: str) -> None:
    if not USERNAME_RE.match(username):
        raise ValueError("username must match [A-Za-z0-9_.-]{3,32}")


def validate_password(password: str) -> None:
    if len(password) < 8:
        raise ValueError("password must contain at least 8 characters")
    if " " in password:
        raise ValueError("password cannot contain spaces")


def build_ssl_context(
    use_tls: bool,
    ca_cert: Optional[str],
    tls_insecure: bool,
) -> Optional[ssl.SSLContext]:
    if not use_tls:
        return None
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    if ca_cert:
        context.load_verify_locations(cafile=ca_cert)
    elif tls_insecure:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    return context


def main() -> None:
    parser = argparse.ArgumentParser(description="Simple TCP messaging client")
    parser.add_argument("--host", default="127.0.0.1", help="server address")
    parser.add_argument("--port", type=int, default=9000, help="TCP port")
    parser.add_argument("--password", default=None, help="account password")
    parser.add_argument("--tls", action="store_true", help="enable TLS")
    parser.add_argument("--ca-cert", default=None, help="CA/cert file for TLS verification")
    parser.add_argument(
        "--tls-insecure",
        action="store_true",
        help="disable TLS certificate verification",
    )
    parser.add_argument("username", help="your username")
    args = parser.parse_args()

    password = args.password or getpass.getpass("Password: ")

    try:
        validate_username(args.username)
        validate_password(password)
        ssl_context = build_ssl_context(args.tls, args.ca_cert, args.tls_insecure)
        client = Client(args.host, args.port, args.username, password, ssl_context)
        client.connect()
        client.run()
    except ValueError as exc:
        print(format_error(str(exc), "INVALID_INPUT").rstrip("\n"))
        sys.exit(1)
    except (
        ConnectionRefusedError,
        ConnectionResetError,
        BrokenPipeError,
        ssl.SSLError,
        OSError,
    ):
        print("ERROR cannot connect to server")
        sys.exit(1)


if __name__ == "__main__":
    main()
