"""
Simple TCP messaging client for private intranet usage.
"""

from __future__ import annotations

import argparse
import socket
import sys
import threading
from typing import Optional

from .protocol import format_error


class LineReceiver:
    """Receive full lines from a TCP stream, buffering partial data."""

    def __init__(self, sock: socket.socket) -> None:
        self.sock = sock
        self.buffer = bytearray()

    def recv_line(self) -> Optional[str]:
        while True:
            nl_index = self.buffer.find(b"\n")
            if nl_index != -1:
                line = self.buffer[: nl_index + 1]
                del self.buffer[: nl_index + 1]
                return line.decode("utf-8", errors="replace")
            try:
                chunk = self.sock.recv(4096)
            except socket.timeout:
                return None
            if not chunk:
                return ""
            self.buffer.extend(chunk)


class Client:
    def __init__(self, host: str, port: int, username: str) -> None:
        self.host = host
        self.port = port
        self.username = username
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.settimeout(1.0)
        self.receiver = LineReceiver(self.sock)
        self.stop_event = threading.Event()

    def connect(self) -> None:
        self.sock.connect((self.host, self.port))
        self.send_line(f"HELLO {self.username}")

    def send_line(self, line: str) -> None:
        self.sock.sendall((line + "\n").encode("utf-8"))

    def recv_loop(self) -> None:
        while not self.stop_event.is_set():
            line = self.receiver.recv_line()
            if line is None:
                continue
            if line == "":
                print("INFO server disconnected")
                self.stop_event.set()
                return
            print(line.rstrip("\n"))

    def run(self) -> None:
        receiver_thread = threading.Thread(target=self.recv_loop, daemon=True)
        receiver_thread.start()
        try:
            while not self.stop_event.is_set():
                try:
                    raw = input()
                except EOFError:
                    raw = "QUIT"
                if not raw:
                    continue
                if raw.upper().startswith("MSG ") or raw.upper() in {"LIST", "QUIT"}:
                    self.send_line(raw)
                    if raw.upper() == "QUIT":
                        self.stop_event.set()
                        break
                else:
                    print(format_error("unknown command").rstrip("\n"))
        finally:
            self.close()

    def close(self) -> None:
        try:
            self.sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        self.sock.close()


def validate_username(username: str) -> None:
    # Keep usernames simple and space-free for parsing.
    if not username or " " in username:
        raise ValueError("username must be non-empty and contain no spaces")


def main() -> None:
    parser = argparse.ArgumentParser(description="Simple TCP messaging client")
    parser.add_argument("--host", default="127.0.0.1", help="server address")
    parser.add_argument("--port", type=int, default=9000, help="TCP port")
    parser.add_argument("username", help="your username")
    args = parser.parse_args()

    try:
        validate_username(args.username)
        client = Client(args.host, args.port, args.username)
        client.connect()
        client.run()
    except ValueError as exc:
        print(format_error(str(exc)).rstrip("\n"))
        sys.exit(1)
    except (ConnectionRefusedError, ConnectionResetError, BrokenPipeError):
        print("ERROR cannot connect to server")
        sys.exit(1)


if __name__ == "__main__":
    main()
