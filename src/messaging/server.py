"""
Simple TCP messaging server for private intranet usage.
"""

from __future__ import annotations

import argparse
import logging
import signal
import socket
import threading
from typing import Dict, Optional

from .protocol import (
    Command,
    format_error,
    format_from,
    format_info,
    format_ok,
    parse_command,
)


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


class ClientConnection:
    def __init__(self, sock: socket.socket, address: tuple[str, int]) -> None:
        self.sock = sock
        self.address = address
        self.username: Optional[str] = None
        self.receiver = LineReceiver(sock)

    def send(self, data: str) -> None:
        self.sock.sendall(data.encode("utf-8"))

    def close(self) -> None:
        try:
            self.sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        self.sock.close()


class MessageServer:
    def __init__(self, host: str, port: int) -> None:
        self.host = host
        self.port = port
        self.logger = logging.getLogger("server")
        self.clients: Dict[str, ClientConnection] = {}
        self.lock = threading.Lock()
        self.stop_event = threading.Event()
        self.server_sock: Optional[socket.socket] = None

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
            client_sock.settimeout(1.0)
            client = ClientConnection(client_sock, address)
            thread = threading.Thread(target=self.handle_client, args=(client,), daemon=True)
            thread.start()

        self.logger.info("Server shutting down")
        self.close_all_clients()
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
            line = client.receiver.recv_line()
            if line is None:
                continue
            if line == "":
                break
            try:
                command = parse_command(line)
            except ValueError as exc:
                client.send(format_error(str(exc)))
                continue
            self.process_command(client, command)

    def process_command(self, client: ClientConnection, command: Command) -> None:
        if command.name == "HELLO":
            username = command.args[0]
            if not self.register_client(client, username):
                client.send(format_error("username already in use"))
                return
            client.send(format_ok("welcome"))
            return
        if client.username is None:
            client.send(format_error("please identify with HELLO first"))
            return
        if command.name == "MSG":
            target, message = command.args
            self.route_message(client, target, message)
        elif command.name == "LIST":
            self.send_user_list(client)
        elif command.name == "QUIT":
            client.send(format_ok("bye"))
            raise ConnectionResetError()

    def register_client(self, client: ClientConnection, username: str) -> bool:
        with self.lock:
            if username in self.clients:
                return False
            self.clients[username] = client
            client.username = username
        self.logger.info("User registered: %s", username)
        return True

    def unregister_client(self, client: ClientConnection) -> None:
        if client.username is None:
            return
        with self.lock:
            existing = self.clients.get(client.username)
            if existing is client:
                del self.clients[client.username]
        self.logger.info("User disconnected: %s", client.username)

    def route_message(self, sender: ClientConnection, target: str, message: str) -> None:
        with self.lock:
            target_client = self.clients.get(target)
        if not target_client:
            sender.send(format_error("unknown target"))
            return
        try:
            target_client.send(format_from(sender.username or "?", message))
            sender.send(format_ok("delivered"))
        except (ConnectionResetError, BrokenPipeError, OSError):
            sender.send(format_error("delivery failed"))

    def send_user_list(self, client: ClientConnection) -> None:
        with self.lock:
            users = sorted(self.clients.keys())
        client.send(format_info("users: " + ", ".join(users)))


def main() -> None:
    parser = argparse.ArgumentParser(description="Simple TCP messaging server")
    parser.add_argument("--host", default="0.0.0.0", help="bind address")
    parser.add_argument("--port", type=int, default=9000, help="TCP port")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
    )

    server = MessageServer(args.host, args.port)

    def handle_sigint(_signum: int, _frame: object) -> None:
        server.logger.info("SIGINT received, stopping")
        server.stop()

    signal.signal(signal.SIGINT, handle_sigint)
    server.start()


if __name__ == "__main__":
    main()
