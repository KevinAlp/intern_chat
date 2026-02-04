"""
Protocol helpers for the simple TCP messaging system.
Each command is a single UTF-8 line terminated by '\n'.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Command:
    name: str
    args: tuple[str, ...]


def parse_command(line: str) -> Command:
    line = line.rstrip("\n")
    if not line:
        raise ValueError("empty line")
    head, *rest = line.split(" ", 1)
    name = head.upper()

    if name == "MSG":
        if not rest:
            raise ValueError("MSG requires <target_username> <message>")
        parts = rest[0].split(" ", 1)
        if len(parts) != 2 or not parts[0] or not parts[1]:
            raise ValueError("MSG requires <target_username> <message>")
        return Command(name, (parts[0], parts[1]))

    tokens = [name]
    if rest:
        tokens.extend(rest[0].split(" "))

    if name == "HELLO":
        if len(tokens) != 2 or not tokens[1]:
            raise ValueError("HELLO requires <version>")
        return Command(name, (tokens[1],))
    if name == "AUTH":
        if len(tokens) != 3 or not tokens[1] or not tokens[2]:
            raise ValueError("AUTH requires <username> <password>")
        return Command(name, (tokens[1], tokens[2]))
    if name == "LIST":
        if len(tokens) != 1:
            raise ValueError("LIST takes no argument")
        return Command(name, ())
    if name == "HISTORY":
        if len(tokens) not in {2, 3} or not tokens[1]:
            raise ValueError("HISTORY requires <username> [limit]")
        if len(tokens) == 3 and not tokens[2].isdigit():
            raise ValueError("HISTORY limit must be numeric")
        return Command(name, tuple(tokens[1:]))
    if name == "READ":
        if len(tokens) != 2 or not tokens[1].isdigit():
            raise ValueError("READ requires <message_id>")
        return Command(name, (tokens[1],))
    if name in {"BLOCK", "UNBLOCK"}:
        if len(tokens) != 2 or not tokens[1]:
            raise ValueError(f"{name} requires <username>")
        return Command(name, (tokens[1],))
    if name == "PING":
        if len(tokens) != 1:
            raise ValueError("PING takes no argument")
        return Command(name, ())
    if name == "QUIT":
        if len(tokens) != 1:
            raise ValueError("QUIT takes no argument")
        return Command(name, ())
    raise ValueError(f"unknown command: {name}")


def format_ok(message: str) -> str:
    return f"OK {message}\n"


def format_info(message: str) -> str:
    return f"INFO {message}\n"


def format_error(reason: str, code: str = "GENERIC") -> str:
    return f"ERROR {code} {reason}\n"


def format_from(message_id: int, username: str, timestamp: int, message: str) -> str:
    return f"FROM {message_id} {username} {timestamp} {message}\n"


def format_delivered(message_id: int) -> str:
    return f"DELIVERED {message_id}\n"


def format_read(message_id: int, username: str) -> str:
    return f"READ {message_id} {username}\n"


def format_pong() -> str:
    return "PONG\n"
