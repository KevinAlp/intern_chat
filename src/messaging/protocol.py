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
    """
    Parse a client->server line into a Command.
    We split only on spaces to preserve message text as-is.
    """
    line = line.rstrip("\n")
    if not line:
        raise ValueError("empty line")
    parts = line.split(" ", 2)
    name = parts[0].upper()
    if name == "HELLO":
        if len(parts) != 2 or not parts[1]:
            raise ValueError("HELLO requires <username>")
        return Command(name, (parts[1],))
    if name == "MSG":
        if len(parts) < 3 or not parts[1] or not parts[2]:
            raise ValueError("MSG requires <target_username> <message>")
        return Command(name, (parts[1], parts[2]))
    if name == "LIST":
        return Command(name, ())
    if name == "QUIT":
        return Command(name, ())
    raise ValueError(f"unknown command: {name}")


def format_ok(message: str) -> str:
    return f"OK {message}\n"


def format_info(message: str) -> str:
    return f"INFO {message}\n"


def format_error(reason: str) -> str:
    return f"ERROR {reason}\n"


def format_from(username: str, message: str) -> str:
    return f"FROM {username} {message}\n"

