"""Credential redaction and sensitive-path checks for review evidence."""
from __future__ import annotations

import re
from pathlib import Path

_SECRET_PATH_PARTS = {".env", ".npmrc", ".pypirc", "credentials", "secrets", "id_rsa", "id_ed25519"}
_SECRET_FILE_SUFFIXES = {".pem", ".key", ".p12", ".pfx", ".keystore"}
_SECRET_NAME = re.compile(r"(?i)(?:^|[._-])(?:credentials?|secrets?|tokens?|passwords?|private[_-]?keys?|api[_-]?keys?|access[_-]?keys?)(?:[._-]|$)")
_SECRET_VALUE = re.compile(
    r"(?i)(?P<prefix>[\"']?(?:[\w-]*api[_-]?key[\w-]*|[\w-]*token[\w-]*|[\w-]*password[\w-]*|[\w-]*passwd[\w-]*|[\w-]*secret[\w-]*|[\w-]*credential[\w-]*|authorization)[\"']?\s*[:=]\s*)"
    r"(?P<value>(?P<quote>[\"'])[^\"'\r\n]+(?P=quote)|[A-Za-z0-9_-]{12,})"
)


def _is_sensitive_path(path: str) -> bool:
    candidate = Path(path)
    parts = {part.lower() for part in candidate.parts}
    name = candidate.name.lower()
    return (bool(parts & _SECRET_PATH_PARTS)
            or any(_SECRET_NAME.search(part) for part in parts)
            or name.startswith(".env")
            or candidate.suffix.lower() in _SECRET_FILE_SUFFIXES)


def _redact_source(text: str) -> str:
    """Redact common literal credential assignments before model prompting."""
    def replacement(match: re.Match[str]) -> str:
        value = match.group("value")
        quote = match.group("quote")
        if quote:
            return f"{match.group('prefix')}{quote}[REDACTED]{quote}"
        return f"{match.group('prefix')}[REDACTED]"
    return _SECRET_VALUE.sub(replacement, text)
