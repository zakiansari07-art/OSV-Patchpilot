"""Credential redaction and sensitive-path checks for review evidence."""
from __future__ import annotations

import re

from vulnerability_agent.security import is_sensitive_path as _is_sensitive_path

_SECRET_VALUE = re.compile(
    r"(?i)(?P<prefix>[\"']?(?:[\w-]*api[_-]?key[\w-]*|[\w-]*token[\w-]*|[\w-]*password[\w-]*|[\w-]*passwd[\w-]*|[\w-]*secret[\w-]*|[\w-]*credential[\w-]*|authorization)[\"']?\s*[:=]\s*)"
    r"(?P<value>(?P<quote>[\"'])[^\"'\r\n]+(?P=quote)|[A-Za-z0-9_-]{12,})"
)


def _redact_source(text: str) -> str:
    """Redact common literal credential assignments before model prompting."""
    def replacement(match: re.Match[str]) -> str:
        value = match.group("value")
        quote = match.group("quote")
        if quote:
            return f"{match.group('prefix')}{quote}[REDACTED]{quote}"
        return f"{match.group('prefix')}[REDACTED]"
    return _SECRET_VALUE.sub(replacement, text)
