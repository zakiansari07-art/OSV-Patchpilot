"""Shared runtime settings used by the workflow and its reports."""
from __future__ import annotations

import os

DEFAULT_MODEL = "gpt-4o-mini"


def model_name() -> str:
    """Return the configured model name with one consistent default."""
    return os.getenv("OPENAI_MODEL", DEFAULT_MODEL)
