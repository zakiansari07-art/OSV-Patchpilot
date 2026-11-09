"""Architecture guardrails: keep modules and functions reviewable in size."""
from __future__ import annotations

import ast
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
EXCLUDED_PARTS = {".git", ".venv", "venv", "__pycache__", ".pytest_cache", "saved report"}
EXCLUDED_PREFIXES = ("evals/rag/fixtures",)

# Shrink these allowlists as the cleanup proceeds; the goal is an empty set.
ALLOWED_LARGE_FILES: set[str] = set()

ALLOWED_LONG_FUNCTIONS: set[tuple[str, str]] = set()

MAX_FILE_LINES = 500
MAX_FUNCTION_LINES = 80


def _python_files() -> list[Path]:
    files = []
    for path in ROOT.rglob("*.py"):
        if any(part in EXCLUDED_PARTS for part in path.parts):
            continue
        relative = path.relative_to(ROOT).as_posix()
        if relative.startswith(EXCLUDED_PREFIXES):
            continue
        files.append(path)
    return sorted(files)


def test_source_files_stay_under_500_lines():
    oversized = []
    for path in _python_files():
        relative = path.relative_to(ROOT).as_posix()
        if relative in ALLOWED_LARGE_FILES:
            continue
        lines = len(path.read_text(encoding="utf-8").splitlines())
        if lines > MAX_FILE_LINES:
            oversized.append(f"{relative}: {lines} lines")
    assert not oversized, "Split these files into modules:\n" + "\n".join(oversized)


def test_source_functions_stay_under_80_lines():
    oversized = []
    for path in _python_files():
        relative = path.relative_to(ROOT).as_posix()
        if relative.startswith("tests/"):
            continue
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except SyntaxError:  # pragma: no cover - compileall covers this
            continue
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            length = getattr(node, "end_lineno", node.lineno) - node.lineno + 1
            if length <= MAX_FUNCTION_LINES:
                continue
            if (relative, node.name) in ALLOWED_LONG_FUNCTIONS:
                continue
            oversized.append(f"{relative}:{node.lineno} {node.name} ({length} lines)")
    assert not oversized, "Split these functions:\n" + "\n".join(oversized)
