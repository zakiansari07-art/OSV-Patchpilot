"""Run repository tests with a deliberately minimal child environment."""
from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path
from typing import Any, Sequence


# Child test code does not need API credentials, cloud configuration, SSH
# agents, or the rest of the invoking process environment.
SAFE_ENV_KEYS = {
    "PATH", "HOME", "TMPDIR", "TMP", "TEMP", "SYSTEMROOT", "WINDIR",
    "LANG", "LC_ALL",
}
DEFAULT_TEST_TIMEOUT_SECONDS = 60


def classify_test_results(
    baseline: dict[str, Any] | None, after_patch: dict[str, Any]
) -> str:
    """Compare post-patch failures to baseline without masking new failures.

    We only label a failure pre-existing when stable failure lines match. If a
    runner emits no recognizable failure identifiers, exact normalized output
    equality is required; uncertain cases are treated as new/changed failures.
    """
    if after_patch.get("passed"):
        return "passed"
    if not baseline:
        return "baseline_unavailable"
    if baseline.get("passed"):
        return "new_or_changed_failure"

    baseline_output = _text_output(baseline.get("output"))
    patched_output = _text_output(after_patch.get("output"))
    baseline_signatures = _failure_signatures(baseline_output)
    patched_signatures = _failure_signatures(patched_output)
    if baseline_signatures and patched_signatures:
        if patched_signatures.issubset(baseline_signatures):
            return "baseline_failure_persists"
        return "new_or_changed_failure"
    if _normalize_output(baseline_output) == _normalize_output(patched_output):
        return "baseline_failure_persists"
    return "new_or_changed_failure"


def _failure_signatures(output: str) -> set[str]:
    signatures: set[str] = set()
    for line in output.splitlines():
        cleaned = line.strip()
        match = re.match(r"^(FAILED|ERROR)\s+(.+?)\s+-\s+(.+)$", cleaned)
        if match:
            signatures.add(" ".join(match.groups()))
            continue
        # Common Jest, Node TAP, and pytest verbose failure markers.
        if re.match(r"^(?:FAIL\s+|✖\s+|not ok\s+)", cleaned):
            signatures.add(cleaned)
    return signatures


def _normalize_output(output: str) -> str:
    output = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", output)
    output = re.sub(r"\bin\s+\d+(?:\.\d+)?s\b", "in <duration>", output)
    return "\n".join(line.strip() for line in output.splitlines() if line.strip())


def _text_output(value: str | bytes | None) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value


def run_tests_safely(
    repo_path: str,
    test_command: Sequence[str],
    *,
    timeout_seconds: int = DEFAULT_TEST_TIMEOUT_SECONDS,
) -> dict[str, Any]:
    """Run tests without inheriting host secrets and return captured results.

    This is environment isolation, not an OS sandbox: callers should still
    use a disposable container or VM for repositories they do not trust.
    """
    if not test_command or any(not isinstance(item, str) or not item for item in test_command):
        raise ValueError("test_command must be a non-empty sequence of non-empty strings")
    if timeout_seconds <= 0:
        raise ValueError("timeout_seconds must be positive")

    parent_env = os.environ
    child_env = {key: parent_env[key] for key in SAFE_ENV_KEYS if key in parent_env}
    # Keeps common JS test runners from switching into interactive watch mode.
    child_env["CI"] = "true"

    try:
        completed = subprocess.run(
            list(test_command),
            cwd=Path(repo_path).resolve(),
            env=child_env,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            check=False,
        )
        stdout = _text_output(completed.stdout)
        stderr = _text_output(completed.stderr)
        return {
            "passed": completed.returncode == 0,
            "returncode": completed.returncode,
            "stdout": stdout,
            "stderr": stderr,
            "output": stdout + stderr,
            "timed_out": False,
        }
    except subprocess.TimeoutExpired as exc:
        stdout = _text_output(exc.stdout)
        stderr = _text_output(exc.stderr)
        timeout_message = f"Test command exceeded the {timeout_seconds}-second timeout."
        stderr = f"{stderr}\n{timeout_message}".strip()
        return {
            "passed": False,
            "returncode": -1,
            "stdout": stdout,
            "stderr": stderr,
            "output": stdout + stderr,
            "timed_out": True,
        }
    except OSError as exc:
        message = f"Could not start test command ({type(exc).__name__}): {exc}"
        return {
            "passed": False,
            "returncode": -1,
            "stdout": "",
            "stderr": message,
            "output": message,
            "timed_out": False,
        }
