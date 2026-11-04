"""Security-aware redaction and structured run report helpers."""
from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from settings import model_name

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


def _redact_data(value: Any) -> Any:
    """Recursively redact strings before structured state enters a report."""
    if isinstance(value, str):
        return _redact_source(value)
    if isinstance(value, list):
        return [_redact_data(item) for item in value]
    if isinstance(value, dict):
        return {key: _redact_data(item) for key, item in value.items()}
    return value


def _phase_status(name: str, state: dict[str, Any], later_phase: str,
                  failure_stage: str, tests_passed: bool) -> str:
    """Resolve one report phase without nested conditional expressions."""
    if failure_stage == name:
        return "failed"
    if name == "scan":
        status = state.get("run_status")
        if status in {"scan_incomplete", "no_findings"}:
            return status
        return "completed" if state.get("manifest_path") else "not_started"
    if name == "planning":
        return "completed" if state.get("proposed_files") else later_phase
    if name == "source_usage":
        return "completed" if state.get("usage_analysis") else later_phase
    if name == "patch":
        return "applied" if state.get("changed_files") else later_phase
    if name == "lockfile":
        status = state.get("lockfile_status", "")
        if status in {"updated", "unchanged"}:
            return status
        if status in {"not_required", "not_configured"}:
            return "skipped"
        return later_phase
    if name == "verification":
        if state.get("is_verified"):
            return "verified"
        if any(item.get("stage") == "verification" for item in state.get("failed_findings", [])):
            return "failed"
        return later_phase
    if name == "approval":
        if state.get("approval_granted"):
            return "approved"
        if state.get("run_status") == "awaiting_human_review":
            return "awaiting_human_review"
        return later_phase
    if name == "tests":
        return "passed" if tests_passed else "failed" if state.get("test_history") else later_phase
    if name == "pull_request":
        return "created" if state.get("pr_url") else later_phase
    return later_phase


def build_run_report(state: dict[str, Any], started_at: datetime, finished_at: datetime) -> dict[str, Any]:
    """Return a JSON-safe, credential-redacted summary of one graph invocation."""
    findings = []
    for finding in state.get("initial_vulnerabilities") or state.get("vulnerabilities", []):
        package = finding.get("package", {})
        findings.append({
            "id": finding.get("id", "unknown"),
            "summary": _redact_source(str(finding.get("summary", ""))),
            "package": package.get("name", ""),
            "version": package.get("version", ""),
            "ecosystem": package.get("ecosystem", ""),
        })
    test_runs = []
    for result in state.get("test_history", []):
        output = _redact_source(str(result.get("output", "")))[-3000:]
        test_runs.append({
            "passed": bool(result.get("passed")),
            "returncode": result.get("returncode"),
            "failure_classification": result.get("failure_classification", ""),
            "output_excerpt": output,
        })
    baseline_result = state.get("baseline_results", {})
    baseline_report = ({
        "passed": bool(baseline_result.get("passed")),
        "returncode": baseline_result.get("returncode"),
        "output_excerpt": _redact_source(str(baseline_result.get("output", "")))[-3000:],
    } if baseline_result else None)
    started = started_at.astimezone(timezone.utc)
    finished = finished_at.astimezone(timezone.utc)
    overall_status = state.get("run_status", "failed")
    failure_stage = state.get("error_stage", "")
    test_runs_passed = bool(test_runs and test_runs[-1]["passed"])
    batch_summary = _redact_data(state.get("batch_summary", {
        "patched": state.get("patched_findings", []),
        "failed": state.get("failed_findings", []),
        "skipped": state.get("skipped_findings", []),
    }))
    for category in ("patched", "failed"):
        for item in batch_summary.get(category, []):
            for test_run in item.get("test_runs", []):
                if "output" in test_run:
                    test_run["output"] = str(test_run["output"])[-3000:]
    if overall_status == "awaiting_human_review":
        batch_summary = {
            **batch_summary,
            "status": "awaiting_human_review",
            "pending_review": {
                "id": state.get("current_vuln", {}).get("id", ""),
                "package": state.get("current_vuln", {}).get("package", {}).get("name", ""),
                "branch": state.get("branch_name", ""),
            },
        }
    if overall_status in {"no_findings", "scan_incomplete"}:
        later_phase = "skipped"
    else:
        later_phase = "not_started"
    phases = [
        {"name": name, "status": _phase_status(name, state, later_phase, failure_stage, test_runs_passed)}
        for name in ("scan", "source_usage", "planning", "patch", "lockfile", "tests", "verification", "approval", "pull_request")
    ]
    return {
        "schema_version": 1,
        "status": overall_status,
        "model": {"provider": "openai", "name": model_name()},
        "repository": state.get("repo_path", ""),
        "started_at": started.isoformat(),
        "finished_at": finished.isoformat(),
        "duration_seconds": round(max(0.0, (finished - started).total_seconds()), 3),
        "phases": phases,
        "manifest": state.get("manifest_path", ""),
        "packages_checked": state.get("package_count", 0),
        "unresolved_packages": state.get("unresolved_packages", []),
        "warnings": [_redact_source(str(item)) for item in state.get("scan_warnings", [])],
        "findings": findings,
        "patch": {
            "branch": state.get("branch_name", ""),
            "base_branch": state.get("base_branch", ""),
            "proposed_files": state.get("proposed_files", []),
            "files": state.get("changed_files", []),
            "diff": _redact_source(str(state.get("patch_diff", "")))[:20000],
        },
        "lockfile": {
            "status": state.get("lockfile_status", ""),
            "warning": _redact_source(str(state.get("lockfile_warning", ""))),
        },
        "verification": _redact_data(state.get("verification_result", {
            "verified": bool(state.get("is_verified")),
        })),
        "retrieval": _redact_data(
            state.get("usage_analysis", [])[-1].get("retrieval", {})
            if state.get("usage_analysis") else {}
        ),
        "source_usage": {
            "note": (
                "Ranked source locations are RAG or literal-search leads for human review. "
                "They do not prove vulnerable behavior or exploitability and are not used to generate patches."
            ),
            "findings": _redact_data(state.get("usage_analysis", [])),
        },
        "approval_granted": bool(state.get("approval_granted")),
        "tests": {"baseline": baseline_report, "attempts": len(test_runs), "runs": test_runs},
        "pull_request_url": state.get("pr_url", ""),
        "mcp_tool_calls": state.get("mcp_tool_calls", []),
        "batch_summary": batch_summary,
        "failure": ({
            "stage": state.get("error_stage", ""),
            "code": state.get("error_code", ""),
            "message": _redact_source(str(state.get("error", ""))),
            "next_action": _failure_action(state.get("error_stage", ""), state.get("error_code", "")),
        } if state.get("error") and state.get("run_status") not in {"no_findings", "scan_incomplete"} else None),
    }


def _failure_action(stage: str, code: str) -> str:
    """Give the report a practical recovery hint for common failure stages."""
    if stage == "scan":
        return "Check the manifest/lockfile and network access to OSV, then rerun the scan."
    if stage == "planning":
        return "Check the model API key, model availability, and returned patch format before retrying."
    if stage == "patch":
        return "Inspect the target branch and repository status; resolve the reported path or Git issue before rerunning."
    if stage == "lockfile":
        return "Check the lockfile tool output, install uv or Poetry if needed, and verify dependency constraints in pyproject.toml."
    if stage == "verification":
        return "Inspect the resolved package version and OSV result. The agent will not push or open a PR until the advisory is absent for a resolved version."
    if stage == "approval":
        return "Resume the saved thread with --approve-pr only after reviewing the proposed diff and verification result."
    if stage == "tests":
        return "Inspect the saved test output and local agent branch; fix the cause before rerunning."
    if stage == "pull_request":
        return "The commit or pushed branch may already exist. Check the recorded branch on GitHub, fix permissions, then open or retry the PR manually."
    return "Review the failure details and repository branch state before retrying."
