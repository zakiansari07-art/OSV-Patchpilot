"""CLI entry point for the autonomous vulnerability patch agent."""
from __future__ import annotations

import argparse
import json
import os
import sqlite3
import sys
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Sequence
from urllib.parse import urlparse

from dotenv import load_dotenv

from agent_graph import build_graph, build_run_report
from mcp_client import default_state_db_path
from persistence import SQLiteAgentPersistence
from reporting import _redact_source
from vulnerability_agent.review_graph import build_dependabot_review_graph
from vulnerability_agent.report_validation import (
    EvidenceReportValidationError,
    report_validation_observability,
    validate_evidence_report,
)


_PROGRESS_LABELS = {
    "scan": "Scanning dependency manifests with OSV",
    "select_finding": "Selecting the next advisory",
    "report_source_usage": "Finding likely source usage locations for the report",
    "prepare_worktree": "Preparing an isolated Git branch",
    "baseline_tests": "Checking the repository’s existing test baseline",
    "investigate": "Analyzing relevant code and planning a patch",
    "apply": "Applying the proposed patch",
    "regenerate_lockfile": "Regenerating dependency lockfiles",
    "tests": "Running tests",
    "verify_patch": "Rescanning OSV to verify the fix",
    "await_approval": "Waiting at the human approval checkpoint",
    "create_pr": "Pushing the branch and creating a pull request",
    "rescan": "Rescanning dependencies after the pull request",
    "cleanup_worktree": "Cleaning up the isolated worktree",
    "record_failure": "Recording this finding’s failure",
    "log_failure": "Recording scan failure",
    "finalize": "Preparing the run summary",
}
DEFAULT_REPORT_DIRECTORY = Path(__file__).resolve().parent / "saved report"


def _save_report_files(
    rendered: str,
    automatic_path: Path,
    requested_path: Path | None,
    report_label: str,
) -> bool:
    """Always archive reports locally, and optionally write a second requested copy."""
    destinations = [automatic_path]
    if requested_path is not None and requested_path != automatic_path:
        destinations.append(requested_path)
    failed = False
    for destination in destinations:
        try:
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_text(rendered + "\n", encoding="utf-8")
            print(f"{report_label} saved: {destination}", file=sys.stderr)
        except OSError as exc:
            failed = True
            print(f"Could not save {report_label.lower()} to {destination}: {exc}", file=sys.stderr)
    return not failed


def _elapsed_label(seconds: float) -> str:
    elapsed = max(0, int(seconds))
    minutes, remainder = divmod(elapsed, 60)
    return f"{minutes:02d}:{remainder:02d}"


def _progress(message: str, started_at: float) -> None:
    """Write human-readable status to stderr, preserving JSON stdout."""
    print(f"[{_elapsed_label(time.monotonic() - started_at)}] {message}", file=sys.stderr, flush=True)


def _workflow_invoke_with_progress(workflow: Any, value: Any, config: dict[str, Any]) -> dict[str, Any]:
    """Stream LangGraph task start/end events and show heartbeats for long nodes."""
    if not callable(getattr(workflow, "stream", None)):
        # Keep the CLI usable with lightweight workflow adapters and test doubles.
        return workflow.invoke(value, config=config)
    run_started = time.monotonic()
    active_tasks: dict[str, tuple[threading.Event, threading.Thread, str, float]] = {}

    def stop_heartbeat(task_id: str) -> tuple[str, float] | None:
        active = active_tasks.pop(task_id, None)
        if active is None:
            return None
        finished, heartbeat, label, task_started = active
        finished.set()
        heartbeat.join(timeout=0.2)
        return label, task_started

    try:
        for event in workflow.stream(value, config=config, stream_mode="tasks"):
            if not isinstance(event, dict) or not event.get("name"):
                continue
            task_id = str(event.get("id", event["name"]))
            node_name = str(event["name"])
            if "result" not in event and "error" not in event:
                label = _PROGRESS_LABELS.get(node_name, node_name.replace("_", " ").capitalize())
                task_input = event.get("input") or {}
                finding = task_input.get("current_vuln", {}) if isinstance(task_input, dict) else {}
                package = finding.get("package", {}) if isinstance(finding, dict) else {}
                package_name = package.get("name", "") if isinstance(package, dict) else str(package)
                suffix = f" — {package_name}" if package_name else ""
                attempt = task_input.get("attempt_count") if isinstance(task_input, dict) else None
                if node_name == "tests" and attempt:
                    suffix += f" (attempt {attempt}/3; each test run has a 60-second timeout)"
                _progress(f"{label}{suffix}…", run_started)
                task_started = time.monotonic()
                finished = threading.Event()

                def heartbeat(
                    done: threading.Event = finished,
                    task_label: str = label,
                    started: float = task_started,
                ) -> None:
                    while not done.wait(30):
                        _progress(
                            f"Still {task_label.lower()} (working for {_elapsed_label(time.monotonic() - started)})…",
                            run_started,
                        )

                worker = threading.Thread(target=heartbeat, daemon=True)
                active_tasks[task_id] = (finished, worker, label, task_started)
                worker.start()
                continue

            active = stop_heartbeat(task_id)
            if active is None:
                label = _PROGRESS_LABELS.get(node_name, node_name.replace("_", " ").capitalize())
                task_started = time.monotonic()
            else:
                label, task_started = active
            result = event.get("result")
            if event.get("error") or (isinstance(result, dict) and result.get("error_stage")):
                suffix = "failed"
            elif node_name == "tests" and isinstance(result, dict):
                tests = result.get("test_results", {})
                suffix = "passed" if tests.get("passed") else "finished with failures"
            else:
                suffix = "complete"
            _progress(f"{label}: {suffix} ({_elapsed_label(time.monotonic() - task_started)})", run_started)
    finally:
        for task_id in list(active_tasks):
            stop_heartbeat(task_id)

    snapshot = workflow.get_state(config)
    if tuple(snapshot.next) == ("await_approval",):
        _progress(
            "Paused for your review. Inspect the report, then run `python main.py --approve` to continue.",
            run_started,
        )
    elif not snapshot.next:
        _progress("Workflow finished.", run_started)
    return dict(snapshot.values)


def _pending_approval_threads(
    workflow: Any, persistence: SQLiteAgentPersistence, requested_repo: Path | None,
) -> list[dict[str, Any]]:
    """Find paused graph threads, optionally restricted to one repository."""
    pending: list[dict] = []
    for candidate_thread_id in persistence.list_thread_ids():
        config = {
            "configurable": {"thread_id": candidate_thread_id},
            "recursion_limit": 100_000,
        }
        try:
            snapshot = workflow.get_state(config)
        except (KeyError, ValueError, sqlite3.Error):
            continue
        if tuple(snapshot.next) != ("await_approval",):
            continue
        state = snapshot.values
        repository_value = state.get("main_repo_path") or state.get("repo_path")
        if not repository_value:
            continue
        repository = Path(repository_value).expanduser().resolve()
        if requested_repo is not None and repository != requested_repo:
            continue
        pending.append({
            "thread_id": candidate_thread_id,
            "repository": repository,
            "state": state,
            "snapshot": snapshot,
            "config": config,
        })
    return pending


def _resumable_threads(
    workflow: Any, persistence: SQLiteAgentPersistence,
) -> list[dict[str, Any]]:
    """Find checkpointed workflows paused somewhere other than approval."""
    resumable: list[dict[str, Any]] = []
    for candidate_thread_id in persistence.list_thread_ids():
        config = {
            "configurable": {"thread_id": candidate_thread_id},
            "recursion_limit": 100_000,
        }
        try:
            snapshot = workflow.get_state(config)
        except Exception:
            continue
        next_nodes = tuple(snapshot.next)
        if not next_nodes or next_nodes == ("await_approval",):
            continue
        state = snapshot.values
        repository = state.get("main_repo_path") or state.get("repo_path")
        resumable.append({
            "thread_id": candidate_thread_id,
            "repository": Path(repository).expanduser().resolve() if repository else Path("."),
            "state": state,
            "snapshot": snapshot,
            "config": config,
            "next_nodes": next_nodes,
        })
    return resumable


def _recent_reports(report_directory: Path, limit: int = 8) -> list[dict[str, Any]]:
    """Read recent auto-saved reports for the CLI dashboard."""
    reports: list[dict[str, Any]] = []
    try:
        paths = sorted(
            report_directory.glob("run-*.json"),
            key=lambda path: path.stat().st_mtime,
            reverse=True,
        )
    except OSError:
        return reports
    for path in paths[:limit]:
        try:
            content = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if isinstance(content, dict):
            reports.append({"path": path, "report": content})
    return reports


def _format_advisory_ids(finding: dict[str, Any]) -> list[str]:
    ids = finding.get("advisory_ids")
    if not ids:
        ids = [item.get("id", "unknown") for item in finding.get("advisories", [])]
    if not ids and finding.get("id"):
        ids = [finding["id"]]
    return sorted({str(item) for item in ids})


def _print_approval_summary(
    state: dict[str, Any], repository: Path | None = None,
    thread_id: str = "",
) -> None:
    """Print the evidence a person should inspect before authorizing a PR."""
    finding = state.get("current_vuln", {})
    package = finding.get("package", {})
    if not isinstance(package, dict):
        package = {"name": str(package)}
    guidance = finding.get("upgrade_guidance", {})
    verification = state.get("verification_result", {})
    lock = state.get("lockfile_verification", {})
    baseline = state.get("baseline_results", {})
    attempts = state.get("test_history", [])
    ids = _format_advisory_ids(finding)
    old_version = verification.get("old_version") or guidance.get("current_version") or package.get("version", "unknown")
    new_version = verification.get("version") or lock.get("resolved_version") or guidance.get("recommended_version", "unknown")
    print("\nReview this verified change before approving:", file=sys.stderr)
    print(f"  Repository: {repository or state.get('main_repo_path') or state.get('repo_path', 'unknown')}", file=sys.stderr)
    if thread_id:
        print(f"  Run ID: {thread_id}", file=sys.stderr)
    print(f"  Package: {package.get('name', 'unknown')} ({package.get('ecosystem', 'unknown')})", file=sys.stderr)
    print(f"  Resolved version: {old_version} -> {new_version}", file=sys.stderr)
    print(f"  Advisories covered: {', '.join(ids) if ids else 'not recorded'}", file=sys.stderr)
    if guidance.get("range_reasoning"):
        print("  OSV range check:", file=sys.stderr)
        for reason in guidance["range_reasoning"]:
            print(f"    - {reason}", file=sys.stderr)
    print(f"  Target branch: {state.get('base_branch', 'unknown')}", file=sys.stderr)
    print(f"  PR branch: {state.get('branch_name', 'unknown')}", file=sys.stderr)
    files = state.get("changed_files") or state.get("proposed_files") or []
    print(f"  Files changed: {', '.join(files) if files else 'not recorded'}", file=sys.stderr)
    print(
        f"  Lockfile: {state.get('lockfile_status', 'not_required')}"
        + (f"; resolved {lock.get('resolved_version')}" if lock.get("resolved_version") else ""),
        file=sys.stderr,
    )
    print(f"  Baseline tests: {'passed' if baseline.get('passed') else 'failed or not recorded'}", file=sys.stderr)
    if attempts:
        last = attempts[-1]
        print(
            f"  Post-change tests: {'passed' if last.get('passed') else 'failed'}"
            f" (attempt {len(attempts)}/3, exit {last.get('returncode', 'unknown')})",
            file=sys.stderr,
        )
    print(
        f"  OSV verification: {'passed' if verification.get('verified', state.get('is_verified')) else 'not verified'}; "
        f"{verification.get('remaining_advisories_for_package', 'unknown')} other advisories remain for this package.",
        file=sys.stderr,
    )
    usage = state.get("current_usage_analysis", {})
    locations = usage.get("locations", []) if isinstance(usage, dict) else []
    if locations:
        print("  Possible source usage (review leads only):", file=sys.stderr)
        for item in locations[:3]:
            print(
                f"    - {item.get('path', 'unknown')}:{item.get('line_start', '?')} "
                f"({item.get('symbol', 'code')}; {item.get('match_type', 'retrieved')})",
                file=sys.stderr,
            )
            if item.get("excerpt"):
                excerpt = str(item["excerpt"]).replace("\n", " ")[:180]
                print(f"      {excerpt}", file=sys.stderr)
    elif usage:
        retrieval = usage.get("retrieval", {})
        print(
            f"  Possible source usage: no locations found ({retrieval.get('backend', 'search unavailable')}).",
            file=sys.stderr,
        )
    if usage:
        print("  Source search is informational and is not used to create the patch.", file=sys.stderr)
    diff = _redact_source(str(state.get("patch_diff", "")))
    if diff:
        preview = diff[:2400]
        print("  Proposed diff preview:", file=sys.stderr)
        print("\n".join(f"    {line}" for line in preview.splitlines()), file=sys.stderr)
        if len(diff) > len(preview):
            print("    … diff shortened; see the saved JSON report for the full diff.", file=sys.stderr)
    print("  Approval authorizes pushing this branch and opening a PR; it does not merge the PR.", file=sys.stderr)


def _print_report_summary(item: dict[str, Any], index: int) -> None:
    report = item["report"]
    batch = report.get("batch_summary", {})
    pending = batch.get("pending_review", {})
    patched = batch.get("patched", [])
    failed = batch.get("failed", [])
    print(
        f"  {index}. {report.get('status', 'unknown')} | "
        f"{Path(report.get('repository') or '.').name} | "
        f"{len(report.get('findings', []))} findings | "
        f"{len(patched)} PR(s) | {len(failed)} failure(s)",
        file=sys.stderr,
    )
    print(f"     {report.get('repository', 'repository unknown')}", file=sys.stderr)
    if pending:
        print(
            f"     Waiting: {pending.get('package', 'package')} / {pending.get('id', 'advisory')} "
            f"on {pending.get('branch', 'branch unknown')}",
            file=sys.stderr,
        )
    for result in patched:
        url = result.get("pull_request_url") or result.get("pr_url")
        if url:
            print(f"     PR: {url}", file=sys.stderr)


def _print_saved_report_detail(item: dict[str, Any]) -> None:
    """Render a saved JSON report as a compact, beginner-friendly review."""
    report = item["report"]
    batch = report.get("batch_summary", {})
    print("\nSaved run report", file=sys.stderr)
    print(f"  File: {item['path']}", file=sys.stderr)
    print(f"  Status: {report.get('status', 'unknown')}", file=sys.stderr)
    print(f"  Repository: {report.get('repository', 'unknown')}", file=sys.stderr)
    print(f"  Started: {report.get('started_at', 'unknown')}", file=sys.stderr)
    model = report.get("model", {})
    model_name = model.get("name", "unknown") if isinstance(model, dict) else str(model)
    print(f"  Model: {model_name}", file=sys.stderr)
    print("  Workflow phases:", file=sys.stderr)
    for phase in report.get("phases", []):
        print(f"    - {phase.get('name', 'phase')}: {phase.get('status', 'unknown')}", file=sys.stderr)
    findings = report.get("findings", [])
    if findings:
        print(f"  Findings ({len(findings)}):", file=sys.stderr)
        for finding in findings[:12]:
            print(
                f"    - {finding.get('package', 'package')} {finding.get('version', '')}: "
                f"{finding.get('id', 'unknown')} — {finding.get('summary', '')}",
                file=sys.stderr,
            )
        if len(findings) > 12:
            print(f"    … and {len(findings) - 12} more; see the JSON report.", file=sys.stderr)
    source_usage = report.get("source_usage", {})
    for usage in source_usage.get("findings", [])[:8]:
        ids = ", ".join(usage.get("advisory_ids", [])) or "advisory unknown"
        print(f"  Possible code locations for {usage.get('package', 'package')} ({ids}):", file=sys.stderr)
        for location in usage.get("locations", [])[:3]:
            print(
                f"    - {location.get('path', 'unknown')}:{location.get('line_start', '?')} "
                f"({location.get('symbol', 'code')}; {location.get('match_type', 'retrieved')})",
                file=sys.stderr,
            )
        if not usage.get("locations"):
            print("    - No likely usage locations found.", file=sys.stderr)
    if source_usage.get("note"):
        print(f"  Note: {source_usage['note']}", file=sys.stderr)
    for patched in batch.get("patched", []):
        url = patched.get("pull_request_url") or patched.get("pr_url")
        if url:
            print(f"  PR for {patched.get('package', 'package')}: {url}", file=sys.stderr)
    pending = batch.get("pending_review")
    if pending:
        print(
            f"  Waiting for review: {pending.get('package', 'package')} / "
            f"{pending.get('id', 'advisory')} on {pending.get('branch', 'branch unknown')}",
            file=sys.stderr,
        )
    if batch.get("failed"):
        print(f"  Failed findings ({len(batch['failed'])}):", file=sys.stderr)
        for failed in batch["failed"][:8]:
            print(
                f"    - {failed.get('package', 'package')} / {failed.get('id', 'advisory')} "
                f"at {failed.get('stage', 'unknown stage')}: {failed.get('error', 'no details')}",
                file=sys.stderr,
            )
    diff = _redact_source(str(report.get("patch", {}).get("diff", "")))
    if diff:
        print("  Current proposed diff:", file=sys.stderr)
        print("\n".join(f"    {line}" for line in diff[:2400].splitlines()), file=sys.stderr)
        if len(diff) > 2400:
            print("    … diff shortened; see the JSON report for the rest.", file=sys.stderr)


def _read_cli_choice(prompt: str) -> str:
    print(prompt, end="", file=sys.stderr, flush=True)
    value = sys.stdin.readline()
    # Treat Ctrl-D / a closed input stream as a clean quit. This prevents the
    # menu from repeatedly prompting when stdin reaches EOF.
    return value.strip() if value else "q"


def _interactive_dashboard(state_database: Path) -> dict[str, Any] | None:
    """Offer beginner-friendly actions when the CLI starts without arguments."""
    while True:
        try:
            with SQLiteAgentPersistence(state_database) as persistence:
                workflow = build_graph(
                    checkpointer=persistence.checkpointer,
                    audit_database_path=state_database,
                    run_id="cli-dashboard",
                    interrupt_before_pr=True,
                )
                pending = _pending_approval_threads(workflow, persistence, None)
                resumable = _resumable_threads(workflow, persistence)
        except Exception as exc:
            print(f"Could not load saved workflow state: {type(exc).__name__}: {exc}", file=sys.stderr)
            return None
        recent = _recent_reports(DEFAULT_REPORT_DIRECTORY)
        print("\nOpen Source Vulnerability Patch Agent", file=sys.stderr)
        print(f"Saved report folder: {DEFAULT_REPORT_DIRECTORY}", file=sys.stderr)
        if pending:
            print("\nWaiting for your review:", file=sys.stderr)
            for index, item in enumerate(pending, 1):
                finding = item["state"].get("current_vuln", {})
                package = finding.get("package", {})
                target = finding.get("upgrade_guidance", {}).get("recommended_version", "unknown")
                ids = ", ".join(_format_advisory_ids(finding))
                print(
                    f"  {index}. {package.get('name', 'package')} -> {target} | {ids} | "
                    f"{item['repository']}",
                    file=sys.stderr,
                )
        else:
            print("\nNo runs are currently waiting for approval.", file=sys.stderr)
        if recent:
            print("\nRecent runs:", file=sys.stderr)
            for index, item in enumerate(recent[:5], 1):
                _print_report_summary(item, index)
        print("\nChoose an action:", file=sys.stderr)
        print("  a  Review and approve a verified PR change", file=sys.stderr)
        print("  r  Resume an interrupted run", file=sys.stderr)
        print("  n  Start a new repository scan", file=sys.stderr)
        print("  v  View a saved run report", file=sys.stderr)
        print("  q  Quit", file=sys.stderr)
        choice = _read_cli_choice("Action [a/r/n/v/q]: ").strip().lower()
        if choice in {"q", "quit", "exit"}:
            return None
        if choice in {"a", "approve"}:
            if not pending:
                print("There are no pending approval checkpoints.", file=sys.stderr)
                continue
            selected = _choose_pending_approval(pending)
            confirmation = _read_cli_choice("Type approve to authorize push and PR creation, or q to cancel: ").lower()
            if confirmation != "approve":
                print("Approval canceled; the run remains paused.", file=sys.stderr)
                continue
            return {"action": "approve", "thread_id": selected["thread_id"],
                    "repository": selected["repository"], "summary_printed": True}
        if choice in {"r", "resume"}:
            if not resumable:
                print("No interrupted runs are available to resume.", file=sys.stderr)
                continue
            selected = _choose_pending_approval(resumable, approval=False)
            return {"action": "resume", "thread_id": selected["thread_id"],
                    "repository": selected["repository"]}
        if choice in {"n", "new", "scan"}:
            raw_path = _read_cli_choice("Repository folder path: ").strip().strip("\"'")
            if not raw_path:
                print("No repository path entered.", file=sys.stderr)
                continue
            repository = Path(raw_path).expanduser().resolve()
            if not repository.is_dir() or not (repository / ".git").exists():
                print("That path is not a Git working tree. Enter a repository folder and try again.", file=sys.stderr)
                continue
            return {"action": "new", "repository": repository}
        if choice in {"v", "view", "reports"}:
            if not recent:
                print("No saved reports were found yet.", file=sys.stderr)
                continue
            print("Select a report number, or q to return:", file=sys.stderr)
            for index, item in enumerate(recent, 1):
                _print_report_summary(item, index)
            report_choice = _read_cli_choice(f"Report [1-{len(recent)} / q]: ").lower()
            if report_choice in {"q", "quit"}:
                continue
            if report_choice.isdigit() and 1 <= int(report_choice) <= len(recent):
                item = recent[int(report_choice) - 1]
                _print_saved_report_detail(item)
            else:
                print("Choose one of the listed report numbers, or q.", file=sys.stderr)
            continue
        print("Choose a, r, n, v, or q.", file=sys.stderr)


def _choose_pending_approval(
    pending: list[dict[str, Any]], *, approval: bool = True,
) -> dict[str, Any]:
    """Select a saved run and show the appropriate review or resume summary."""
    if len(pending) == 1:
        selected = pending[0]
    else:
        print("Pending approvals:", file=sys.stderr)
        for index, item in enumerate(pending, start=1):
            state = item["state"]
            finding = state.get("current_vuln", {})
            package = finding.get("package", {})
            package_name = package.get("name", "unknown package") if isinstance(package, dict) else package
            advisory_ids = ", ".join(_format_advisory_ids(finding)) or "unknown advisory"
            print(
                f"  {index}. {package_name} / {advisory_ids}"
                f" — {state.get('branch_name', 'branch unknown')} — {item['repository']}",
                file=sys.stderr,
            )
        while True:
            choice = _read_cli_choice(f"Choose a run [1-{len(pending)}] or q to cancel: ").lower()
            if choice in {"q", "quit"}:
                raise SystemExit(0)
            if choice.isdigit() and 1 <= int(choice) <= len(pending):
                selected = pending[int(choice) - 1]
                break
            print("Enter one of the listed numbers, or q to cancel.", file=sys.stderr)

    state = selected["state"]
    if approval:
        finding = state.get("current_vuln", {})
        package = finding.get("package", {})
        package_name = package.get("name", "unknown package") if isinstance(package, dict) else package
        print(f"Approving {package_name} / {', '.join(_format_advisory_ids(finding)) or 'unknown advisory'}", file=sys.stderr)
        _print_approval_summary(state, selected["repository"], selected["thread_id"])
    else:
        print(f"Resuming run {selected['thread_id']}", file=sys.stderr)
        print(f"Repository: {selected['repository']}", file=sys.stderr)
        print(f"Next workflow step: {', '.join(selected.get('next_nodes', []))}", file=sys.stderr)
    return selected


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Review Dependabot PRs or scan and remediate OSV findings in a local repository.")
    parser.add_argument("repo", nargs="?", type=Path,
                        help="Path to a Git repository (not needed for --approve or --resume)")
    parser.add_argument("--report", type=Path,
                        help="Also save a copy of the JSON report at this path; every run is archived in ./saved report/")
    parser.add_argument("--state-db", type=Path,
                        help="SQLite database for graph checkpoints and MCP audit records")
    parser.add_argument("--thread-id", help="Stable workflow thread ID (generated when omitted)")
    parser.add_argument("--resume", metavar="THREAD_ID", help="Resume an interrupted or crashed workflow thread; repo can be inferred")
    parser.add_argument("--pause-before-pr", action="store_true",
                        help="Deprecated compatibility flag; human approval is now always required before PR creation")
    parser.add_argument("--approve", "--approve-pr", dest="approve_pr", action="store_true",
                        help="Approve the only pending run, or choose a run if several are waiting")
    parser.add_argument("--review-pr", metavar="URL_OR_NUMBER",
                        help="Investigate an open Dependabot PR with tests, OSV, RAG, and an AI review")
    parser.add_argument("--post-comment", action="store_true",
                        help="Post or update the AI review as a comment on the reviewed PR")
    parser.add_argument("--collect-only", action="store_true",
                        help="Collect tests/OSV/RAG evidence without an LLM call; for a secret-free CI job")
    parser.add_argument("--analyze-report", type=Path, metavar="JSON",
                        help="Analyze a previously collected JSON report and optionally post its PR comment")
    parser.add_argument("--report-artifact-url",
                        help="GitHub Actions artifact URL to include in the report and PR comment")
    parser.add_argument("--expected-pr", type=int,
                        help="Expected PR number for validating a report before comment posting")
    parser.add_argument("--expected-repository", metavar="OWNER/REPOSITORY",
                        help="Expected GitHub repository for validating a report before comment posting")
    parser.add_argument("--expected-head-sha", metavar="SHA",
                        help="Expected PR head commit for validating a report before comment posting")
    args = parser.parse_args(argv)
    load_dotenv()
    state_database = (args.state_db or default_state_db_path()).expanduser().resolve()
    tracing_enabled = os.getenv("LANGSMITH_TRACING", "false").strip().lower() in {"1", "true", "yes", "on"}
    if tracing_enabled and not os.getenv("LANGSMITH_API_KEY"):
        parser.error("LANGSMITH_TRACING is enabled but LANGSMITH_API_KEY is missing")
    repo = args.repo.expanduser().resolve() if args.repo else None
    if args.post_comment and not args.review_pr:
        if not args.analyze_report:
            parser.error("--post-comment requires --review-pr or --analyze-report")
    if args.collect_only and not args.review_pr:
        parser.error("--collect-only requires --review-pr")
    if args.report_artifact_url and not args.analyze_report:
        parser.error("--report-artifact-url requires --analyze-report")
    if args.analyze_report and (repo is not None or args.review_pr or args.collect_only):
        parser.error("--analyze-report cannot be combined with repo, --review-pr, or --collect-only")
    if args.review_pr or args.analyze_report:
        if args.analyze_report:
            if args.resume or args.approve_pr:
                parser.error("--analyze-report cannot be combined with --resume or --approve")
            try:
                precollected_report = json.loads(args.analyze_report.expanduser().read_text(encoding="utf-8"))
                if not isinstance(precollected_report, dict) or precollected_report.get("mode") != "dependabot_pr_review":
                    raise ValueError("The report is not a Dependabot PR review artifact")
                validate_evidence_report(precollected_report)
                if args.report_artifact_url:
                    artifact = urlparse(args.report_artifact_url)
                    repo_parts = str(precollected_report.get("repository_full_name", "")).split("/")
                    path_parts = artifact.path.strip("/").split("/")
                    valid_path = (
                        len(repo_parts) == 2 and len(path_parts) == 7
                        and [part.casefold() for part in path_parts[:2]] == [part.casefold() for part in repo_parts]
                        and path_parts[2:4] == ["actions", "runs"]
                        and path_parts[4].isdigit() and path_parts[5] == "artifacts"
                        and path_parts[6].isdigit()
                    )
                    if artifact.scheme != "https" or artifact.netloc != "github.com" or not valid_path:
                        raise ValueError("Artifact URL must point to this report's GitHub Actions run")
                    precollected_report["report_artifact_url"] = args.report_artifact_url
                if args.post_comment:
                    report_pr = precollected_report.get("pull_request", {})
                    if not args.expected_pr or not args.expected_repository or not args.expected_head_sha:
                        raise ValueError("Commenting on a collected report requires expected PR number, repository, and head SHA")
                    if (report_pr.get("number") != args.expected_pr
                            or precollected_report.get("repository_full_name", "").casefold() != args.expected_repository.casefold()
                            or report_pr.get("author", "").casefold() != "dependabot[bot]"
                            or report_pr.get("head_sha") != args.expected_head_sha):
                        raise ValueError("Evidence report does not match the expected Dependabot PR identity")
            except (OSError, json.JSONDecodeError, ValueError) as exc:
                parser.error(f"Could not read Dependabot evidence report: {exc}")
        else:
            precollected_report = None
        if repo is None:
            if not args.analyze_report:
                parser.error("repo is required with --review-pr")
        if args.resume or args.approve_pr:
            parser.error("Dependabot review cannot be combined with --resume or --approve")
        if args.post_comment and args.review_pr:
            parser.error("For safer credential separation, collect evidence first, then use --analyze-report --post-comment")
        if repo is not None and (not repo.is_dir() or not (repo / ".git").exists()):
            parser.error(f"Not a Git working tree: {repo}")

        def analyze_usage(head_repository: Path, dependencies: list[dict[str, Any]]) -> list[dict[str, Any]]:
            """Analyze every changed package, attaching advisory context only when present."""
            if not dependencies:
                return []
            from vulnerability_agent.dependencies import create_dependencies
            from vulnerability_agent.nodes.usage_analysis import node_report_source_usage

            agent_dependencies = create_dependencies(audit_database_path=state_database, run_id=f"dependabot-review-{uuid.uuid4().hex}")
            analyses: list[dict[str, Any]] = []
            for dependency in dependencies:
                package_name = str(dependency.get("package", ""))
                ecosystem = str(dependency.get("ecosystem", "PyPI"))
                target = {
                    "id": "dependency-change",
                    "package": {
                        "name": package_name,
                        "version": str(dependency.get("head_version", "")),
                        "ecosystem": ecosystem,
                    },
                    "advisories": dependency.get("advisories", []),
                    "relationship": dependency.get("relationship", "unknown"),
                    "dependency_paths": dependency.get("dependency_paths", []),
                }
                result = node_report_source_usage({
                    "repo_path": str(head_repository), "main_repo_path": str(head_repository),
                    "current_vuln": target,
                }, agent_dependencies)
                analysis = result.get("current_usage_analysis", {})
                analysis["ecosystem"] = ecosystem
                analysis.setdefault("analysis_status", (
                    "completed_with_matches" if analysis.get("locations")
                    else "completed_without_matches"
                ))
                if analysis["analysis_status"] == "failed":
                    analysis["error"] = str(analysis.get("retrieval", {}).get("warning", "Source analysis failed."))
                analyses.append(analysis)
            return analyses

        started_at = datetime.now(timezone.utc)
        automatic_report_path = DEFAULT_REPORT_DIRECTORY / (
            f"review-{started_at.strftime('%Y%m%dT%H%M%S.%fZ')}-{uuid.uuid4().hex[:8]}.json"
        )
        requested_report_path = args.report.expanduser().resolve() if args.report else None
        try:
            review_graph = build_dependabot_review_graph(usage_analyzer=analyze_usage)
            initial_review_state: dict[str, Any] = {
                "post_comment": args.post_comment,
                "collect_only": args.collect_only,
            }
            if precollected_report is not None:
                initial_review_state["report"] = precollected_report
            else:
                initial_review_state.update({"repository": str(repo), "pull_request": args.review_pr})
            review_state = review_graph.invoke(initial_review_state)
            report = review_state.get("report", {})
        except Exception as exc:
            report = {
                "schema_version": 3, "mode": "dependabot_pr_review", "status": "review_failed",
                "repository": str(repo), "pull_request_reference": args.review_pr,
                "error": f"{type(exc).__name__}: {exc}",
                "note": "Review-only workflow; no push, PR creation, merge, or comment was attempted.",
            }
            validation_status = "failed" if isinstance(exc, EvidenceReportValidationError) else "not_run"
            report["validation"] = report_validation_observability(
                report, status=validation_status,
                errors=[str(exc)] if validation_status == "failed" else [],
            )
        report["observability"] = {
            "langsmith_tracing": "enabled" if tracing_enabled else "disabled",
            "langsmith_project": os.getenv("LANGSMITH_PROJECT", "default") if tracing_enabled else "",
        }
        rendered = json.dumps(report, indent=2, ensure_ascii=False)
        if not _save_report_files(rendered, automatic_report_path, requested_report_path, "Review report"):
            print(rendered)
            return 1
        print(rendered)
        return 0 if report.get("status") == "review_complete" else 1
    dashboard_requested = repo is None and not (args.approve_pr or args.resume)
    dashboard_summary_printed = False
    if dashboard_requested:
        if not sys.stdin.isatty():
            parser.error("repo is required in non-interactive mode; run without arguments in a terminal to open the CLI dashboard")
        action = _interactive_dashboard(state_database)
        if action is None:
            return 0
        repo = action.get("repository")
        if action["action"] == "approve":
            args.resume = action["thread_id"]
            args.approve_pr = True
            dashboard_summary_printed = bool(action.get("summary_printed"))
        elif action["action"] == "resume":
            args.resume = action["thread_id"]
    if repo is not None:
        if not repo.is_dir():
            parser.error(f"Repository directory does not exist: {repo}")
        if not (repo / ".git").exists():
            parser.error(f"Not a Git working tree: {repo}")
    started_at = datetime.now(timezone.utc)
    thread_id = args.resume or args.thread_id or ""
    try:
        with SQLiteAgentPersistence(state_database) as persistence:
            workflow = build_graph(
                checkpointer=persistence.checkpointer,
                audit_database_path=state_database,
                run_id=thread_id or "approval-discovery",
                interrupt_before_pr=True,
            )
            if args.approve_pr and not args.resume:
                pending = _pending_approval_threads(workflow, persistence, repo)
                if not pending:
                    parser.error("No runs are waiting for approval in the configured state database")
                selected = _choose_pending_approval(pending)
                thread_id = selected["thread_id"]
                config = selected["config"]
                # Rebuild dependencies with the real run ID before the resumed
                # graph makes audited MCP calls for the PR workflow.
                workflow = build_graph(
                    checkpointer=persistence.checkpointer,
                    audit_database_path=state_database,
                    run_id=thread_id,
                    interrupt_before_pr=True,
                )
                workflow.update_state(config, {"approval_granted": True})
                state = _workflow_invoke_with_progress(workflow, None, config)
                snapshot = workflow.get_state(config)
                repo = selected["repository"]
            elif args.resume:
                # A saved run stores its target repository, so resuming it no
                # longer requires copying the path or the thread ID's repo.
                config = {"configurable": {"thread_id": thread_id}, "recursion_limit": 100_000}
                snapshot = workflow.get_state(config)
                awaiting_approval = tuple(snapshot.next) == ("await_approval",)
                if args.approve_pr and not awaiting_approval:
                    parser.error("--approve-pr can only be used when the thread is paused at the approval checkpoint")
                if awaiting_approval and not dashboard_summary_printed:
                    _print_approval_summary(snapshot.values, repo, thread_id)
                if awaiting_approval and not args.approve_pr:
                    state = {**snapshot.values, "run_status": "awaiting_human_review"}
                else:
                    if awaiting_approval:
                        # Approval is persisted into the same graph thread;
                        # resuming without this explicit state update cannot
                        # reach the PR node.
                        workflow.update_state(config, {"approval_granted": True})
                    state = _workflow_invoke_with_progress(workflow, None, config)
                    snapshot = workflow.get_state(config)
                if repo is None:
                    saved_repo = snapshot.values.get("main_repo_path") or snapshot.values.get("repo_path")
                    repo = Path(saved_repo).expanduser().resolve() if saved_repo else None
            else:
                if repo is None:
                    parser.error("A repository path is required to start a new scan")
                # A batch has multiple graph-node trips per finding; raise
                # LangGraph's default per-invocation limit for full scans.
                config = {
                    "configurable": {"thread_id": thread_id or uuid.uuid4().hex},
                    "recursion_limit": 100_000,
                }
                thread_id = config["configurable"]["thread_id"]
                state = _workflow_invoke_with_progress(
                    workflow,
                    {"repo_path": str(repo), "main_repo_path": str(repo), "attempt_count": 0},
                    config,
                )
                snapshot = workflow.get_state(config)
            if snapshot.next:
                state = {**state, "run_status": "awaiting_human_review"}
    except Exception as exc:
        # Most node failures are converted to state by the graph. This final
        # boundary still gives callers a report if orchestration itself fails.
        state = {
            "repo_path": str(repo or ""), "run_status": "failed", "error_stage": "workflow",
            "error_code": "workflow_failed", "error": f"{type(exc).__name__}: {exc}",
        }
    finished_at = datetime.now(timezone.utc)
    report = build_run_report(state, started_at, finished_at)
    report["observability"] = {
        "langsmith_tracing": "enabled" if tracing_enabled else "disabled",
        "langsmith_project": os.getenv("LANGSMITH_PROJECT", "default") if tracing_enabled else "",
        "thread_id": thread_id or args.resume or "",
        "state_database": str(state_database),
    }
    rendered = json.dumps(report, indent=2, ensure_ascii=False)
    automatic_report_path = DEFAULT_REPORT_DIRECTORY / (
        f"run-{started_at.strftime('%Y%m%dT%H%M%S.%fZ')}-{thread_id or uuid.uuid4().hex[:8]}.json"
    )
    requested_report_path = args.report.expanduser().resolve() if args.report else None
    report_saved = _save_report_files(rendered, automatic_report_path, requested_report_path, "Run report")
    print(rendered)
    if not report_saved:
        return 1
    if report["status"] in {"pull_request_created", "no_findings", "awaiting_human_review", "batch_completed"}:
        return 0
    if report["status"] == "scan_incomplete":
        return 2
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
