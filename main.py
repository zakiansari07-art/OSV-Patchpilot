"""CLI entry point for Dependabot pull request reviews."""
from __future__ import annotations

import argparse
import json
import os
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Sequence
from urllib.parse import urlparse

from dotenv import load_dotenv

from vulnerability_agent.review_graph import build_dependabot_review_graph

DEFAULT_REPORT_DIRECTORY = Path(__file__).resolve().parent / "saved report"


def _save_report_files(
    rendered: str,
    automatic_path: Path,
    requested_path: Path | None,
    report_label: str,
) -> bool:
    """Archive a review report and optionally write an additional copy."""
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


def _group_source_analysis_inputs(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Group OSV records and retain source-only dependency queries."""
    from osv_service import group_advisories_by_package

    osv_findings = []
    source_only_groups = []
    for item in findings:
        package = item.get("package", {})
        if isinstance(package, dict):
            package_data = {
                "name": str(package.get("name", "")),
                "version": str(package.get("version", item.get("version", ""))),
                "ecosystem": str(package.get("ecosystem", item.get("ecosystem", "PyPI"))),
            }
        else:
            package_data = {
                "name": str(package), "version": str(item.get("version", "")),
                "ecosystem": str(item.get("ecosystem", "PyPI")),
            }
        if str(item.get("id", "")).startswith("source-analysis:"):
            source_only_groups.append({
                "id": str(item["id"]), "package": package_data,
                "advisories": [], "advisory_ids": [],
                "relationship": item.get("relationship", "unknown"),
                "dependency_paths": item.get("dependency_paths", []),
            })
        else:
            osv_findings.append({**item, "package": package_data})
    return group_advisories_by_package(osv_findings) + source_only_groups


def _validate_artifact_url(url: str, report: dict[str, Any]) -> None:
    artifact = urlparse(url)
    repo_parts = str(report.get("repository_full_name", "")).split("/")
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


def _validate_comment_identity(args: argparse.Namespace, report: dict[str, Any]) -> None:
    pull_request = report.get("pull_request", {})
    if not args.expected_pr or not args.expected_repository or not args.expected_head_sha:
        raise ValueError("Commenting on a collected report requires expected PR number, repository, and head SHA")
    if (
        pull_request.get("number") != args.expected_pr
        or report.get("repository_full_name", "").casefold() != args.expected_repository.casefold()
        or pull_request.get("author", "").casefold() != "dependabot[bot]"
        or pull_request.get("head_sha") != args.expected_head_sha
    ):
        raise ValueError("Evidence report does not match the expected Dependabot PR identity")


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Collect or analyze evidence for a Dependabot pull request review.")
    parser.add_argument("repo", nargs="?", type=Path,
                        help="Path to a local clone (required with --review-pr)")
    parser.add_argument("--report", type=Path,
                        help="Also save a copy of the JSON report at this path; every review is archived in ./saved report/")
    parser.add_argument("--state-db", type=Path,
                        help="SQLite database for MCP audit records")
    parser.add_argument("--review-pr", metavar="URL_OR_NUMBER",
                        help="Collect evidence and review an open Dependabot pull request")
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

    tracing_enabled = os.getenv("LANGSMITH_TRACING", "false").strip().lower() in {"1", "true", "yes", "on"}
    if tracing_enabled and not os.getenv("LANGSMITH_API_KEY"):
        parser.error("LANGSMITH_TRACING is enabled but LANGSMITH_API_KEY is missing")

    repo = args.repo.expanduser().resolve() if args.repo else None
    if not args.review_pr and not args.analyze_report:
        parser.error("Specify --review-pr or --analyze-report")
    if args.post_comment and not (args.review_pr or args.analyze_report):
        parser.error("--post-comment requires --review-pr or --analyze-report")
    if args.collect_only and not args.review_pr:
        parser.error("--collect-only requires --review-pr")
    if args.report_artifact_url and not args.analyze_report:
        parser.error("--report-artifact-url requires --analyze-report")
    if args.analyze_report and (repo is not None or args.review_pr or args.collect_only):
        parser.error("--analyze-report cannot be combined with repo, --review-pr, or --collect-only")
    if args.post_comment and args.review_pr:
        parser.error("For safer credential separation, collect evidence first, then use --analyze-report --post-comment")
    if args.review_pr and repo is None:
        parser.error("repo is required with --review-pr")
    if repo is not None and (not repo.is_dir() or not (repo / ".git").exists()):
        parser.error(f"Not a Git working tree: {repo}")

    if args.analyze_report:
        try:
            precollected_report = json.loads(args.analyze_report.expanduser().read_text(encoding="utf-8"))
            if not isinstance(precollected_report, dict) or precollected_report.get("mode") != "dependabot_pr_review":
                raise ValueError("The report is not a Dependabot PR review artifact")
            if args.report_artifact_url:
                _validate_artifact_url(args.report_artifact_url, precollected_report)
                precollected_report["report_artifact_url"] = args.report_artifact_url
            if args.post_comment:
                _validate_comment_identity(args, precollected_report)
        except (OSError, json.JSONDecodeError, ValueError) as exc:
            parser.error(f"Could not read Dependabot evidence report: {exc}")
    else:
        precollected_report = None

    def analyze_usage(head_repository: Path, findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Reuse report-only hybrid RAG on the exact PR snapshot."""
        if not findings:
            return []
        from vulnerability_agent.dependencies import create_dependencies
        from vulnerability_agent.nodes.usage_analysis import node_report_source_usage

        dependencies = create_dependencies(
            audit_database_path=args.state_db,
            run_id=f"dependabot-review-{uuid.uuid4().hex}",
        )
        analyses: list[dict[str, Any]] = []
        for group in _group_source_analysis_inputs(findings):
            result = node_report_source_usage({
                "repo_path": str(head_repository), "main_repo_path": str(head_repository),
                "current_vuln": group,
            }, dependencies)
            analyses.extend(result.get("usage_analysis", []))
        return analyses

    started_at = datetime.now(timezone.utc)
    automatic_report_path = DEFAULT_REPORT_DIRECTORY / (
        f"review-{started_at.strftime('%Y%m%dT%H%M%S.%fZ')}-{uuid.uuid4().hex[:8]}.json"
    )
    requested_report_path = args.report.expanduser().resolve() if args.report else None
    try:
        review_graph = build_dependabot_review_graph(usage_analyzer=analyze_usage)
        initial_state: dict[str, Any] = {
            "post_comment": args.post_comment,
            "collect_only": args.collect_only,
        }
        if precollected_report is not None:
            initial_state["report"] = precollected_report
        else:
            initial_state.update({"repository": str(repo), "pull_request": args.review_pr})
        review_state = review_graph.invoke(initial_state)
        report = review_state.get("report", {})
    except Exception as exc:
        report = {
            "schema_version": 3, "mode": "dependabot_pr_review", "status": "review_failed",
            "repository": str(repo or ""), "pull_request_reference": args.review_pr,
            "error": f"{type(exc).__name__}: {exc}",
            "note": "Review-only workflow; no push, PR creation, merge, or comment was attempted.",
        }

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


if __name__ == "__main__":
    raise SystemExit(main())
