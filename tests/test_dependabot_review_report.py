from __future__ import annotations

import json
import os
import httpx
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

import main
from vulnerability_agent import dependabot_review as review
from vulnerability_agent.dependabot import git_ops, inventory, release_notes
from vulnerability_agent.dependabot import scan as scan_module
from vulnerability_agent.dependabot import tests as tests_module
from vulnerability_agent.report_validation import (
    EvidenceReportValidationError, evidence_report_json_schema, validate_evidence_report,
)
from vulnerability_agent.review_graph import (
    COMMENT_MARKER,
    build_dependabot_review_graph,
    post_idempotent_review_comment,
    render_pr_comment,
    render_review_prompt,
)


def test_scan_preserves_osv_evidence_and_deduplicates_per_package_advisory(tmp_path, monkeypatch):
    (tmp_path / "poetry.lock").write_text('''[[package]]
name = "alpha"
version = "1.0"

[[package]]
name = "beta"
version = "2.0"
''')
    advisory = {
        "id": "GHSA-shared", "summary": "Security issue", "severity": [{"type": "CVSS_V3", "score": "8.1"}],
        "affected": [{"package": {"name": "alpha", "ecosystem": "PyPI"}, "ranges": [{
            "type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1.2"}],
        }]}],
        "references": [{"type": "WEB", "url": "https://example.test/advisory"}],
    }
    findings = [
        {**advisory, "package": {"name": "alpha", "version": "1.0", "ecosystem": "PyPI"}},
        {**advisory, "package": {"name": "alpha", "version": "1.0", "ecosystem": "PyPI"}},
        {"id": "GHSA-shared", "summary": "Shared advisory", "package": {"name": "beta", "version": "2.0", "ecosystem": "PyPI"}},
        {"id": "GHSA-second", "summary": "Another advisory", "package": {"name": "alpha", "version": "1.0", "ecosystem": "PyPI"}},
    ]
    monkeypatch.setattr(scan_module, "run_async", lambda awaitable: (awaitable.close(), findings)[1])
    monkeypatch.setattr(scan_module, "dependency_index", lambda _root: (
        {("pypi", "alpha")}, {("pypi", "alpha"): {("pypi", "beta")}},
    ))

    result = review._scan(tmp_path, None)
    records = result["findings"]
    assert len(records) == 3  # alpha/shared duplicate collapsed; beta/shared retained
    alpha_shared = next(item for item in records if item["package"] == "alpha" and item["id"] == "GHSA-shared")
    beta_shared = next(item for item in records if item["package"] == "beta")
    assert alpha_shared["version_assessment"]["status"] == "affected"
    assert beta_shared["version_assessment"]["status"] == "unknown"
    assert alpha_shared["finding_identity"] != beta_shared["finding_identity"]
    assert alpha_shared["severity"] == [{"type": "CVSS_V3", "score": "8.1"}]
    assert alpha_shared["affected_ranges"][0]["events"][-1]["fixed"] == "1.2"
    assert alpha_shared["fixed_versions"] == ["1.2"]
    assert alpha_shared["manifest_files"] == ["poetry.lock"]
    assert alpha_shared["relationship"] == "direct"
    assert alpha_shared["dependency_paths"] == [["alpha"]]
    assert beta_shared["severity_status"] == "unavailable"
    assert beta_shared["fixed_version_status"] == "unavailable"
    assert beta_shared["dependency_path_status"] == "available"
    assert beta_shared["dependency_paths"] == [["alpha", "beta"]]


def test_compact_schema_serializes_complete_package_advisory_provenance():
    finding = {
        "id": "GHSA-1", "finding_identity": "pypi:demo:ghsa-1", "package": "demo",
        "ecosystem": "PyPI", "version": "1.0", "installed_version": "1.0",
        "severity": [], "severity_status": "unavailable", "affected_ranges": [],
        "affected_versions": [], "affected_range_status": "unavailable", "fixed_versions": [],
        "fixed_version_status": "unavailable", "manifest_files": ["poetry.lock"],
        "relationship": "unknown", "dependency_paths": [], "dependency_path_status": "unavailable",
        "references": [], "summary": "A finding",
    }
    delta = {key: [] for key in ("resolved", "introduced", "remaining", "unaffected", "not_assessed")}
    delta["remaining"] = [finding]
    report = review._compact_review_report({
        "base": {"security_scan": {"scan_status": "complete", "findings": [finding]}},
        "head": {"security_scan": {"scan_status": "complete", "findings": [finding]}},
        "security_delta": delta, "dependency_changes": [],
    })
    loaded = json.loads(json.dumps(report))
    assert loaded["schema_version"] == 6
    advisory = loaded["security_delta"]["remaining"][0]["advisories"][0]
    assert advisory["finding_identity"] == "pypi:demo:ghsa-1"
    assert advisory["fixed_version_status"] == "unavailable"
    assert advisory["manifest_files"] == ["poetry.lock"]
    assert loaded["osv_scans"]["pr"]["unique_advisory_count"] == 1


def test_report_compaction_groups_advisories_and_limits_rag_locations():
    findings = [
        {"id": f"GHSA-{number}", "package": "demo", "version": "1.0", "ecosystem": "PyPI",
         "summary": "short title", "details": "very long advisory text" * 1000}
        for number in range(6)
    ]
    report = review._compact_review_report({
        "mode": "dependabot_pr_review", "status": "review_complete",
        "base": {"tests": {"passed": True, "output": "6 passed in 1s"},
                 "security_scan": {"manifests": ["poetry.lock"], "packages_checked": 1,
                                   "unresolved_packages": [], "findings": findings}},
        "head": {"tests": {"passed": True, "output": "6 passed in 1s"},
                 "security_scan": {"manifests": ["poetry.lock"], "packages_checked": 1,
                                   "unresolved_packages": [], "findings": findings}},
        "security_delta": {"resolved": [], "introduced": [], "remaining": findings},
        "dependency_changes": [], "source_usage": [{
            "package": "demo", "advisory_ids": [item["id"] for item in findings],
            "locations": [
                {"path": f"src/file{number}.py", "line_start": 1, "line_end": 3,
                 "excerpt": "x" * 1000, "match_type": "hybrid RAG"}
                for number in range(8)
            ],
            "retrieval": {"backend": "qdrant_local_hybrid"},
        }],
    })
    assert report["schema_version"] == 6
    assert report["summary"]["osv"]["remaining"] == 6
    assert len(report["security_delta"]["remaining"]) == 1
    assert report["security_delta"]["remaining"][0]["advisory_count"] == 6
    assert len(report["source_usage"][0]["locations"]) == 3
    assert len(report["source_usage"][0]["locations"][0]["excerpt"]) == 240
    assert report["source_usage"][0]["locations"][0]["evidence_classification"] == "semantic_context"
    assert report["security_delta"]["count_semantics"]["unit"] == "package_advisory_records"
    assert "details" not in report["security_delta"]["remaining"][0]["advisories"][0]


def test_report_validator_rejects_missing_dependency_summary_record():
    finding = {"id": "GHSA-ONE", "package": "demo", "ecosystem": "PyPI", "version": "2.0",
               "summary": "Finding", "aliases": []}
    changed = {"package": "demo", "ecosystem": "pypi", "base_version": "1.0", "head_version": "2.0",
               "relationship": "direct", "dependency_paths": [["demo"]]}
    report = review._compact_review_report({
        "mode": "dependabot_pr_review", "status": "review_complete", "repository_full_name": "acme/demo",
        "pull_request": {"number": 1}, "files_changed": [],
        "base": {"tests": {"passed": True, "returncode": 0, "output": "1 passed"},
                 "security_scan": {"scan_status": "complete", "findings": []}},
        "head": {"tests": {"passed": True, "returncode": 0, "output": "1 passed"},
                 "security_scan": {"scan_status": "complete", "findings": [finding]}},
        "test_comparison": review._compare_tests(
            {"passed": True, "returncode": 0}, {"passed": True, "returncode": 0}),
        "dependency_changes": [changed],
        "security_delta": {"resolved": [], "introduced": [finding], "remaining": [], "unaffected": [], "not_assessed": []},
    })
    report["summary"]["dependency_updates"] = []
    with pytest.raises(EvidenceReportValidationError, match="summary.dependency_updates"):
        validate_evidence_report(report)


def test_pr_comment_uses_detailed_dependency_data_and_preserves_evidence_label():
    body = render_pr_comment({
        "dependency_changes": [{"package": "demo", "ecosystem": "pypi", "base_version": "1.0",
                                "head_version": "2.0", "relationship": "transitive"}],
        "summary": {"dependency_updates": [{"package": "missing-summary-entry", "from": "?", "to": "?"}],
                    "tests": {"base": {"passed": True, "summary": "passed"},
                              "pr": {"passed": True, "summary": "passed"}},
                    "osv": {"resolved": 0, "introduced": 0, "remaining": 0}},
        "source_usage": [{"package": "demo", "ecosystem": "pypi", "locations": [{
            "path": "src/demo.py", "line_start": 3, "line_end": 3, "area": "application",
            "evidence_classification": "direct_import",
        }]}],
    }, "")
    assert "| `demo` | `1.0` → `2.0` | transitive |" in body
    assert "missing-summary-entry" not in body
    assert "direct import" in body
    assert "package-advisory records" in body
    no_changes = render_pr_comment({
        "dependency_changes": [],
        "summary": {"dependency_updates": [{"package": "stale-summary-entry", "from": "1", "to": "2"}]},
    }, "")
    assert "No dependency change was identified." in no_changes
    assert "stale-summary-entry" not in no_changes


def test_report_v6_json_schema_and_per_dependency_source_statuses():
    schema = evidence_report_json_schema()
    assert schema["properties"]["schema_version"]["const"] == 6
    changes = [
        {"package": name, "ecosystem": "pypi", "base_version": "1.0", "head_version": "2.0",
         "relationship": relation, "dependency_paths": [[name]]}
        for name, relation in (("alpha", "direct"), ("beta", "transitive"))
    ]
    report = review._compact_review_report({
        "mode": "dependabot_pr_review", "status": "review_complete", "repository_full_name": "acme/demo",
        "pull_request": {"number": 2}, "files_changed": [], "dependency_changes": changes,
        "source_usage_status": "completed_with_matches",
        "source_usage": [{"package": "alpha", "ecosystem": "pypi", "relationship": "direct",
                          "advisory_ids": [], "locations": [{
                              "path": "src/alpha.py", "line_start": 1, "line_end": 1,
                              "evidence_classification": "direct_import",
                          }]}],
        "base": {"tests": {"passed": True, "returncode": 0},
                 "security_scan": {"scan_status": "complete", "findings": [], "unresolved_packages": []}},
        "head": {"tests": {"passed": True, "returncode": 0},
                 "security_scan": {"scan_status": "complete", "findings": [], "unresolved_packages": []}},
        "security_delta": {"resolved": [], "introduced": [], "remaining": [], "unaffected": [], "not_assessed": []},
    })
    statuses = {item["package"]: item["source_analysis_status"] for item in report["summary"]["dependency_analyses"]}
    assert statuses == {"alpha": "completed_with_matches", "beta": "completed_without_matches"}
    assert validate_evidence_report(report) is report

    legacy = json.loads(json.dumps(report))
    legacy["schema_version"] = 4
    legacy["validation"]["schema_version"] = 4
    for item in legacy["source_usage"]:
        if "source_usage_classifications" in item:
            item["application_usage_classifications"] = item.pop("source_usage_classifications")
    legacy["summary"]["osv"]["unaffected"] = legacy["summary"]["osv"].pop("unchanged_dependencies")
    legacy_delta = legacy["security_delta"]
    legacy_delta["unaffected"] = legacy_delta.pop("unchanged_dependencies")
    legacy_delta["counts"]["unaffected"] = legacy_delta["counts"].pop("unchanged_dependencies")
    legacy_delta["version_assessment_counts"]["unaffected"] = legacy_delta["version_assessment_counts"].pop("unchanged_dependencies")
    for key in ("package_groups", "unique_advisory_ids", "underlying_vulnerabilities"):
        legacy_delta["count_semantics"][key]["unaffected"] = legacy_delta["count_semantics"][key].pop("unchanged_dependencies")
    assert validate_evidence_report(legacy) is legacy

    legacy_v5 = json.loads(json.dumps(report))
    legacy_v5["schema_version"] = 5
    legacy_v5["validation"]["schema_version"] = 5
    for item in legacy_v5["source_usage"]:
        if "source_usage_classifications" in item:
            item["application_usage_classifications"] = item.pop("source_usage_classifications")
    assert validate_evidence_report(legacy_v5) is legacy_v5


def test_pr_comment_is_compact_and_links_full_report_artifact():
    body = render_pr_comment({
        "repository_full_name": "acme/demo",
        "report_artifact_url": "https://github.com/acme/demo/actions/runs/10/artifacts/20",
        "summary": {
            "dependency_updates": [{"package": "demo", "from": "1.0", "to": "2.0"}],
            "tests": {"base": {"passed": True, "summary": "6 passed"},
                      "pr": {"passed": True, "summary": "6 passed"}},
            "osv": {"resolved": 1, "introduced": 0, "remaining": 4},
            "recommendation": "Review the dependency change.",
        },
        "source_usage": [{"package": "demo", "locations": [
            {"path": "src/app.py", "line_start": 5, "line_end": 8, "area": "application"}
        ]}],
    }, "## AI recommendation\nLooks reasonable.")
    assert "0 introduced · 1 resolved · 4 remain in changed dependencies" in body
    assert "src/app.py:5-8" in body
    assert "[Open the full JSON report and run artifacts]" in body
    assert "<details>" in body
    assert len(body) < 2_500


def test_review_rejects_non_dependabot_pr_before_fetching_refs(tmp_path, monkeypatch):
    repository = tmp_path / "repo"
    repository.mkdir()
    (repository / ".git").mkdir()
    github = Mock()
    response = Mock()
    response.json.return_value = {
        "state": "open", "user": {"login": "someone-else"},
        "base": {"ref": "main", "sha": "base"},
        "head": {"ref": "topic", "sha": "head"},
    }
    github.get.return_value = response
    monkeypatch.setattr(git_ops, "github_origin", lambda _root: "acme/demo")
    git = Mock()
    monkeypatch.setattr(git_ops, "git", git)

    with pytest.raises(ValueError, match="not opened by dependabot"):
        review.review_dependabot_pull_request(repository, "17", github_client=github)
    git.assert_not_called()


def test_review_uses_current_base_when_pr_base_is_its_ancestor(tmp_path, monkeypatch):
    repository = tmp_path / "repo"
    repository.mkdir()
    (repository / ".git").mkdir()

    def metadata(base_sha: str, head_sha: str) -> Mock:
        response = Mock()
        response.json.return_value = {
            "state": "open", "user": {"login": "dependabot[bot]"},
            "html_url": "https://github.com/acme/demo/pull/17", "title": "Bump demo",
            "base": {"ref": "main", "sha": base_sha},
            "head": {"ref": "dependabot/pip/demo-2", "sha": head_sha},
            "changed_files": 0,
        }
        return response

    files_response = Mock()
    files_response.json.return_value = []
    github = Mock()
    github.get.side_effect = [metadata("api-base", "head-sha"), files_response]
    worktree_adds: list[tuple[str, ...]] = []
    merges: list[tuple[str, ...]] = []

    def fake_git(root: Path, *args: str) -> str:
        if args[:3] == ("remote", "get-url", "origin"):
            return "https://github.com/acme/demo.git"
        if args[0] == "rev-parse":
            return {
                "refs/agent-review/17/base": "current-base",
                "refs/agent-review/17/head": "head-sha",
            }[args[1]]
        if args[0] == "merge-base":
            if args[1:] == ("api-base", "current-base"):
                return "api-base"
            if args[1:] == ("current-base", "head-sha"):
                return "current-base"
            raise AssertionError(f"Unexpected merge-base arguments: {args[1:]}")
        if args[:2] == ("worktree", "add"):
            worktree_adds.append(args)
            Path(args[-2]).mkdir(parents=True, exist_ok=True)
        if args[0] == "-C" and args[2] == "merge":
            merges.append(args)
        return ""

    monkeypatch.setattr(git_ops, "git", fake_git)
    monkeypatch.setattr(scan_module, "scan_snapshot", lambda *_: {
        "manifests": ["requirements.txt"], "packages_checked": 0,
        "unresolved_packages": [], "findings": [], "resolved_packages": [],
    })
    monkeypatch.setattr(tests_module, "run_snapshot_tests", lambda *_: {"passed": True, "returncode": 0, "output": "ok"})
    monkeypatch.setattr(release_notes, "release_context", lambda _changes: [])

    report = review.review_dependabot_pull_request(repository, "17", github_client=github)

    assert report["status"] == "review_complete"
    assert report["pull_request"]["base_sha"] == "current-base"
    assert report["pull_request"]["reported_base_sha"] == "api-base"
    assert report["pull_request"]["base_advanced"] is True
    assert "local merge" in report["note"]
    assert [args[-1] for args in worktree_adds] == ["current-base", "current-base"]
    assert merges == [("-C", str(Path(worktree_adds[1][-2])), "merge", "--no-edit", "--no-commit", "--no-ff", "head-sha")]
    assert github.get.call_count == 2  # metadata and changed-files list


def test_unrelated_pr_history_has_actionable_recovery_guidance(tmp_path, monkeypatch):
    def fail_merge_base(*_args):
        raise RuntimeError("git merge-base failed")

    monkeypatch.setattr(git_ops, "git", fail_merge_base)
    with pytest.raises(ValueError, match="no common Git ancestor.*rebase.*recreate"):
        review._require_common_history(tmp_path, "current-main", "dependabot-head")


def test_review_reports_shas_when_pr_refs_never_match(tmp_path, monkeypatch):
    repository = tmp_path / "repo"
    repository.mkdir()
    (repository / ".git").mkdir()
    response = Mock()
    response.json.return_value = {
        "state": "open", "user": {"login": "dependabot[bot]"},
        "base": {"ref": "main", "sha": "api-base"},
        "head": {"ref": "dependabot/pip/demo-2", "sha": "api-head"},
    }
    github = Mock()
    github.get.return_value = response
    monkeypatch.setattr(git_ops, "github_origin", lambda _root: "acme/demo")
    monkeypatch.setattr(git_ops, "git", lambda _root, *args: {
        ("rev-parse", "refs/agent-review/17/base"): "fetched-base",
        ("rev-parse", "refs/agent-review/17/head"): "fetched-head",
    }.get(args[:2], ""))

    with pytest.raises(RuntimeError, match="api-base.*fetched-base.*api-head.*fetched-head"):
        review.review_dependabot_pull_request(repository, "17", github_client=github)
    assert github.get.call_count == 3


def test_cli_dependabot_review_saves_json_report(tmp_path, monkeypatch, capsys):
    repository = tmp_path / "repo"
    repository.mkdir()
    (repository / ".git").mkdir()
    report_path = tmp_path / "review.json"
    saved_report_directory = tmp_path / "saved report"
    class FakeReviewGraph:
        def invoke(self, state):
            assert state["repository"] == str(repository)
            return {"report": {"schema_version": 1, "mode": "dependabot_pr_review", "status": "review_complete"}}

    monkeypatch.setattr(main, "build_dependabot_review_graph", lambda **_kwargs: FakeReviewGraph())
    monkeypatch.setattr(main, "DEFAULT_REPORT_DIRECTORY", saved_report_directory)

    result = main.main([str(repository), "--review-pr", "17", "--report", str(report_path)])

    assert result == 0
    assert json.loads(report_path.read_text())["mode"] == "dependabot_pr_review"
    archived_reports = list(saved_report_directory.glob("review-*.json"))
    assert len(archived_reports) == 1
    assert json.loads(archived_reports[0].read_text())["mode"] == "dependabot_pr_review"
    assert json.loads(capsys.readouterr().out)["status"] == "review_complete"


def test_cli_accepts_artifact_url_for_matching_repository_report(tmp_path, monkeypatch, capsys):
    evidence_path = tmp_path / "evidence.json"
    artifact_url = "https://github.com/acme/demo/actions/runs/10/artifacts/20"
    evidence_path.write_text(json.dumps({
        "schema_version": 2,
        "mode": "dependabot_pr_review",
        "status": "review_complete",
        "repository_full_name": "acme/demo",
        "pull_request": {"number": 17, "author": "dependabot[bot]", "head_sha": "abc123"},
    }))
    archived = tmp_path / "saved report"

    class FakeReviewGraph:
        def invoke(self, state):
            assert state["report"]["report_artifact_url"] == artifact_url
            return {"report": {**state["report"], "ai_review": "Short review", "ai_review_status": "complete"}}

    monkeypatch.setattr(main, "build_dependabot_review_graph", lambda **_kwargs: FakeReviewGraph())
    monkeypatch.setattr(main, "DEFAULT_REPORT_DIRECTORY", archived)

    code = main.main([
        "--analyze-report", str(evidence_path),
        "--report-artifact-url", artifact_url,
    ])

    files = list(archived.glob("review-*.json"))
    assert code == 0
    assert len(files) == 1
    assert json.loads(files[0].read_text())["report_artifact_url"] == artifact_url
    assert json.loads(capsys.readouterr().out)["status"] == "review_complete"
