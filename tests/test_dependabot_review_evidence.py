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


def test_review_runs_base_then_head_and_reports_osv_delta(tmp_path, monkeypatch):
    repository = tmp_path / "repo"
    repository.mkdir()
    (repository / ".git").mkdir()
    response = Mock()
    response.json.return_value = {
        "state": "open", "user": {"login": "dependabot[bot]"},
        "html_url": "https://github.com/acme/demo/pull/17", "title": "Bump demo",
        "base": {"ref": "main", "sha": "base-sha"},
        "head": {"ref": "dependabot/pip/demo-2", "sha": "head-sha"},
        "changed_files": 2,
    }
    files_response = Mock()
    files_response.json.return_value = [{
        "filename": "requirements.txt", "status": "modified", "additions": 1,
        "deletions": 1, "patch": "-demo==1.0\\n+demo==2.0",
    }]
    github = Mock()
    github.get.side_effect = [response, files_response]
    seen_tests: list[Path] = []
    seen_usage: list[Path] = []

    def fake_git(root: Path, *args: str) -> str:
        if args[:3] == ("remote", "get-url", "origin"):
            return "https://github.com/acme/demo.git"
        if args[0] == "rev-parse":
            return {"refs/agent-review/17/base": "base-sha", "refs/agent-review/17/head": "head-sha"}[args[1]]
        if args[:2] == ("worktree", "add"):
            Path(args[-2]).mkdir(parents=True, exist_ok=True)
        return ""

    def fake_test(worktree: Path, project_root: Path) -> dict:
        seen_tests.append(worktree)
        return {"passed": True, "returncode": 0, "output": "all tests passed", "command": ["pytest"]}

    scans = iter([
        {"manifests": ["requirements.txt"], "packages_checked": 1, "unresolved_packages": [],
         "findings": [{"id": "GHSA-old", "package": "demo", "version": "1.0", "ecosystem": "PyPI", "summary": "old"}]},
        {"manifests": ["requirements.txt"], "packages_checked": 1, "unresolved_packages": [], "findings": []},
    ])
    monkeypatch.setattr(git_ops, "git", fake_git)
    monkeypatch.setattr(tests_module, "run_snapshot_tests", fake_test)
    monkeypatch.setattr(scan_module, "scan_snapshot", lambda *_: next(scans))
    monkeypatch.setattr(inventory, "dependency_changes", lambda *_: [{
        "package": "demo", "ecosystem": "pypi", "base_version": "1.0", "head_version": "2.0",
    }])

    result = review.review_dependabot_pull_request(
        repository, "17", github_client=github,
        usage_analyzer=lambda head, findings: seen_usage.append((head, findings)) or [{"package": "demo"}],
    )

    assert result["status"] == "review_complete"
    assert [path.name for path in seen_tests] == ["base", "head"]
    assert seen_usage[0][0] == seen_tests[1]
    assert seen_usage[0][1][0]["id"].startswith("source-analysis:")
    assert seen_usage[0][1][0]["advisories"] == []
    assert result["schema_version"] == 6
    assert result["tests"]["base"]["passed"] is True
    assert result["tests"]["pr"]["passed"] is True
    assert result["files_changed"][0]["path"] == "requirements.txt"
    assert result["files_truncated"] is True
    assert result["summary"]["osv"]["resolved"] == 1
    assert result["summary"]["osv"]["unchanged_dependencies"] == 0
    assert result["summary"]["dependency_updates"] == [{
        "package": "demo", "from": "1.0", "to": "2.0", "ecosystem": "pypi",
        "relationship": "unknown", "dependency_paths": [],
    }]
    assert result["summary"]["dependency_analyses"][0]["relationship"] == "unknown"
    assert result["validation"] == {"status": "passed", "schema_version": 6, "errors": [], "warnings": []}
    assert result["osv_scans"]["base"]["finding_count"] == 1
    resolved = result["security_delta"]["resolved"][0]
    assert (resolved["package"], resolved["ecosystem"], resolved["version"]) == ("demo", "PyPI", "1.0")
    assert resolved["advisory_count"] == 1
    assert resolved["advisories"][0]["id"] == "GHSA-old"
    assert resolved["advisories"][0]["fixed_version_status"] == "unavailable"
    assert github.get.call_count == 2


@pytest.mark.parametrize(("osv_results", "source_fails", "release_fails"), [
    ([{"scan_status": "complete", "findings": [], "unresolved_packages": []},
      {"scan_status": "complete", "findings": [], "unresolved_packages": []}], False, False),
    ([RuntimeError("OSV offline"), {"scan_status": "complete", "findings": [], "unresolved_packages": []}], False, False),
    ([{"scan_status": "complete", "findings": [{"id": "GHSA-one", "package": "demo", "ecosystem": "PyPI", "version": "1"}], "unresolved_packages": []},
      {"scan_status": "complete", "findings": [{"id": "GHSA-one", "package": "demo", "ecosystem": "PyPI", "version": "2"}], "unresolved_packages": []}], True, False),
    ([{"scan_status": "complete", "findings": [
          {"id": f"GHSA-{index}", "package": "demo", "ecosystem": "PyPI", "version": "1"} for index in range(14)
      ], "unresolved_packages": []},
      {"scan_status": "complete", "findings": [
          {"id": f"GHSA-{index}", "package": "demo", "ecosystem": "PyPI", "version": "2"} for index in range(12)
      ], "unresolved_packages": []}], False, False),
    ([{"scan_status": "complete", "findings": [{"id": "GHSA-release", "package": "demo", "ecosystem": "PyPI", "version": "1"}], "unresolved_packages": []},
      {"scan_status": "complete", "findings": [{"id": "GHSA-release", "package": "demo", "ecosystem": "PyPI", "version": "2"}], "unresolved_packages": []}], False, True),
])
def test_source_analysis_runs_independently_of_osv_and_preserves_other_results(tmp_path, monkeypatch, osv_results, source_fails, release_fails):
    repository = tmp_path / "repo"
    repository.mkdir()
    (repository / ".git").mkdir()
    response = Mock()
    response.json.return_value = {
        "state": "open", "user": {"login": "dependabot[bot]"}, "html_url": "", "title": "Bump demo",
        "base": {"ref": "main", "sha": "base"}, "head": {"ref": "dependabot/demo", "sha": "head"},
        "changed_files": 1,
    }
    files = Mock()
    files.json.return_value = [{"filename": "requirements.txt", "status": "modified", "patch": ""}]
    github = Mock()
    github.get.side_effect = [response, files]
    scans = iter(osv_results)
    analyzed = []

    def fake_git(root, *args):
        if args[:3] == ("remote", "get-url", "origin"):
            return "https://github.com/acme/demo.git"
        if args[0] == "rev-parse":
            return {"refs/agent-review/2/base": "base", "refs/agent-review/2/head": "head"}[args[1]]
        if args[:2] == ("worktree", "add"):
            Path(args[-2]).mkdir(parents=True, exist_ok=True)
        return ""

    def scan(_root, _client):
        result = next(scans)
        if isinstance(result, Exception):
            raise result
        return result

    monkeypatch.setattr(git_ops, "git", fake_git)
    monkeypatch.setattr(tests_module, "run_snapshot_tests", lambda *_: {"passed": True, "returncode": 0, "output": "passed"})
    monkeypatch.setattr(scan_module, "scan_snapshot", scan)
    monkeypatch.setattr(inventory, "dependency_changes", lambda *_: [
        {"package": name, "ecosystem": "pypi", "base_version": "1", "head_version": "2",
         "relationship": "direct", "dependency_paths": [[name]]}
        for name in ("demo", "other")
    ])

    def source_analysis(_root, inputs):
        analyzed.extend(inputs)
        if source_fails:
            raise RuntimeError("source analysis unavailable")
        return [{"package": "demo", "ecosystem": "pypi", "locations": []}]

    def release_lookup(_changes):
        if release_fails:
            raise RuntimeError("release endpoint unavailable")
        return []

    result = review.review_dependabot_pull_request(
        repository, "2", github_client=github, usage_analyzer=source_analysis,
        release_context_lookup=release_lookup,
    )
    assert any((item.get("package", {}).get("name") if isinstance(item.get("package"), dict) else item.get("package")) == "demo"
               for item in analyzed)
    analyzed_names = {
        item.get("package", {}).get("name") if isinstance(item.get("package"), dict) else item.get("package")
        for item in analyzed
    }
    assert analyzed_names == {"demo", "other"}
    supplied_advisory_ids = {str(item.get("id")) for item in analyzed if not str(item.get("id", "")).startswith("source-analysis:")}
    expected_pr_advisory_ids = {str(item["id"]) for item in osv_results[1]["findings"]} if not isinstance(osv_results[1], Exception) else set()
    assert supplied_advisory_ids == expected_pr_advisory_ids
    expected_source_status = "failed" if source_fails else "completed_without_matches"
    assert result["summary"]["dependency_analyses"][0]["source_analysis_status"] == expected_source_status
    assert result["summary"]["dependency_analyses"][1]["source_analysis_status"] == expected_source_status
    if isinstance(osv_results[0], Exception):
        assert result["osv_scans"]["base"]["status"] == "failed"
        assert result["summary"]["dependency_analyses"][0]["osv_status"] == "failed"
    if source_fails:
        assert result["summary"]["osv"]["remaining"] == 1
        assert result["osv_scans"]["base"]["status"] == "complete"
    if release_fails:
        assert result["status"] == "review_complete"
        assert result["release_context"][0]["status"] == "lookup_failed"
        assert result["summary"]["osv"]["remaining"] == 1
        assert result["summary"]["dependency_analyses"][0]["source_analysis_status"] == "completed_without_matches"


def test_actions_only_update_keeps_python_baseline_out_of_pr_delta():
    finding = {"id": "OSV-BASE", "package": "aiohttp", "version": "3.8.0", "ecosystem": "PyPI"}
    delta = review._pr_security_delta(
        {"scan_status": "complete", "findings": [finding]},
        {"scan_status": "complete", "findings": [finding]},
        [], scan_scope_changed=False,
    )
    assert delta["resolved"] == delta["introduced"] == delta["remaining"] == []
    assert delta["unaffected"] == [finding]
    report = review._compact_review_report({
        "files_changed": [{"path": ".github/workflows/ci.yml", "category": "github_actions_workflow"}],
        "base": {"security_scan": {"findings": [finding]}, "tests": {"passed": True}},
        "head": {"security_scan": {"findings": [finding]}, "tests": {"passed": True}},
        "security_delta": delta, "dependency_changes": [],
        "test_comparison": {"base_passed": True, "pr_passed": True},
    })
    assert report["summary"]["osv"]["introduced"] == 0
    assert report["summary"]["osv"]["remaining"] == 0
    assert report["summary"]["osv"]["unchanged_dependencies"] == 1
    assert report["security_delta"]["unchanged_dependencies"][0]["package"] == "aiohttp"
    assert "unaffected" not in report["security_delta"]
    assert report["security_delta"]["version_assessment_counts"]["unchanged_dependencies"]["affected"] == 0
    assert "do not assess GitHub Actions" in report["summary"]["osv_scope_note"]


@pytest.mark.parametrize(("base_findings", "head_findings", "classification"), [
    ([{"id": "GHSA-1", "package": "demo", "version": "1", "ecosystem": "PyPI"}], [], "resolved"),
    ([], [{"id": "GHSA-1", "package": "demo", "version": "2", "ecosystem": "PyPI"}], "introduced"),
    ([{"id": "GHSA-1", "package": "demo", "version": "1", "ecosystem": "PyPI"}],
     [{"id": "GHSA-1", "package": "demo", "version": "2", "ecosystem": "PyPI"}], "remaining"),
])
def test_changed_python_dependency_findings_are_classified(base_findings, head_findings, classification):
    delta = review._pr_security_delta(
        {"scan_status": "complete", "findings": base_findings},
        {"scan_status": "complete", "findings": head_findings},
        [{"package": "demo", "ecosystem": "pypi", "base_version": "1", "head_version": "2"}],
        scan_scope_changed=True,
    )
    assert len(delta[classification]) == 1
    assert sum(len(delta[key]) for key in ("resolved", "introduced", "remaining")) == 1


def test_failed_osv_scan_is_not_reported_as_zero_findings():
    delta = review._pr_security_delta(
        {"scan_status": "failed", "findings": []}, {"scan_status": "complete", "findings": []},
        [{"package": "demo", "ecosystem": "pypi", "base_version": "1", "head_version": "2"}],
        scan_scope_changed=True,
    )
    assert delta["resolved"] == delta["introduced"] == delta["remaining"] == []
    assert delta["not_assessed"][0]["package"] == "demo"


def test_missing_osv_scan_results_are_not_treated_as_empty_success():
    delta = review._pr_security_delta(
        {}, {"scan_status": "complete", "findings": []},
        [{"package": "demo", "ecosystem": "pypi", "base_version": "1", "head_version": "2"}],
        scan_scope_changed=True,
    )
    assert delta["resolved"] == delta["introduced"] == delta["remaining"] == []
    assert delta["not_assessed"][0]["package"] == "demo"


def test_unresolved_changed_package_is_not_reported_as_zero_vulnerabilities():
    delta = review._pr_security_delta(
        {"scan_status": "complete", "findings": [], "unresolved_packages": []},
        {"scan_status": "complete", "findings": [], "unresolved_packages": ["demo"]},
        [{"package": "demo", "ecosystem": "pypi", "base_version": "1", "head_version": ""}],
        scan_scope_changed=True,
    )
    assert delta["not_assessed"][0]["package"] == "demo"


def test_changed_file_categories_cover_dependency_actions_config_and_source():
    assert review._changed_file_category("pyproject.toml") == "dependency_manifest"
    assert review._changed_file_category("poetry.lock") == "dependency_lockfile"
    assert review._changed_file_category(".github/workflows/ci.yml") == "github_actions_workflow"
    assert review._changed_file_category(".pre-commit-config.yaml") == "configuration"
    assert review._changed_file_category("src/app.py") == "application_source"
    assert review._changed_file_category("README.md") == "other"


def test_multiple_supported_dependency_manifests_are_scanned_as_background_inventory(tmp_path):
    (tmp_path / "poetry.lock").write_text('''[[package]]
name = "demo"
version = "1.0"
''')
    (tmp_path / "package.json").write_text('{"dependencies": {"left-pad": "1.3.0"}}')
    packages, manifests = review._read_packages(tmp_path)
    assert manifests == ["poetry.lock", "package.json"]
    assert {(item["ecosystem"], item["name"]) for item in packages} == {
        ("PyPI", "demo"), ("npm", "left-pad"),
    }


