"""Offline regression contracts for Dependabot review evidence quality.

Strict expected failures below document contracts that this branch does not
yet implement. When the corresponding production behavior lands, remove the
xfail marker so an accidental regression fails the suite.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from vulnerability_agent import dependabot_review as review
from vulnerability_agent.nodes import usage_analysis
from vulnerability_agent.report_validation import EvidenceReportValidationError, validate_evidence_report
from vulnerability_agent.review_graph import render_pr_comment


def _scan(findings):
    return {"scan_status": "complete", "findings": findings, "unresolved_packages": []}


def _changed(package="demo", ecosystem="pypi"):
    return [{"package": package, "ecosystem": ecosystem, "base_version": "1.0", "head_version": "2.0"}]


@pytest.mark.parametrize(("base", "pr", "expected"), [
    ([{"id": "GHSA-OLD", "package": "demo", "ecosystem": "PyPI", "version": "1.0"}], [], "resolved"),
    ([], [{"id": "GHSA-NEW", "package": "demo", "ecosystem": "PyPI", "version": "2.0"}], "introduced"),
    ([{"id": "GHSA-SAME", "package": "demo", "ecosystem": "PyPI", "version": "1.0"}],
     [{"id": "GHSA-SAME", "package": "demo", "ecosystem": "PyPI", "version": "2.0"}], "remaining"),
])
def test_osv_classifications_are_deterministic(base, pr, expected):
    delta = review._pr_security_delta(
        _scan(base), _scan(pr), _changed(), scan_scope_changed=True,
    )
    assert len(delta[expected]) == 1
    assert sum(len(delta[key]) for key in ("introduced", "resolved", "remaining")) == 1


def test_different_advisories_on_one_package_are_not_merged():
    before = [{"id": "GHSA-ONE", "package": "demo", "ecosystem": "PyPI", "version": "1.0"},
              {"id": "GHSA-TWO", "package": "demo", "ecosystem": "PyPI", "version": "1.0"}]
    after = [{**item, "version": "2.0"} for item in before]

    delta = review._pr_security_delta(_scan(before), _scan(after), _changed(), scan_scope_changed=True)

    assert {item["id"] for item in delta["remaining"]} == {"GHSA-ONE", "GHSA-TWO"}
    grouped = review._compact_advisory_groups(delta["remaining"])
    assert len(grouped) == 1
    assert grouped[0]["advisory_count"] == 2


def test_unknown_aliases_are_preserved_without_inventing_alias_identity():
    finding = {"id": "OSV-LOCAL-1", "aliases": ["UNVERIFIED-REF"], "package": "demo",
               "ecosystem": "PyPI", "version": "2.0"}

    group, = review._compact_advisory_groups([finding])

    assert group["advisories"][0]["id"] == "OSV-LOCAL-1"
    assert group["advisories"][0]["aliases"] == ["UNVERIFIED-REF"]


def test_package_affected_version_range_boundaries_are_checked_offline():
    finding = {
        "id": "GHSA-BOUNDARY", "package": {"name": "demo", "ecosystem": "PyPI", "version": "1.0.0"},
        "affected": [{"package": {"name": "demo", "ecosystem": "PyPI"},
                      "ranges": [{"type": "ECOSYSTEM", "events": [
                          {"introduced": "1.0.0"}, {"fixed": "2.0.0"},
                      ]}]}],
    }
    from osv_service import is_version_affected_by_advisory

    assert is_version_affected_by_advisory(finding, "1.0.0")
    assert is_version_affected_by_advisory(finding, "1.9.9")
    assert not is_version_affected_by_advisory(finding, "2.0.0")


@pytest.mark.xfail(strict=True, reason="comparison currently keys findings by advisory ID, not reliable shared aliases")
def test_two_advisory_ids_sharing_a_cve_remain_one_underlying_issue():
    before = [{"id": "GHSA-AAAA-BBBB-CCCC", "aliases": ["CVE-2025-12345"],
               "package": "demo", "ecosystem": "PyPI", "version": "1.0"}]
    after = [{"id": "PYSEC-2025-123", "aliases": ["CVE-2025-12345"],
              "package": "demo", "ecosystem": "PyPI", "version": "2.0"}]

    delta = review._pr_security_delta(_scan(before), _scan(after), _changed(), scan_scope_changed=True)

    assert not delta["resolved"] and not delta["introduced"]
    assert len(delta["remaining"]) == 2
    assert {item["aliases"][0] for item in delta["remaining"]} == {"CVE-2025-12345"}


def test_dependency_relationship_can_be_direct_transitive_or_unknown(tmp_path):
    base, head = tmp_path / "base", tmp_path / "head"
    base.mkdir()
    head.mkdir()
    (base / "pyproject.toml").write_text('[tool.poetry.dependencies]\nroot = "*"\n')
    (head / "pyproject.toml").write_text('[tool.poetry.dependencies]\nroot = "*"\n')
    (base / "poetry.lock").write_text(
        '[[package]]\nname="root"\nversion="1.0"\n[package.dependencies]\ndemo="*"\n\n'
        '[[package]]\nname="demo"\nversion="1.0"\n\n[[package]]\nname="orphan"\nversion="1.0"\n'
    )
    (head / "poetry.lock").write_text(
        '[[package]]\nname="root"\nversion="1.0"\n[package.dependencies]\ndemo="*"\n\n'
        '[[package]]\nname="demo"\nversion="2.0"\n\n[[package]]\nname="orphan"\nversion="2.0"\n'
    )
    direct_base, direct_head = tmp_path / "direct-base", tmp_path / "direct-head"
    direct_base.mkdir(); direct_head.mkdir()
    (direct_base / "requirements.txt").write_text("direct-demo==1.0\n")
    (direct_head / "requirements.txt").write_text("direct-demo==2.0\n")

    changes = review._dependency_changes(
        base, head,
        {"resolved_packages": [
            {"name": "demo", "version": "1.0", "ecosystem": "PyPI"},
            {"name": "orphan", "version": "1.0", "ecosystem": "PyPI"},
        ]},
        {"resolved_packages": [
            {"name": "demo", "version": "2.0", "ecosystem": "PyPI"},
            {"name": "orphan", "version": "2.0", "ecosystem": "PyPI"},
        ]},
    )
    direct = review._dependency_changes(
        direct_base, direct_head,
        {"resolved_packages": [{"name": "direct-demo", "version": "1.0", "ecosystem": "PyPI"}]},
        {"resolved_packages": [{"name": "direct-demo", "version": "2.0", "ecosystem": "PyPI"}]},
    )

    relationships = {item["package"]: item["relationship"] for item in changes + direct}
    assert relationships == {"demo": "transitive", "orphan": "unknown", "direct-demo": "direct"}


def test_transitive_dependency_usage_evidence_stays_separate_from_relationship():
    changed = [{"package": "demo", "ecosystem": "pypi", "base_version": "1.0", "head_version": "2.0",
                "relationship": "transitive", "dependency_paths": [["root", "demo"]]}]
    report = review._compact_review_report({
        "mode": "dependabot_pr_review", "status": "review_complete", "repository_full_name": "acme/demo",
        "pull_request": {"number": 3}, "files_changed": [], "dependency_changes": changed,
        "source_usage_status": "completed_with_matches",
        "source_usage": [{"package": "demo", "ecosystem": "pypi", "locations": [{
            "path": "src/agent.py", "line_start": 4, "line_end": 4,
            "evidence_classification": "direct_import",
        }]}],
        "base": {"tests": {"passed": True, "returncode": 0},
                 "security_scan": {"scan_status": "complete", "findings": [], "unresolved_packages": []}},
        "head": {"tests": {"passed": True, "returncode": 0},
                 "security_scan": {"scan_status": "complete", "findings": [], "unresolved_packages": []}},
        "security_delta": {"resolved": [], "introduced": [], "remaining": [], "unaffected": [], "not_assessed": []},
    })

    dependency = report["summary"]["dependency_analyses"][0]
    source = report["source_usage"][0]
    assert dependency["relationship"] == "transitive"
    assert source["relationship"] == "transitive"
    assert source["locations"][0]["evidence_classification"] == "direct_import"
    assert validate_evidence_report(report) is report


def test_source_candidates_prioritize_production_files_over_test_files(tmp_path, monkeypatch):
    from types import SimpleNamespace

    def fake_run(command, **_kwargs):
        if command[1:3] == ["ls-files", "--cached"]:
            return SimpleNamespace(returncode=0, stdout="tests/test_client.py\0src/client.py\0", stderr="")
        if command[1:3] == ["grep", "-l"]:
            return SimpleNamespace(returncode=0, stdout="tests/test_client.py\nsrc/client.py\n", stderr="")
        raise AssertionError(f"Unexpected subprocess call: {command}")

    monkeypatch.setattr(usage_analysis.subprocess, "run", fake_run)
    paths, count = usage_analysis._source_paths(tmp_path, "demo")

    assert count == 2
    assert paths == ["src/client.py", "tests/test_client.py"]


def test_source_report_retains_import_api_test_and_semantic_evidence_labels():
    records = review._compact_source_usage([{
        "package": "demo", "ecosystem": "PyPI", "locations": [
            {"path": "src/app.py", "line_start": 1, "line_end": 1,
             "evidence_classification": "direct_import"},
            {"path": "src/usage.py", "line_start": 2, "line_end": 2,
             "evidence_classification": "api_usage"},
            {"path": "tests/test_demo.py", "line_start": 3, "line_end": 3,
             "evidence_classification": "test_only"},
        ],
    }])
    labels = {item["evidence_classification"] for item in records[0]["locations"]}
    assert labels == {"direct_import", "api_usage", "test_only"}


@pytest.mark.xfail(strict=True, reason="source analysis has no AST-based deterministic import classifier on this branch")
@pytest.mark.parametrize("source", [
    "import git\n",
    "import git as pygit\n",
    "from git.repo import Repo as GitRepo\n",
])
def test_gitpython_distribution_import_variants_are_classified_as_direct_import(tmp_path, monkeypatch, source):
    monkeypatch.setattr(usage_analysis, "_package_terms", lambda _name: ["git"])
    monkeypatch.setattr(usage_analysis, "_source_paths", lambda *_: (["src/app.py"], 1))
    monkeypatch.setattr(usage_analysis.subprocess, "run", lambda *_a, **_kw: type(
        "Result", (), {"returncode": 0, "stdout": "revision", "stderr": ""})())

    class Retriever:
        def has_index(self, *_args): return True
        def retrieve(self, *_args, **_kwargs):
            return [{"path": "src/app.py", "line_start": 1, "line_end": 1, "content": source}]

    class Dependencies:
        def get_code_retriever(self): return Retriever()

    report = usage_analysis.node_report_source_usage({
        "repo_path": str(tmp_path), "main_repo_path": str(tmp_path), "usage_analysis": [],
        "current_vuln": {"id": "OSV-1", "package": {"name": "GitPython", "ecosystem": "PyPI"}},
    }, Dependencies())["current_usage_analysis"]

    assert report["locations"][0]["evidence_classification"] == "direct_import"


@pytest.mark.xfail(strict=True, reason="distribution-to-module mapping table omits GitPython -> git")
def test_distribution_name_maps_to_import_module():
    assert "git" in usage_analysis._package_terms("GitPython")


@pytest.mark.xfail(strict=True, reason="configuration files are excluded from source discovery")
def test_configuration_only_package_reference_is_discoverable_as_configuration(tmp_path, monkeypatch):
    monkeypatch.setattr(usage_analysis.subprocess, "run", lambda *_args, **_kwargs: type(
        "Result", (), {"returncode": 0, "stdout": "pyproject.toml\0", "stderr": ""})())
    paths, _ = usage_analysis._source_paths(tmp_path, "demo")
    assert paths == ["pyproject.toml"]


def test_test_only_and_configuration_references_are_not_production_usage():
    compact = review._compact_source_usage([
        {"package": "demo", "ecosystem": "PyPI", "locations": [
            {"path": "tests/test_demo.py", "line_start": 1, "line_end": 1,
             "evidence_classification": "test_only"},
            {"path": "pyproject.toml", "line_start": 1, "line_end": 1,
             "evidence_classification": "configuration"},
        ]},
    ])[0]
    assert [item["evidence_classification"] for item in compact["locations"]] == ["test_only", "configuration"]


@pytest.mark.parametrize("text,expected", [
    pytest.param('mock.patch("git.Repo")', "test_only", marks=pytest.mark.xfail(
        strict=True, reason="mocked dependency references are not classified as test-only by retrieval")),
    ("some unrelated but semantically similar handler", "semantic_context"),
    ("", "no_evidence"),
])
def test_mocked_semantic_and_absent_references_are_not_called_direct_usage(text, expected):
    source = {"package": "GitPython", "locations": [] if not text else [{
        "path": "tests/test_mock.py" if "mock" in text else "src/handler.py",
        "line_start": 1, "line_end": 1, "excerpt": text,
    }]}
    compact = review._compact_source_usage([source])[0]
    actual = compact["evidence_classification"] if not compact["locations"] else compact["locations"][0].get("evidence_classification")
    assert actual == expected


@pytest.mark.xfail(strict=True, reason="report source usage currently drops advisory-specific reachability evidence")
@pytest.mark.parametrize("usage_class,expected", [
    ("api_usage", "established"),
    ("direct_import", "unknown"),
    ("no_evidence", "unknown"),
    ("semantic_context", "unknown"),
])
def test_vulnerability_reachability_requires_advisory_specific_api_evidence(usage_class, expected):
    compact, = review._compact_source_usage([{
        "package": "demo", "ecosystem": "PyPI", "advisory_ids": ["GHSA-TEST"],
        "application_usage_classifications": [usage_class],
        "vulnerability_reachability": [{"advisory_id": "GHSA-TEST", "status": expected}],
        "locations": [],
    }])
    assert compact["vulnerability_reachability"] == [{"advisory_id": "GHSA-TEST", "status": expected}]


@pytest.mark.xfail(strict=True, reason="schema v4 does not carry advisory-specific vulnerability_reachability")
def test_report_represents_vulnerability_reachability_as_unknown_without_specific_evidence():
    report = review._compact_review_report({
        "mode": "dependabot_pr_review", "status": "review_complete", "repository_full_name": "acme/demo",
        "pull_request": {"number": 1}, "files_changed": [], "dependency_changes": [],
        "base": {"tests": {"passed": True, "returncode": 0}, "security_scan": {"scan_status": "complete", "findings": []}},
        "head": {"tests": {"passed": True, "returncode": 0}, "security_scan": {"scan_status": "complete", "findings": []}},
        "test_comparison": review._compare_tests({"passed": True, "returncode": 0}, {"passed": True, "returncode": 0}),
        "security_delta": {"resolved": [], "introduced": [], "remaining": [], "unaffected": [], "not_assessed": []},
        "source_usage": [{"package": "demo", "ecosystem": "PyPI", "locations": [], "advisory_ids": []}],
    })
    assert report["source_usage"][0]["vulnerability_reachability"] == [{"status": "unknown"}]
    validate_evidence_report(report)


@pytest.mark.xfail(strict=True, reason="LLM text is appended without grounding validation against supplied evidence")
def test_comment_does_not_publish_fabricated_source_claims_when_evidence_is_missing():
    body = render_pr_comment({
        "dependency_changes": [], "summary": {"dependency_updates": [], "tests": {}, "osv": {}},
        "source_usage": [],
    }, "The package is imported at src/secret.py:99 and its vulnerable API is reachable.")
    assert "src/secret.py" not in body
    assert "vulnerable API is reachable" not in body

