"""Offline regression contracts for Dependabot review evidence quality.

These tests exercise both the report contract and production code paths with
local fixtures; none rely on external services.
"""
from __future__ import annotations

import json

import pytest

from vulnerability_agent import dependabot_review as review
from vulnerability_agent.nodes import usage_analysis
from vulnerability_agent.report_validation import EvidenceReportValidationError, validate_evidence_report
from vulnerability_agent.review_graph import _sanitize_ai_review, render_pr_comment, render_review_prompt


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


def test_remaining_alias_records_assess_pr_version_and_preserve_base_assessment():
    def record(advisory_id, version):
        return {
            "id": advisory_id, "package": "langchain", "ecosystem": "PyPI", "version": version,
            "aliases": ["CVE-2026-12345"], "affected_ranges": [{"type": "ECOSYSTEM", "events": [
                {"introduced": "0"}, {"fixed": "0.3.30"},
            ]}], "affected_versions": [],
        }

    before = [record("GHSA-3644-Q5CJ-C5C7", "0.2.16"), record("PYSEC-2026-2555", "0.2.16")]
    after = [record("GHSA-3644-Q5CJ-C5C7", "0.2.17"), record("PYSEC-2026-2555", "0.2.17")]
    delta = review._pr_security_delta(_scan(before), _scan(after), _changed("langchain"), scan_scope_changed=True)

    assert {item["id"] for item in delta["remaining"]} == {"GHSA-3644-Q5CJ-C5C7", "PYSEC-2026-2555"}
    assert {item["version_assessment"]["installed_version"] for item in delta["remaining"]} == {"0.2.17"}
    assert {item["base_version_assessment"]["installed_version"] for item in delta["remaining"]} == {"0.2.16"}
    compact, = review._compact_advisory_groups(delta["remaining"])
    assert compact["installed_version"] == compact["head_version"] == "0.2.17"
    assert compact["base_version"] == "0.2.16"
    assert {item["version_assessment"]["installed_version"] for item in compact["advisories"]} == {"0.2.17"}
    report = review._compact_review_report({
        "mode": "dependabot_pr_review", "status": "review_complete", "repository_full_name": "acme/demo",
        "pull_request": {"number": 11}, "files_changed": [],
        "dependency_changes": [{"package": "langchain", "ecosystem": "pypi", "base_version": "0.2.16",
                                "head_version": "0.2.17", "relationship": "direct", "dependency_paths": [["langchain"]]}],
        "source_usage_status": "completed_without_matches", "source_usage": [],
        "base": {"tests": {"passed": True}, "security_scan": _scan(before)},
        "head": {"tests": {"passed": True}, "security_scan": _scan(after)},
        "security_delta": delta,
    })
    persisted, = report["security_delta"]["remaining"]
    assert persisted["installed_version"] == persisted["head_version"] == "0.2.17"
    assert {item["version_assessment"]["installed_version"] for item in persisted["advisories"]} == {"0.2.17"}
    assert {item["base_version_assessment"]["installed_version"] for item in persisted["advisories"]} == {"0.2.16"}
    invalid_report = json.loads(json.dumps(report))
    invalid_report["security_delta"]["remaining"][0]["advisories"][0]["version_assessment"]["installed_version"] = "0.2.16"
    with pytest.raises(EvidenceReportValidationError, match="assessment version disagrees"):
        validate_evidence_report(invalid_report)


def test_alias_grouping_counts_underlying_issues_without_discarding_records():
    findings = [
        {"id": "GHSA-AAAA-BBBB-CCCC", "aliases": ["CVE-2025-12345", "PYSEC-2025-100"],
         "package": "alpha", "ecosystem": "PyPI"},
        {"id": "PYSEC-2025-100", "aliases": ["CVE-2025-12345"],
         "package": "beta", "ecosystem": "PyPI"},
        {"id": "OSV-LOCAL-1", "aliases": ["unreliable-alias"],
         "package": "gamma", "ecosystem": "PyPI"},
    ]
    summary = review._underlying_vulnerability_summary(findings)

    assert summary["known_unique_count"] == 1
    assert summary["unknown_identity_record_count"] == 1
    assert summary["groups"][0]["advisory_ids"] == ["GHSA-AAAA-BBBB-CCCC", "PYSEC-2025-100"]
    assert summary["groups"][0]["packages"] == ["alpha", "beta"]


def test_json_report_separates_advisory_records_from_underlying_vulnerability_count():
    base_finding = {"id": "GHSA-AAAA-BBBB-CCCC", "aliases": ["CVE-2025-12345"],
                    "package": "demo", "ecosystem": "PyPI", "version": "1.0"}
    head_finding = {"id": "PYSEC-2025-123", "aliases": ["CVE-2025-12345"],
                    "package": "demo", "ecosystem": "PyPI", "version": "2.0"}
    delta = review._pr_security_delta(_scan([base_finding]), _scan([head_finding]), _changed(), scan_scope_changed=True)
    report = review._compact_review_report({
        "mode": "dependabot_pr_review", "status": "review_complete", "repository_full_name": "acme/demo",
        "pull_request": {"number": 4}, "files_changed": [], "dependency_changes": _changed(),
        "base": {"tests": {"passed": True}, "security_scan": _scan([base_finding])},
        "head": {"tests": {"passed": True}, "security_scan": _scan([head_finding])},
        "security_delta": delta,
    })

    assert report["security_delta"]["counts"]["remaining"] == 2
    group, = report["security_delta"]["remaining"]
    assert group["advisory_count"] == 2
    assert {item["id"] for item in group["advisories"]} == {"GHSA-AAAA-BBBB-CCCC", "PYSEC-2025-123"}
    semantic = report["security_delta"]["count_semantics"]["underlying_vulnerabilities"]["remaining"]
    assert semantic["known_unique_count"] == 1
    assert semantic["groups"][0]["identity"] == "CVE-2025-12345"


def test_unverified_shared_alias_does_not_merge_osv_classifications():
    delta = review._pr_security_delta(
        _scan([{"id": "OSV-OLD", "aliases": ["not-a-real-alias"], "package": "demo", "ecosystem": "PyPI", "version": "1"}]),
        _scan([{"id": "OSV-NEW", "aliases": ["not-a-real-alias"], "package": "demo", "ecosystem": "PyPI", "version": "2"}]),
        _changed(), scan_scope_changed=True,
    )
    assert len(delta["resolved"]) == 1
    assert len(delta["introduced"]) == 1
    assert delta["remaining"] == []


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
    assert source["dependency_relationship"] == "transitive"
    assert source["source_usage_classifications"] == ["direct_import"]
    assert source["vulnerability_reachability"] == [{"status": "unknown"}]
    assert validate_evidence_report(report) is report

    comment = render_pr_comment(report, "The demo dependency is transitive and directly imported by the application. The demo package is a direct application dependency.")
    assert "dependency graph says transitive" in comment
    assert "production source evidence: direct import" in comment
    assert "vulnerability reachability: unknown" in comment
    assert "direct application dependency" not in comment

    prompt = render_review_prompt(report)
    assert '"dependency_relationship": "transitive"' in prompt
    assert '"source_usage_classifications": ["direct_import"]' in prompt


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


def test_distribution_name_maps_to_import_module():
    assert "git" in usage_analysis._package_terms("GitPython")


def test_configuration_only_package_reference_is_discoverable_as_configuration(tmp_path, monkeypatch):
    monkeypatch.setattr(usage_analysis.subprocess, "run", lambda *_args, **_kwargs: type(
        "Result", (), {"returncode": 0, "stdout": "pyproject.toml\0", "stderr": ""})())
    paths, _ = usage_analysis._source_paths(tmp_path, "demo")
    assert paths == ["pyproject.toml"]


def test_test_only_and_configuration_references_are_not_production_usage():
    compact = review._compact_source_usage([
        {"package": "demo", "ecosystem": "PyPI", "locations": [
            {"path": "tests/test_demo.py", "line_start": 1, "line_end": 1,
             "evidence_classification": "semantic_context"},
            {"path": "pyproject.toml", "line_start": 1, "line_end": 1,
             "evidence_classification": "semantic_context"},
        ]},
    ])[0]
    assert [item["evidence_classification"] for item in compact["locations"]] == ["test_only", "configuration"]


@pytest.mark.parametrize("text,expected", [
    ('mock.patch("git.Repo")', "test_only"),
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


def test_package_evidence_label_is_derived_from_traceable_import_locations():
    compact, = review._compact_source_usage([{
        "package": "langchain-core", "ecosystem": "pypi", "evidence_classification": "no_evidence",
        "application_usage_classifications": ["direct_import"],
        "locations": [
            {"path": "src/agent.py", "line_start": 4, "line_end": 4,
             "excerpt": "from langchain_core import messages", "evidence_classification": "semantic_context"},
            {"path": "src/agent.py", "line_start": 4, "line_end": 4,
             "excerpt": "from langchain_core import messages", "match_type": "AST import",
             "evidence_classification": "direct_import"},
        ],
    }])
    assert compact["evidence_classification"] == "direct_import"
    assert compact["source_usage_classifications"] == ["direct_import"]


@pytest.mark.parametrize("usage_class,expected", [
    ("api_usage", "unknown"),
    ("direct_import", "unknown"),
    ("no_evidence", "unknown"),
    ("semantic_context", "unknown"),
])
def test_vulnerability_reachability_requires_advisory_specific_api_evidence(usage_class, expected):
    compact, = review._compact_source_usage([{
        "package": "demo", "ecosystem": "PyPI", "advisory_ids": ["GHSA-TEST"],
        "application_usage_classifications": [usage_class],
        "locations": [],
    }])
    assert compact["vulnerability_reachability"] == [{"advisory_id": "GHSA-TEST", "status": expected}]


