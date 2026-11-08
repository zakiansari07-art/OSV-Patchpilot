"""Offline regression contracts for Dependabot review evidence quality.

These tests exercise both the report contract and production code paths with
local fixtures; none rely on external services.
"""
from __future__ import annotations

import json
from pathlib import Path

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
    assert "production source evidence: direct_import" in comment
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


def test_explicit_advisory_specific_vulnerable_api_evidence_can_establish_reachability():
    compact, = review._compact_source_usage([{
        "package": "demo", "ecosystem": "PyPI", "advisory_ids": ["GHSA-TEST"],
        "vulnerability_reachability": [{"advisory_id": "GHSA-TEST", "status": "established",
                                         "evidence": "src/app.py:8 invokes the affected parser API"}],
        "locations": [],
    }])
    assert compact["vulnerability_reachability"][0]["status"] == "established"
    assert "affected parser API" in compact["vulnerability_reachability"][0]["evidence"]


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


def test_definitive_reachability_status_requires_evidence():
    from vulnerability_agent.report_validation import VulnerabilityReachability

    with pytest.raises(ValueError, match="requires supporting evidence"):
        VulnerabilityReachability(status="established")
    with pytest.raises(ValueError, match="requires supporting evidence"):
        VulnerabilityReachability(status="not_established")


def test_comment_does_not_publish_fabricated_source_claims_when_evidence_is_missing():
    report = {
        "dependency_changes": [], "summary": {"dependency_updates": [], "tests": {}, "osv": {}},
        "source_usage": [],
    }
    body = render_pr_comment(report,
        "The package is imported at src/secret.py:99 and its vulnerable API is reachable. "
        "Passing tests prove all functionality is compatible. The whole repository is secure. "
        "Upstream release notes prove application compatibility.")
    assert "src/secret.py" not in body
    assert "vulnerable API is reachable" not in body
    assert "prove all functionality" not in body
    assert "whole repository is secure" not in body
    assert "release notes prove application compatibility" not in body


def test_comment_labels_limited_source_location_selection():
    report = {
        "dependency_changes": [],
        "summary": {"dependency_updates": [], "tests": {}, "osv": {}},
        "source_usage": [{"package": "demo", "locations": [
            {"path": f"src/module_{index}.py", "line_start": index, "line_end": index,
             "evidence_classification": "direct_import"}
            for index in range(1, 7)
        ]}],
    }
    body = render_pr_comment(report, "")
    assert "showing 6 of 6" in body
    assert "src/module_3.py" in body
    assert "src/module_4.py" in body


def test_comment_source_locations_are_selected_fairly_across_changed_packages():
    report = {
        "dependency_changes": [], "summary": {"dependency_updates": [], "tests": {}, "osv": {}},
        "source_usage": [
            {"package": "langchain", "locations": [
                {"path": f"src/langchain_{i}.py", "line_start": i, "line_end": i,
                 "evidence_classification": "direct_import", "area": "application"}
                for i in range(1, 7)
            ]},
            {"package": "langchain-core", "locations": [
                {"path": f"src/core_{i}.py", "line_start": i, "line_end": i,
                 "evidence_classification": "direct_import", "area": "application"}
                for i in range(1, 4)
            ]},
        ],
    }
    body = render_pr_comment(report, "")
    assert "showing 6 of 9" in body
    assert "`langchain-core`: `src/core_1.py:1-1`" in body
    assert "`langchain-core`: `src/core_2.py:2-2`" in body


def test_ai_review_does_not_conflate_osv_affected_version_with_application_reachability():
    report = {
        "dependency_changes": [{"package": "langchain-core", "relationship": "transitive"}],
        "security_delta": {"remaining": [{"package": "langchain-core", "advisories": [{
            "version_assessment": {"status": "affected"},
        }]}]},
        "source_usage": [{"package": "langchain-core", "relationship": "transitive",
                          "source_usage_classifications": ["direct_import"],
                          "vulnerability_reachability": [{"status": "unknown"}],
                          "locations": [{"path": "src/agent.py", "line_start": 9,
                                         "evidence_classification": "direct_import", "area": "application"}]}],
    }
    ai_text = (
        "The installed langchain-core version is affected according to OSV. "
        "langchain-core is directly affected by known vulnerabilities. "
        "Production code imports langchain-core, but vulnerable API reachability is unknown."
    )
    clean = _sanitize_ai_review(report, ai_text)
    assert "installed langchain-core version is affected according to OSV" in clean
    assert "directly affected by known vulnerabilities" not in clean
    assert "Production code imports" not in clean


def test_comment_surfaces_release_retrieval_and_no_notes_separately():
    body = render_pr_comment({
        "dependency_changes": [], "summary": {"dependency_updates": [], "tests": {}, "osv": {}},
        "release_context": [
            {"package": "demo", "status": "lookup_failed", "error": "HTTPStatusError: 403"},
            {"package": "other", "status": "no_release_notes"},
            {"package": "third", "status": "retrieved", "release_notes": "Notes found."},
        ],
        "source_usage": [],
    }, "")
    assert "demo: lookup failed (HTTPStatusError: 403)" in body
    assert "other: no release notes found" in body
    assert "third: release notes retrieved" in body


def test_configuration_or_lockfile_reference_is_not_presented_as_application_usage():
    body = render_pr_comment({
        "dependency_changes": [], "summary": {"dependency_updates": [], "tests": {}, "osv": {}},
        "source_usage": [{"package": "demo", "relationship": "transitive",
                          "application_usage_classifications": ["configuration"],
                          "vulnerability_reachability": [{"status": "unknown"}], "locations": []}],
    }, "")
    assert "configuration reference only; production source usage not established" in body
    assert "vulnerability reachability: unknown" in body


def test_recommendation_includes_version_guidance_usage_and_unknown_reachability():
    report = review._compact_review_report({
        "mode": "dependabot_pr_review", "status": "review_complete", "repository_full_name": "acme/demo",
        "pull_request": {"number": 4}, "files_changed": [],
        "dependency_changes": [{"package": "langchain-core", "ecosystem": "pypi", "base_version": "0.2.40",
                                "head_version": "0.2.41", "relationship": "transitive",
                                "dependency_paths": [["langchain", "langchain-core"]]}],
        "source_usage_status": "completed_with_matches",
        "source_usage": [{"package": "langchain-core", "ecosystem": "pypi", "relationship": "transitive",
                           "dependency_paths": [["langchain", "langchain-core"]], "advisory_ids": ["GHSA-TEST"],
                           "application_usage_classifications": ["direct_import"],
                           "locations": [{"path": "src/app.py", "line_start": 8, "line_end": 8,
                                          "evidence_classification": "direct_import"}]}],
        "base": {"tests": {"passed": True}, "security_scan": {"scan_status": "complete", "findings": [], "unresolved_packages": []}},
        "head": {"tests": {"passed": True}, "security_scan": {"scan_status": "complete", "findings": [], "unresolved_packages": []}},
        "security_delta": {
            "resolved": [], "introduced": [],
            "remaining": [{"id": "GHSA-TEST", "package": "langchain-core", "ecosystem": "PyPI", "version": "0.2.41",
                           "affected_range_status": "available", "fixed_version_status": "available",
                           "fixed_versions": ["0.2.42"], "aliases": ["CVE-2025-54321"],
                           "version_assessment": {"status": "affected", "assessment_status": "complete",
                                                  "confidence": "deterministic", "installed_version": "0.2.41",
                                                  "reason": "Test range contains installed version."}}],
            "unaffected": [], "not_assessed": [],
        },
    })
    recommendation = report["summary"]["recommendation"]
    prompt = render_review_prompt(report)
    assert '"status": "affected"' in prompt
    assert '"installed_version": "0.2.41"' in prompt
    assert '"fixed_versions": ["0.2.42"]' in prompt
    assert "langchain-core 0.2.41" in recommendation
    assert "affected range is available" in recommendation
    assert "fixed version available (0.2.42)" in recommendation
    assert "production source evidence direct_import" in recommendation
    assert "reachability unknown" in recommendation
    assert "do not establish vulnerable API reachability" in recommendation
    assert "exploitable" not in recommendation
    assert "deterministic affected installed version" in recommendation
    assert "Test evidence: base passed, PR passed" in recommendation
    assert "passing tests do not change the OSV affected-version assessment" in recommendation
    assert "No regression detected by the current test suite" in recommendation
    assert "langchain-core 0.2.41 (1 advisory record(s))" in recommendation
    comment = render_pr_comment(
        report,
        "The langchain-core 0.2.41 version is not vulnerable and is safe to merge.",
    )
    assert "Deterministic installed-version assessment" in comment
    assert "remaining (PR snapshot): 1 affected" in comment
    assert "not vulnerable and is safe to merge" not in comment


@pytest.mark.parametrize(("constraint_status", "constraint", "expected"), [
    ("complete", "^0.2.0", "conflict with recorded constraint(s)"),
    ("partial", "^0.2.0", "conflict with recorded constraint(s)"),
    ("partial", "*", "compatibility with parent constraints is unknown"),
])
def test_recommendation_never_suggests_fixed_version_that_conflicts_with_parent(constraint_status, constraint, expected):
    report = review._compact_review_report({
        "mode": "dependabot_pr_review", "status": "review_complete", "repository_full_name": "acme/demo",
        "pull_request": {"number": 5}, "files_changed": [],
        "dependency_changes": [{"package": "langchain-core", "ecosystem": "pypi", "base_version": "0.2.41",
                                "head_version": "0.2.43", "relationship": "transitive",
                                "dependency_paths": [["langchain", "langchain-core"]],
                                "upgrade_constraints": [{"parent": "langchain", "constraint": constraint}],
                                "upgrade_constraints_status": constraint_status}],
        "source_usage_status": "completed_without_matches", "source_usage": [],
        "base": {"tests": {"passed": True}, "security_scan": {"scan_status": "complete", "findings": [], "unresolved_packages": []}},
        "head": {"tests": {"passed": True}, "security_scan": {"scan_status": "complete", "findings": [], "unresolved_packages": []}},
        "security_delta": {"resolved": [], "introduced": [], "unaffected": [], "not_assessed": [],
                           "remaining": [{"id": "GHSA-TEST", "package": "langchain-core", "ecosystem": "PyPI",
                                          "version": "0.2.43", "fixed_versions": ["0.3.80"],
                                          "fixed_version_status": "available", "affected_range_status": "available",
                                          "version_assessment": {"status": "affected", "assessment_status": "complete",
                                                                 "confidence": "deterministic", "installed_version": "0.2.43",
                                                                 "reason": "Fixture range."}}]},
    })
    recommendation = report["summary"]["recommendation"]
    assert expected in recommendation
    if "conflict" in expected:
        assert "parent or coordinated dependency upgrade is needed" in recommendation
        assert "do not upgrade this package in isolation" in recommendation
        assert "langchain (^0.2.0)" in recommendation
        assert "no compatible coordinated version set is established by the available metadata" in recommendation


def test_source_usage_field_is_neutral_and_legacy_report_is_normalized():
    report = review._compact_review_report({
        "mode": "dependabot_pr_review", "status": "review_complete", "repository_full_name": "acme/demo",
        "pull_request": {"number": 6}, "files_changed": [], "dependency_changes": [],
        "source_usage_status": "completed_with_matches",
        "source_usage": [{"package": "demo", "ecosystem": "pypi", "relationship": "unknown",
                           "application_usage_classifications": ["test_only"],
                           "locations": [{"path": "tests/test_demo.py", "line_start": 8, "line_end": 8,
                                          "evidence_classification": "test_only"}]}],
        "base": {"tests": {"passed": True}, "security_scan": {"scan_status": "complete", "findings": [], "unresolved_packages": []}},
        "head": {"tests": {"passed": True}, "security_scan": {"scan_status": "complete", "findings": [], "unresolved_packages": []}},
        "security_delta": {"resolved": [], "introduced": [], "remaining": [], "unaffected": [], "not_assessed": []},
    })
    usage = report["source_usage"][0]
    assert usage["source_usage_classifications"] == ["test_only"]
    assert "application_usage_classifications" not in usage
    assert "production source evidence: not established" in render_pr_comment(report, "")
    assert "test evidence: test_only" in render_pr_comment(report, "")


def test_source_usage_classifications_come_from_serialized_locations_only():
    compact, = review._compact_source_usage([{
        "package": "cryptography", "ecosystem": "pypi",
        "source_usage_classifications": ["direct_import", "api_usage"],
        "locations": [{"path": "src/security.py", "line_start": 4, "line_end": 4,
                       "area": "application", "evidence_classification": "semantic_context",
                       "excerpt": "Build a secure transport configuration."}],
    }])
    assert compact["source_usage_classifications"] == ["semantic_context"]
    assert compact["evidence_classification"] == "semantic_context"
    comment = render_pr_comment({
        "dependency_changes": [], "summary": {"dependency_updates": [], "tests": {}, "osv": {}},
        "source_usage": [compact],
    }, "")
    assert "production source evidence: not established" in comment
    assert "other source evidence: semantic_context" in comment

    report = review._compact_review_report({
        "mode": "dependabot_pr_review", "status": "review_complete",
        "repository_full_name": "acme/demo", "pull_request": {"number": 12},
        "files_changed": [],
        "dependency_changes": [{"package": "cryptography", "ecosystem": "pypi",
                                "base_version": "43.0", "head_version": "44.0",
                                "relationship": "unknown", "dependency_paths": []}],
        "source_usage_status": "completed_with_matches", "source_usage": [compact],
        "base": {"tests": {"passed": True}, "security_scan": {"scan_status": "complete", "findings": [], "unresolved_packages": []}},
        "head": {"tests": {"passed": True}, "security_scan": {"scan_status": "complete", "findings": [], "unresolved_packages": []}},
        "security_delta": {"resolved": [], "introduced": [], "remaining": [], "unaffected": [], "not_assessed": []},
    })
    assert validate_evidence_report(report) is report
    inconsistent = json.loads(json.dumps(report))
    inconsistent["source_usage"][0]["source_usage_classifications"].append("direct_import")
    inconsistent["source_usage"][0]["evidence_classification"] = "direct_import"
    with pytest.raises(EvidenceReportValidationError, match="derived from recorded locations"):
        validate_evidence_report(inconsistent)

    no_location, = review._compact_source_usage([{
        "package": "cryptography", "ecosystem": "pypi",
        "source_usage_classifications": ["direct_import"], "locations": [],
    }])
    assert no_location["source_usage_classifications"] == ["no_evidence"]
    assert no_location["evidence_classification"] == "no_evidence"


def test_werkzeug_changed_dependency_is_consistent_in_summary_and_detail():
    report = review._compact_review_report({
        "mode": "dependabot_pr_review", "status": "review_complete", "repository_full_name": "acme/demo",
        "pull_request": {"number": 7}, "files_changed": [],
        "dependency_changes": [{"package": "werkzeug", "ecosystem": "pypi", "base_version": "3.0.0",
                                "head_version": "3.0.1", "relationship": "transitive",
                                "dependency_paths": [["flask", "werkzeug"]]}],
        "source_usage_status": "completed_without_matches", "source_usage": [],
        "base": {"tests": {"passed": True}, "security_scan": {"scan_status": "complete", "findings": [], "unresolved_packages": []}},
        "head": {"tests": {"passed": True}, "security_scan": {"scan_status": "complete", "findings": [], "unresolved_packages": []}},
        "security_delta": {"resolved": [], "introduced": [], "remaining": [], "unaffected": [], "not_assessed": []},
    })
    assert report["dependency_changes"][0]["package"] == "werkzeug"
    assert report["summary"]["dependency_updates"][0]["package"] == "werkzeug"
    assert report["summary"]["dependency_analyses"][0]["package"] == "werkzeug"
    assert validate_evidence_report(report) is report


def test_ai_narrative_cannot_attribute_global_remaining_count_to_one_package():
    report = {
        "security_delta": {
            "counts": {"remaining": 16},
            "remaining": [
                {"package": "langchain", "advisory_count": 4, "advisories": []},
                {"package": "langchain-core", "advisory_count": 12, "advisories": []},
            ],
        },
    }
    misleading = "There are 16 remaining advisory records indicating that langchain 0.2.17 is affected."
    corrected = "There are 16 remaining advisory records across langchain and langchain-core."

    assert _sanitize_ai_review(report, misleading) == ""
    assert _sanitize_ai_review(report, corrected) == corrected


def test_unchanged_dependency_findings_remain_affected_and_are_labeled_out_of_scope():
    finding = {
        "id": "GHSA-BASELINE", "finding_identity": "pypi:aiohttp:ghsa-baseline",
        "package": "aiohttp", "ecosystem": "PyPI", "version": "3.10.8", "installed_version": "3.10.8",
        "aliases": [], "affected_ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "3.14.1"}]}],
        "affected_versions": [], "version_assessment": {"status": "affected", "assessment_status": "complete",
            "confidence": "deterministic", "installed_version": "3.10.8", "reason": "Within affected range."},
    }
    report = review._compact_review_report({
        "mode": "dependabot_pr_review", "status": "review_complete", "repository_full_name": "acme/demo",
        "pull_request": {"number": 4}, "files_changed": [],
        "dependency_changes": [{"package": "langchain", "ecosystem": "pypi", "base_version": "0.2.16",
                                "head_version": "0.2.17", "relationship": "direct", "dependency_paths": [["langchain"]]}],
        "source_usage_status": "completed_without_matches", "source_usage": [],
        "base": {"tests": {"passed": True}, "security_scan": {"scan_status": "complete", "findings": [finding]}},
        "head": {"tests": {"passed": True}, "security_scan": {"scan_status": "complete", "findings": [finding]}},
        "security_delta": {"resolved": [], "introduced": [], "remaining": [], "unaffected": [finding], "not_assessed": []},
    })
    assert report["schema_version"] == 6
    assert report["security_delta"]["counts"]["unchanged_dependencies"] == 1
    assert report["security_delta"]["version_assessment_counts"]["unchanged_dependencies"]["affected"] == 1
    assert "unaffected" not in report["security_delta"]
    comment = render_pr_comment(report, "")
    assert "1 in unchanged dependencies (out of update scope)" in comment
    assert "unaffected" not in comment


def test_ai_review_does_not_turn_test_only_or_empty_clues_into_production_usage():
    report = {"source_usage": [{
        "package": "demo", "application_usage_classifications": ["test_only"],
        "locations": [{"path": "tests/test_agent.py", "line_start": 72, "evidence_classification": "test_only"}],
    }]}
    text = "Source Code Clues: 1. 2.\nThe application uses demo in production. Demo is used in production.\nOnly a test reference was found."
    clean = _sanitize_ai_review(report, text)
    assert "Source Code Clues" not in clean
    assert "uses demo in production" not in clean
    assert "is used in production" not in clean
    assert "Only a test reference was found." in clean


def test_ai_review_cannot_invent_upstream_release_explanation_after_lookup_failure():
    report = {"release_context": [{"package": "demo", "status": "lookup_failed", "error": "HTTPStatusError"}]}
    text = "The release notes explain why the dependency was replaced. The release notes were unavailable."
    clean = _sanitize_ai_review(report, text)
    assert "explain why" not in clean
    assert "release notes were unavailable" in clean

