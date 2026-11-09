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
    assert "showing" not in body
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
    assert "`src/core_1.py:1-1`" in body
    assert "`langchain-core`, direct import" in body
    assert "`src/core_2.py:2-2`" in body


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
    assert "test evidence: test only" in render_pr_comment(report, "")


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
    assert "other source evidence: semantic context" in comment

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
    assert "1 pre-existing records in unchanged dependencies (out of scope)" in comment
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

