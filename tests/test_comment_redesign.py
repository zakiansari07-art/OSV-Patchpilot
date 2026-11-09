"""Contracts for the deterministic PR comment redesign."""
from __future__ import annotations

from vulnerability_agent import dependabot_review as review
from vulnerability_agent.review_graph import render_pr_comment
from vulnerability_agent.workflow.formatting import (
    advisory_link,
    code_permalink,
    severity_label,
)
from vulnerability_agent.workflow.insights import derive_verdict


def _advisory(index: int, package: str, version: str, fixed=("0.3.80", "1.0.7")):
    return {
        "id": f"GHSA-{index:04d}-abcd-efgh",
        "package": package,
        "ecosystem": "PyPI",
        "version": version,
        "installed_version": version,
        "summary": f"Advisory {index} summary",
        "severity": [{
            "type": "CVSS_V3",
            "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        }],
        "severity_status": "available",
        "affected_ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "0.3.80"}]}],
        "affected_range_status": "available",
        "fixed_versions": list(fixed),
        "fixed_version_status": "available",
        "version_assessment": {
            "status": "affected", "assessment_status": "complete",
            "confidence": "deterministic", "installed_version": version,
            "reason": "Within range.",
        },
        "aliases": [f"CVE-2025-{1000 + index}"],
        "manifest_files": ["poetry.lock"],
        "relationship": "transitive",
        "dependency_paths": [["langchain", "langchain-core"]],
    }


def _langchain_report():
    changes = [
        {"package": "langchain", "ecosystem": "pypi", "base_version": "0.2.16",
         "head_version": "0.2.17", "relationship": "direct", "dependency_paths": [["langchain"]],
         "upgrade_constraints": [{"parent": "project", "constraint": "^0.2.0", "source": "pyproject.toml"}],
         "upgrade_constraints_status": "complete"},
        {"package": "langchain-core", "ecosystem": "pypi", "base_version": "0.2.41",
         "head_version": "0.2.43", "relationship": "transitive",
         "dependency_paths": [["langchain", "langchain-core"]],
         "upgrade_constraints": [{"parent": "langchain", "constraint": "^0.2.0", "source": "poetry.lock"}],
         "upgrade_constraints_status": "complete"},
    ]
    remaining = [_advisory(i, "langchain-core", "0.2.43") for i in range(1, 17)]
    resolved = [_advisory(100 + i, "langchain", "0.2.16", fixed=()) for i in range(2)]
    unaffected = [_advisory(200 + i, "aiohttp", "3.10.8") for i in range(332)]
    return review._compact_review_report({
        "mode": "dependabot_pr_review", "status": "review_complete",
        "repository_full_name": "acme/demo",
        "pull_request": {"number": 14, "head_sha": "5178523a7a279ec57c0b8120d00c721894bed3d1"},
        "files_changed": [], "dependency_changes": changes,
        "source_usage_status": "completed_with_matches",
        "source_usage": [{
            "package": "langchain", "ecosystem": "pypi", "relationship": "direct",
            "dependency_paths": [["langchain"]], "advisory_ids": [],
            "locations": [
                {"path": "agents/tools/flights_finder.py", "line_start": 10,
                 "line_end": 18, "area": "application", "evidence_classification": "api_usage"},
                {"path": "agents/tools/search.py", "line_start": 22,
                 "line_end": 25, "area": "application", "evidence_classification": "direct_import"},
            ],
        }],
        "base": {"tests": {"passed": True, "returncode": 0, "output": "11 passed"},
                 "security_scan": {"scan_status": "complete", "findings": [], "unresolved_packages": []}},
        "head": {"tests": {"passed": True, "returncode": 0, "output": "11 passed"},
                 "security_scan": {"scan_status": "complete", "findings": [], "unresolved_packages": []}},
        "security_delta": {
            "resolved": resolved, "introduced": [], "remaining": remaining,
            "unaffected": unaffected, "not_assessed": [],
        },
    })


def test_comment_has_one_verdict_one_test_line_and_scannable_evidence():
    report = _langchain_report()
    body = render_pr_comment(report, "The update is routine.")

    assert body.count("**Tests:**") == 1
    assert "A passing base and failing PR" not in body
    assert "**Verdict: ⚠️ Investigate before merging**" in body
    assert "| Change | Version | Relationship |" in body
    assert "| `langchain` | `0.2.16` → `0.2.17` | direct |" in body
    assert "transitive (via `langchain`)" in body
    assert "0 introduced · 2 resolved · 16 remain in changed dependencies" in body
    assert "332 pre-existing records in unchanged dependencies (out of scope)" in body
    assert "critical (9.8)" in body
    assert "https://osv.dev/vulnerability/GHSA-0001-abcd-efgh" in body
    assert (
        "https://github.com/acme/demo/blob/5178523a7a279ec57c0b8120d00c721894bed3d1/"
        "agents/tools/flights_finder.py#L10-L18"
    ) in body
    assert "direct import" in body
    assert "direct_import" not in body
    assert "**Next step:**" in body
    assert "coordinated dependency upgrade is required" in body
    assert "showing" not in body

    visible = body.split("<details>")[0]
    assert len(visible) <= 2_600
    assert "Full evidence" in body
    assert "AI review" in body


def test_compare_tests_notes_are_classification_specific():
    passed = {"passed": True, "returncode": 0}
    failed = {"passed": False, "returncode": 1, "output": "FAILED test_a - boom"}

    both = review._compare_tests(passed, passed)
    assert both["classification"] == "passed_on_base_and_pr"
    assert "no regression detected" in both["note"]
    assert "passing base and failing PR" not in both["note"]

    regression = review._compare_tests(passed, failed)
    assert regression["classification"] == "failure_introduced_or_exposed_by_pr"
    assert "passing base and failing PR" in regression["note"]

    recovered = review._compare_tests(failed, passed)
    assert recovered["classification"] == "pr_passed_base_failed"
    assert "PR snapshot" in recovered["note"]

    unavailable = review._compare_tests({}, passed)
    assert unavailable["classification"] == "test_environment_unavailable"
    assert "environment or test runner" in unavailable["note"]

    persists = review._compare_tests(failed, failed)
    assert persists["classification"] == "baseline_failure_persists"
    assert "same test failures" in persists["note"]


def test_verdict_selection_is_conservative_and_deterministic():
    routine = {
        "dependency_changes": [{"package": "demo"}],
        "test_comparison": {"classification": "passed_on_base_and_pr",
                            "base_passed": True, "pr_passed": True},
        "security_delta": {"counts": {"introduced": 0, "resolved": 1, "remaining": 0,
                                      "unchanged_dependencies": 0, "not_assessed": 0},
                           "version_assessment_counts": {}},
        "summary": {"source_usage": {"status": "completed_with_matches"}},
    }
    assert derive_verdict(routine) == "routine_update"

    investigate = {
        **routine,
        "security_delta": {
            "counts": {"introduced": 0, "resolved": 0, "remaining": 1,
                       "unchanged_dependencies": 0, "not_assessed": 0},
            "version_assessment_counts": {"remaining": {"affected": 1, "not_affected": 0, "unknown": 0}},
        },
    }
    assert derive_verdict(investigate) == "investigate_before_merging"

    block = {
        **routine,
        "security_delta": {
            "counts": {"introduced": 1, "resolved": 0, "remaining": 0,
                       "unchanged_dependencies": 0, "not_assessed": 0},
            "version_assessment_counts": {"introduced": {"affected": 1, "not_affected": 0, "unknown": 0}},
        },
    }
    assert derive_verdict(block) == "do_not_merge_yet"

    regression = {**routine, "test_comparison": {
        "classification": "failure_introduced_or_exposed_by_pr",
        "base_passed": True, "pr_passed": False,
    }}
    assert derive_verdict(regression) == "do_not_merge_yet"


def test_severity_links_and_permalinks_are_bounded():
    critical = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    medium = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N"
    assert severity_label([{"type": "CVSS_V3", "score": critical}]) == ("critical", 9.8)
    assert severity_label([{"type": "CVSS_V3", "score": medium}])[0] == "medium"
    assert severity_label([]) == ("unavailable", None)

    assert advisory_link({"id": "GHSA-abcd"}) == "https://osv.dev/vulnerability/GHSA-abcd"
    assert advisory_link({"id": "GHSA-abcd", "url": "https://example.test/a"}) == "https://example.test/a"

    report = {
        "repository_full_name": "acme/demo",
        "pull_request": {"head_sha": "a" * 40},
    }
    location = {"path": "src/a b.py", "line_start": 3, "line_end": 5}
    assert code_permalink(report, location) == (
        "https://github.com/acme/demo/blob/" + "a" * 40 + "/src/a%20b.py#L3-L5"
    )
    assert code_permalink({**report, "pull_request": {}}, location) is None
    assert code_permalink(report, {"path": "../.env", "line_start": 1}) is None


def test_advisory_and_location_truncation_is_explicit():
    report = _langchain_report()
    body = render_pr_comment(report, "")
    assert "+13 more in the full evidence below" in body

    many_locations = {
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
    body = render_pr_comment(many_locations, "")
    assert "showing 6 of 9" in body


def test_comment_stays_complete_when_ai_review_is_empty():
    report = _langchain_report()
    body = render_pr_comment(report, "")
    assert "**Verdict:" in body
    assert "**Next step:**" in body
    assert "<details>" in body
    assert "AI review" not in body
