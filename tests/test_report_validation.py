import json
import gzip
from pathlib import Path
from unittest.mock import Mock

import pytest

from vulnerability_agent.report_validation import (
    EvidenceReportValidationError,
    evidence_report_json_schema,
    report_validation_observability,
    validate_evidence_report,
)
from vulnerability_agent.review_graph import build_dependabot_review_graph, render_review_prompt


FIXTURES = Path(__file__).parent / "fixtures" / "dependabot_reports"


def load_report(name):
    path = FIXTURES / name
    if not path.suffix:
        path = path.with_suffix(".json")
    if path.suffix == ".gz":
        return json.loads(gzip.decompress(path.read_bytes()))
    return json.loads(path.read_text())


class FakeReviewModel:
    def invoke(self, _messages):
        return Mock(content=(
            "All functionality remains intact. The repository is secure. "
            "The release notes prove compatibility."
        ))


class FakeGitHub:
    def __init__(self):
        self.body = None

    def get(self, _url):
        response = Mock()
        response.json.return_value = []
        response.raise_for_status.return_value = None
        return response

    def post(self, _url, *, json):
        self.body = json["body"]
        response = Mock()
        response.json.return_value = {"html_url": "https://github.com/acme/demo/pull/17#issuecomment-1"}
        response.raise_for_status.return_value = None
        return response


def run_production_comment_path(report):
    github = FakeGitHub()
    graph = build_dependabot_review_graph(github_client=github, model=FakeReviewModel())
    state = graph.invoke({"report": report, "post_comment": True})
    assert state.get("comment_url", "").startswith("https://github.com/acme/demo/")
    assert state["report"]["validation"]["status"] == "passed"
    assert github.body
    return github.body


@pytest.mark.parametrize(
    "name",
    [
        "actions_only",
        "dependency_resolves",
        "dependency_introduces",
        "vulnerability_remaining",
        "weak_rag_evidence",
        "incomplete_osv_scan",
    ],
)
def test_saved_reports_validate_and_use_production_comment_path(name):
    report = load_report(name)
    assert validate_evidence_report(report) is report
    comment = run_production_comment_path(report)
    assert "## Dependabot review summary" in comment
    assert "**Test results**" in comment
    assert "**Security impact**" in comment
    assert "**Remaining uncertainty**" in comment or report["summary"].get("osv_scan_status", {}).get("base") == "complete"
    assert "safe to merge" not in comment.casefold()


def test_actions_only_comment_keeps_lockfile_findings_as_baseline_context():
    comment = run_production_comment_path(load_report("actions_only"))
    assert "actions/setup-python" in comment and "v5" in comment and "v7" in comment
    assert "Dependency changes detected: no" in comment
    assert "No Python dependency changes were detected" in comment
    assert "Unaffected repository findings: 1" in comment
    assert "unaffected findings are repository baseline findings" in comment
    assert "GitHub Action version itself was not assessed" in comment
    assert "Passing Python tests do not establish GitHub Actions workflow compatibility" in comment
    assert "Introduced findings: 0" in comment
    assert "Resolved findings: 0" in comment


def test_resolved_introduced_and_remaining_classifications_are_preserved():
    expectations = {
        "dependency_resolves": ("Resolved findings: 1", "requests", "PYSEC-2023-1"),
        "dependency_introduces": ("Introduced findings: 1", "urllib3", "GHSA-2024-0001"),
        "vulnerability_remaining": ("Remaining findings: 1", "urllib3", "GHSA-2024-0001"),
    }
    for name, expected in expectations.items():
        report = load_report(name)
        comment = run_production_comment_path(report)
        assert expected[0] in comment
        assert expected[1] in comment
        assert expected[2] in json.dumps(report["security_delta"])
        assert "No regression detected" in comment


def test_weak_rag_evidence_is_labeled_as_semantic_context():
    report = load_report("weak_rag_evidence")
    report["summary"]["source_usage"]["retrieval_status"] = "completed_with_matches"
    comment = run_production_comment_path(report)
    assert "semantic_context" in comment
    assert "none establishes vulnerable code reachability" in comment
    assert "does not establish aiohttp usage" in comment


def test_zero_locations_with_completed_retrieval_are_distinct_from_not_executed():
    report = load_report("pr10_sendgrid_report.json.gz")
    report["summary"]["source_usage"].update({
        "retrieval_status": "completed_without_matches",
        "reason": None,
    })
    report["validation"] = report_validation_observability(report)
    comment = run_production_comment_path(report)
    assert "Source retrieval completed without matches" in comment
    assert "does not establish that changed packages are unused" in comment
    assert "Source retrieval was not executed" not in comment


def test_failed_source_retrieval_is_explicit_and_nonfatal():
    report = load_report("pr10_sendgrid_report.json.gz")
    report["summary"]["source_usage"].update({
        "retrieval_status": "failed",
        "error": "Vector store was unavailable.",
    })
    report["validation"] = report_validation_observability(report)
    comment = run_production_comment_path(report)
    assert "Source retrieval failed: Vector store was unavailable" in comment
    assert "package usage is unknown" in comment
    assert report["validation"]["status"] == "passed"
    assert any("Source retrieval failed" in warning for warning in report["validation"]["warnings"])


def test_incomplete_osv_scan_is_not_rendered_as_zero_findings():
    report = load_report("incomplete_osv_scan")
    comment = run_production_comment_path(report)
    assert "Not assessed findings: 1" in comment
    assert "Introduced findings: unknown (scan incomplete)" in comment
    assert "Resolved findings: unknown (scan incomplete)" in comment
    assert "OSV scan status is incomplete" in comment
    assert "Not assessed details: PR snapshot OSV scan failed" in comment


def test_validation_rejects_malformed_reports_but_keeps_incomplete_reports_valid():
    report = load_report("actions_only")
    del report["security_delta"]["counts"]["introduced"]
    with pytest.raises(EvidenceReportValidationError):
        validate_evidence_report(report)

    report = load_report("incomplete_osv_scan")
    assert validate_evidence_report(report)["osv_scans"]["pr"]["status"] == "failed"


@pytest.mark.parametrize(
    ("mutator", "message"),
    [
        (lambda r: r.pop("pull_request"), "pull_request"),
        (lambda r: r["security_delta"]["counts"].update(introduced=-1), "greater than or equal to 0"),
        (lambda r: r["source_usage"][0].update(evidence_classification="confirmed_use"), "evidence_classification"),
        (lambda r: r["dependency_changes"][0].update(relationship="guessed"), "relationship"),
    ],
)
def test_validation_rejects_missing_identifiers_and_invalid_enum_values(mutator, message):
    report = load_report("weak_rag_evidence" if message == "evidence_classification" else "dependency_resolves")
    mutator(report)
    with pytest.raises(EvidenceReportValidationError, match=message):
        validate_evidence_report(report)


def test_published_json_schema_is_machine_readable_and_requires_core_fields():
    schema = evidence_report_json_schema()
    assert schema["properties"]["schema_version"]["const"] == 4
    assert {"schema_version", "mode", "status", "summary", "pull_request", "security_delta"} <= set(schema["required"])
    json.dumps(schema)


def test_schema_v4_accepts_new_source_areas_while_v3_contract_remains_strict():
    report = load_report("weak_rag_evidence")
    location = report["source_usage"][0]["locations"][0]
    report["schema_version"] = 4
    location["area"] = "configuration"
    assert validate_evidence_report(report) is report

    report["schema_version"] = 3
    with pytest.raises(EvidenceReportValidationError, match="v4 area classifications"):
        validate_evidence_report(report)


def test_pr10_sendgrid_report_regression_uses_precise_counts_release_evidence_and_unknowns():
    report = load_report("pr10_sendgrid_report.json.gz")
    assert validate_evidence_report(report) is report
    assert report["validation"]["status"] == "passed"
    assert report["validation"]["schema_version"] == 3
    assert any("Upstream release notes provide context" in warning for warning in report["validation"]["warnings"])

    comment = run_production_comment_path(report)
    assert "350 package-advisory findings across 25 package groups and 349 unique advisory IDs" in comment
    assert "No OSV findings were identified for the changed dependencies" in comment
    assert "starkbank-ecdsa" in comment and "removed" in comment
    assert "cryptography" in comment and "added" in comment
    assert "Replace ecdsa with cryptography" in comment
    assert "sendgrid-python/pull/1114" in comment
    assert "Source retrieval was not executed" in comment
    assert "package usage is unknown" in comment
    assert "Application-level compatibility remains unverified" in comment
    assert "Passing tests apply to the tested suite and do not prove all application behavior remains compatible" in comment
    assert "Review recommended:" in comment
    assert "repository is secure" not in comment.casefold()
    assert "All functionality remains intact" not in comment
    assert "release notes prove compatibility" not in comment.casefold()

    prompt = render_review_prompt(report)
    assert len(prompt) <= 16_000
    assert "Replace ecdsa with cryptography" in prompt
    assert "count_semantics" in prompt
    assert "retrieval_status" in prompt


def test_report_validation_observability_records_nonblocking_warnings():
    report = load_report("pr10_sendgrid_report.json.gz")
    warnings = report["validation"]["warnings"]
    assert any("Source retrieval was not executed" in warning for warning in warnings)
    assert any("Pre-existing package-advisory findings remain" in warning for warning in warnings)


def test_validation_failure_observability_keeps_sanitized_errors():
    from vulnerability_agent.report_validation import report_validation_observability

    report = load_report("pr10_sendgrid_report.json.gz")
    report["security_delta"]["counts"]["unaffected"] = 0
    with pytest.raises(EvidenceReportValidationError) as captured:
        validate_evidence_report(report)
    result = report_validation_observability(
        report, status="failed", errors=[str(captured.value)],
    )
    assert result["status"] == "failed"
    assert result["schema_version"] == 3
    assert result["errors"]
    assert "input_value" not in result["errors"][0]

