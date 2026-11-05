import json
from pathlib import Path
from unittest.mock import Mock

import pytest

from vulnerability_agent.report_validation import (
    EvidenceReportValidationError,
    evidence_report_json_schema,
    validate_evidence_report,
)
from vulnerability_agent.review_graph import build_dependabot_review_graph


FIXTURES = Path(__file__).parent / "fixtures" / "dependabot_reports"


def load_report(name):
    return json.loads((FIXTURES / f"{name}.json").read_text())


class FakeReviewModel:
    def invoke(self, _messages):
        return Mock(content="Evidence reviewed. See the structured findings and remaining uncertainty above.")


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
    comment = run_production_comment_path(load_report("weak_rag_evidence"))
    assert "semantic_context" in comment
    assert "none establishes vulnerable code reachability" in comment
    assert "does not establish aiohttp usage" in comment


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
    assert schema["properties"]["schema_version"]["const"] == 3
    assert {"schema_version", "mode", "status", "summary", "pull_request", "security_delta"} <= set(schema["required"])
    json.dumps(schema)

