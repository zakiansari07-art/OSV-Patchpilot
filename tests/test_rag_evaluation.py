from __future__ import annotations

import copy
import json

import pytest

from evals.rag.evaluate import (
    DATASET,
    ROOT,
    _load_sources,
    _repo_paths,
    score_case,
    summarize,
    validate_baseline,
    validate_dataset,
    validate_evaluation_ids,
)


@pytest.fixture
def dataset():
    return json.loads(DATASET.read_text(encoding="utf-8"))


@pytest.fixture
def source_context(dataset):
    roots = _repo_paths(dataset)
    sources = {name: _load_sources(path) for name, path in roots.items()}
    return roots, sources


def test_dataset_ids_match_recorded_baseline_and_have_no_duplicates(dataset):
    baseline = json.loads((DATASET.parent / "baseline.json").read_text(encoding="utf-8"))
    validate_evaluation_ids(dataset["cases"], baseline["cases"])
    assert len({case["id"] for case in dataset["cases"]}) == len(dataset["cases"])
    assert 20 <= len(dataset["cases"]) <= 30
    assert {case["repository"] for case in dataset["cases"]} == {"patchpilot", "test_agents_fixture"}
    assert any(case.get("uncertain") for case in dataset["cases"])
    assert (ROOT / "evals/rag/fixtures/test-agents/LICENSE").is_file()


def test_every_ground_truth_path_symbol_snippet_and_configuration_ref_is_valid(dataset, source_context):
    roots, sources = source_context
    validate_dataset(dataset["cases"], sources, roots)


def test_audited_cases_include_all_qdrant_pydantic_and_langgraph_locations(dataset):
    by_id = {case["id"]: case for case in dataset["cases"]}
    qdrant = by_id["qdrant-retriever"]["expected_relevant_locations"]
    qdrant_symbols = {item["symbol"] for item in qdrant}
    assert {
        "LocalCodeRetriever.__init__", "LocalCodeRetriever.index_sources",
        "LocalCodeRetriever._repo_filter", "LocalCodeRetriever._load_documents",
        "LocalCodeRetriever.retrieve",
    } <= qdrant_symbols
    assert "test_qdrant_local_index_searches_and_reloads_persisted_chunks" in qdrant_symbols
    pydantic = by_id["pydantic-report-models"]["expected_relevant_locations"]
    pydantic_symbols = {item["symbol"] for item in pydantic}
    assert {"_ReportModel", "ValidationRecord", "EvidenceReportV6",
            "validate_evidence_report", "evidence_report_json_schema"} <= pydantic_symbols
    graph = by_id["langgraph-remediation-graph"]["expected_relevant_locations"]
    assert len(graph) == 2
    assert any("graph.add_conditional_edges(" in item["required_text"] for item in graph)


def test_relevant_location_matching_counts_distinct_expected_locations():
    case = {
        "id": "two-labels", "dependency": "demo", "query": "demo use",
        "uncertain": False, "source_retrieval_eligible": True,
        "expected_evidence_classification": "api_usage",
        "expected_source_evidence_classification": "api_usage",
        "relevant_source_evidence_exists": True,
        "expected_relevant_locations": [
            {"path": "src/a.py", "symbol": "a", "required_text": "api_call(", "evidence_classification": "api_usage"},
            {"path": "src/b.py", "symbol": "b", "required_text": "other_call(", "evidence_classification": "api_usage"},
        ],
    }
    results = [
        {"path": "src/nope.py", "symbol": "n", "content": "irrelevant"},
        {"path": "src/a.py", "symbol": "a", "content": "api_call()"},
        {"path": "src/other.py", "symbol": "o", "content": "irrelevant"},
    ]

    scored = score_case(case, results)

    assert scored["precision_at_5"] == 0.2
    assert scored["recall_at_5"] == 0.5
    assert scored["reciprocal_rank"] == 0.5
    assert scored["relevant_ranks"] == [2]
    assert scored["matched_relevant_location_count"] == 1
    assert scored["non_relevant_results_at_5"] == 2
    assert scored["no_evidence_false_positive_results"] is None


def test_positive_case_reports_non_relevant_results_explicitly():
    case = {
        "id": "one-label", "dependency": "demo", "query": "demo use",
        "uncertain": False, "source_retrieval_eligible": True,
        "expected_evidence_classification": "api_usage",
        "expected_source_evidence_classification": "api_usage",
        "relevant_source_evidence_exists": True,
        "expected_relevant_locations": [
            {"path": "src/a.py", "symbol": "a", "required_text": "api_call(", "evidence_classification": "api_usage"},
        ],
    }
    scored = score_case(case, [
        {"path": "src/a.py", "symbol": "a", "content": "api_call()"},
        {"path": "tests/test_demo.py", "symbol": "t", "content": "mock"},
        {"path": "src/other.py", "symbol": "x", "content": "unrelated"},
    ])

    assert scored["precision_at_5"] == 0.2
    assert scored["non_relevant_results_at_5"] == 2


def test_negative_cases_have_false_positives_but_no_recall_or_mrr():
    case = {
        "id": "none", "dependency": "unused", "query": "unused",
        "uncertain": False, "source_retrieval_eligible": True,
        "expected_evidence_classification": "no_evidence",
        "expected_source_evidence_classification": "no_evidence",
        "relevant_source_evidence_exists": False, "expected_relevant_locations": [],
    }
    scored = score_case(case, [{"path": "generic.py", "symbol": "f", "content": "generic"}])
    summary = summarize([scored])

    assert scored["precision_at_5"] == 0.0
    assert scored["recall_at_5"] is None and scored["reciprocal_rank"] is None
    assert scored["non_relevant_results_at_5"] is None
    assert scored["no_evidence_false_positive_results"] == 1
    assert summary["no_evidence_false_positive_case_count"] == 1
    assert summary["no_evidence_false_positive_results"] == 1


def test_configuration_only_case_is_checked_outside_source_metrics(dataset, source_context):
    roots, sources = source_context
    validate_dataset(dataset["cases"], sources, roots)
    case = next(item for item in dataset["cases"] if item["id"] == "mcp-server-git-config-only")
    scored = score_case(case, [{"path": "mcp_client.py", "symbol": "MCPClient._config", "content": "config"}])

    assert case["expected_evidence_classification"] == "configuration"
    assert case["expected_source_evidence_classification"] == "no_evidence"
    assert case["configuration_evidence_exists"] is True
    assert case["source_retrieval_eligible"] is False
    assert scored["precision_at_5"] is None
    assert scored["no_evidence_false_positive_results"] is None
    assert scored["configuration_evidence_validated"] is True
    assert all(result["relevant"] is None for result in scored["retrieved"])


def test_uncertain_case_is_excluded_from_aggregate_metrics():
    case = {
        "id": "uncertain", "dependency": "maybe", "query": "maybe",
        "uncertain": True, "source_retrieval_eligible": True,
        "expected_evidence_classification": "semantic_context",
        "expected_source_evidence_classification": "semantic_context",
        "relevant_source_evidence_exists": True,
        "expected_relevant_locations": [
            {"path": "a.py", "symbol": "f", "required_text": "context", "evidence_classification": "semantic_context"},
        ],
    }
    scored = score_case(case, [{"path": "a.py", "symbol": "f", "content": "context"}])
    summary = summarize([scored])

    assert scored["precision_at_5"] == 0.2
    assert scored["recall_at_5"] is None and scored["reciprocal_rank"] is None
    assert summary["scored_source_retrieval_case_count"] == 0
    assert summary["precision_at_5"] is None
    assert summary["recall_at_5"] is None and summary["mrr"] is None


def test_missing_or_duplicate_evaluation_results_fail_clearly(dataset):
    one = dataset["cases"][:1]
    with pytest.raises(ValueError, match="missing=.*httpx-osv-query"):
        validate_evaluation_ids(one, [])
    with pytest.raises(ValueError, match="duplicate case ids"):
        validate_evaluation_ids(one, [one[0], one[0]])


def test_saved_baseline_scores_recompute_from_raw_chunks_and_aggregate(dataset):
    baseline = json.loads((DATASET.parent / "baseline.json").read_text(encoding="utf-8"))
    validate_baseline(dataset, baseline)
    changed = copy.deepcopy(baseline)
    changed["cases"][0]["precision_at_5"] = 1.0
    with pytest.raises(ValueError, match="raw retrieved chunks"):
        validate_baseline(dataset, changed)


def test_missing_case_from_baseline_fails_with_actionable_error(dataset):
    baseline = json.loads((DATASET.parent / "baseline.json").read_text(encoding="utf-8"))
    baseline["cases"].pop()
    with pytest.raises(ValueError, match="missing="):
        validate_baseline(dataset, baseline)


def test_category_summary_keeps_configuration_outside_source_categories():
    dataset = json.loads(DATASET.read_text(encoding="utf-8"))
    report = json.loads((DATASET.parent / "baseline.json").read_text(encoding="utf-8"))
    validate_baseline(dataset, report)
    summary = report["summary"]
    assert summary["configuration_only_case_count"] == 1
    assert "configuration" not in summary["category_metrics"]
    assert summary["with_relevant_source_evidence"] == 24
    assert summary["without_relevant_source_evidence"] == 4
