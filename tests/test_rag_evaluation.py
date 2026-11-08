from __future__ import annotations

import json
from pathlib import Path

from evals.rag.evaluate import DATASET, ROOT, score_case, summarize


def test_rag_dataset_has_reproducible_ground_truth_mix():
    dataset = json.loads(DATASET.read_text(encoding="utf-8"))
    cases = dataset["cases"]
    assert 20 <= len(cases) <= 30
    assert len({case["id"] for case in cases}) == len(cases)
    assert {case["repository"] for case in cases} == {"patchpilot", "test_agents_fixture"}
    assert any(case.get("uncertain") for case in cases)
    assert any(case["expected_evidence_classification"] == "test_only" for case in cases)
    assert any(case["expected_evidence_classification"] == "configuration" for case in cases)
    assert any(case["expected_evidence_classification"] == "no_evidence" for case in cases)
    assert (ROOT / "evals/rag/fixtures/test-agents/LICENSE").is_file()


def test_precision_recall_and_mrr_use_labelled_locations():
    case = {
        "id": "two-labels", "dependency": "demo", "uncertain": False,
        "expected_evidence_classification": "api_usage", "relevant_evidence_exists": True,
        "expected_relevant_locations": [
            {"path": "src/a.py", "symbol": "a", "required_text": "api_call("},
            {"path": "src/b.py", "symbol": "b", "required_text": "other_call("},
        ],
    }
    results = [
        {"path": "src/nope.py", "symbol": "n", "content": "irrelevant"},
        {"path": "src/a.py", "symbol": "a", "content": "api_call()"},
        {"path": "src/other.py", "symbol": "o", "content": "other"},
    ]

    scored = score_case(case, results)

    assert scored["precision_at_5"] == 0.2
    assert scored["recall_at_5"] == 0.5
    assert scored["reciprocal_rank"] == 0.5
    assert scored["relevant_ranks"] == [2]


def test_no_evidence_false_positives_and_uncertain_cases_are_separate():
    no_evidence = {
        "id": "none", "dependency": "unused", "uncertain": False,
        "expected_evidence_classification": "no_evidence", "relevant_evidence_exists": False,
        "expected_relevant_locations": [],
    }
    uncertain = {
        "id": "uncertain", "dependency": "maybe", "uncertain": True,
        "expected_evidence_classification": "semantic_context", "relevant_evidence_exists": True,
        "expected_relevant_locations": [{"path": "a.py", "symbol": "f", "required_text": "x"}],
    }
    first = score_case(no_evidence, [{"path": "generic.py", "symbol": "f", "content": "generic"}])
    second = score_case(uncertain, [])
    summary = summarize([first, second])

    assert first["false_positive_results"] == 1
    assert first["recall_at_5"] is None and first["reciprocal_rank"] is None
    assert second["recall_at_5"] is None and second["reciprocal_rank"] is None
    assert summary["case_count"] == 2
    assert summary["scored_case_count"] == 1
    assert summary["uncertain_case_count"] == 1
    assert summary["without_relevant_evidence"] == 1
    assert summary["no_evidence_false_positive_case_count"] == 1
    assert summary["no_evidence_false_positive_result_count"] == 1


def test_category_summary_keeps_configuration_only_cases_separate():
    case = {
        "id": "config", "dependency": "mcp-server-git", "uncertain": False,
        "expected_evidence_classification": "configuration", "relevant_evidence_exists": False,
        "expected_relevant_locations": [],
    }
    summary = summarize([score_case(case, [])])

    assert summary["category_metrics"]["configuration"] == {
        "case_count": 1,
        "with_relevant_evidence": 0,
        "without_relevant_evidence": 1,
        "precision_at_5": 0.0,
        "recall_at_5": None,
        "mrr": None,
        "no_evidence_false_positive_results": 0,
    }
