"""Repeatable offline evaluation for the existing hybrid code retriever.

This harness does not alter retrieval configuration or ranking. It builds a
temporary local Qdrant index with the application's configured FastEmbed model
and evaluates the versioned, manually labelled cases in ``cases.json``.
"""
from __future__ import annotations

import json
import sys
import tempfile
from collections import defaultdict
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from vulnerability_agent.retrieval import (  # noqa: E402
    DEFAULT_EMBEDDING_MODEL,
    LocalCodeRetriever,
    chunk_source,
)

DATASET = Path(__file__).with_name("cases.json")
TOP_K = 5
EXCLUDED_DIRS = {".git", ".venv", "venv", "node_modules", "__pycache__", "saved report", "evals"}


def _repo_paths(dataset: dict[str, Any]) -> dict[str, Path]:
    return {
        name: (ROOT / path).resolve()
        for name, path in dataset["repositories"].items()
    }


def _load_sources(repository: Path) -> dict[str, str]:
    sources: dict[str, str] = {}
    for path in sorted(repository.rglob("*")):
        if not path.is_file() or path.suffix.lower() not in {".py", ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"}:
            continue
        relative = path.relative_to(repository)
        if set(relative.parts) & EXCLUDED_DIRS:
            continue
        try:
            sources[relative.as_posix()] = path.read_text(encoding="utf-8")
        except (OSError, UnicodeError):
            continue
    return sources


def _ground_truth_is_valid(case: dict[str, Any], sources_by_repo: dict[str, dict[str, str]]) -> None:
    """Fail if a manual label points to a missing path/symbol/snippet."""
    sources = sources_by_repo[case["repository"]]
    for expected in case["expected_relevant_locations"]:
        source = sources.get(expected["path"])
        if source is None:
            raise ValueError(f"{case['id']}: ground-truth source missing: {expected['path']}")
        chunks = chunk_source(expected["path"], source)
        matching = [chunk for chunk in chunks if chunk["symbol"] == expected["symbol"]]
        if not any(expected["required_text"] in chunk["content"] for chunk in matching):
            raise ValueError(
                f"{case['id']}: ground-truth symbol/snippet not found in current source: "
                f"{expected['path']}::{expected['symbol']}"
            )
    for expected in case.get("configuration_references", []):
        path = ROOT / expected["path"] if case["repository"] == "patchpilot" else _repo_paths({
            "repositories": {case["repository"]: "evals/rag/fixtures/test-agents"}
        })[case["repository"]] / expected["path"]
        if not path.is_file() or expected["required_text"] not in path.read_text(encoding="utf-8"):
            raise ValueError(f"{case['id']}: configuration ground truth is missing")


def _is_relevant(result: dict[str, Any], expected_locations: list[dict[str, str]]) -> bool:
    for expected in expected_locations:
        if result.get("path") != expected["path"] or result.get("symbol") != expected["symbol"]:
            continue
        if expected["required_text"] in str(result.get("content", "")):
            return True
    return False


def _mean(values: list[float]) -> float | None:
    return sum(values) / len(values) if values else None


def score_case(case: dict[str, Any], results: list[dict[str, Any]]) -> dict[str, Any]:
    relevant = [
        index for index, result in enumerate(results, start=1)
        if _is_relevant(result, case["expected_relevant_locations"])
    ]
    expected_count = len(case["expected_relevant_locations"])
    uncertain = bool(case.get("uncertain"))
    return {
        "id": case["id"],
        "dependency": case["dependency"],
        "expected_evidence_classification": case["expected_evidence_classification"],
        "uncertain": uncertain,
        "relevant_evidence_exists": bool(case["relevant_evidence_exists"]),
        "expected_relevant_count": expected_count,
        "returned_count": len(results),
        "relevant_ranks": relevant,
        "precision_at_5": len(relevant) / TOP_K,
        "recall_at_5": (len(relevant) / expected_count) if expected_count and not uncertain else None,
        "reciprocal_rank": (1 / relevant[0]) if relevant and not uncertain else (0.0 if expected_count and not uncertain else None),
        "false_positive_results": (len(results) - len(relevant)) if not expected_count else 0,
        "retrieved": [
            {"rank": index, "path": item.get("path"), "line_start": item.get("line_start"),
             "line_end": item.get("line_end"), "symbol": item.get("symbol"),
             "relevant": _is_relevant(item, case["expected_relevant_locations"])}
            for index, item in enumerate(results, start=1)
        ],
    }


def summarize(case_results: list[dict[str, Any]]) -> dict[str, Any]:
    eligible = [item for item in case_results if not item["uncertain"]]
    evidence_cases = [item for item in eligible if item["expected_relevant_count"] > 0]
    no_evidence_cases = [item for item in eligible if item["expected_relevant_count"] == 0]
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for item in eligible:
        grouped[item["expected_evidence_classification"]].append(item)
    category_metrics = {}
    for category, items in sorted(grouped.items()):
        category_positive = [item for item in items if item["expected_relevant_count"] > 0]
        category_negative = [item for item in items if item["expected_relevant_count"] == 0]
        category_metrics[category] = {
            "case_count": len(items),
            "with_relevant_evidence": len(category_positive),
            "without_relevant_evidence": len(category_negative),
            "precision_at_5": _mean([item["precision_at_5"] for item in items]),
            "recall_at_5": _mean([item["recall_at_5"] for item in category_positive]),
            "mrr": _mean([item["reciprocal_rank"] for item in category_positive]),
            "no_evidence_false_positive_results": sum(item["false_positive_results"] for item in category_negative),
        }
    return {
        "case_count": len(case_results),
        "scored_case_count": len(eligible),
        "uncertain_case_count": len(case_results) - len(eligible),
        "with_relevant_evidence": len(evidence_cases),
        "without_relevant_evidence": len(no_evidence_cases),
        "precision_at_5": _mean([item["precision_at_5"] for item in eligible]),
        "recall_at_5": _mean([item["recall_at_5"] for item in evidence_cases]),
        "mrr": _mean([item["reciprocal_rank"] for item in evidence_cases]),
        "no_evidence_false_positive_case_count": sum(bool(item["false_positive_results"]) for item in no_evidence_cases),
        "no_evidence_false_positive_result_count": sum(item["false_positive_results"] for item in no_evidence_cases),
        "category_metrics": category_metrics,
    }


def evaluate(output: Path | None = None) -> dict[str, Any]:
    dataset = json.loads(DATASET.read_text(encoding="utf-8"))
    repositories = _repo_paths(dataset)
    sources_by_repo = {name: _load_sources(path) for name, path in repositories.items()}
    for case in dataset["cases"]:
        _ground_truth_is_valid(case, sources_by_repo)

    # The ephemeral local index makes each run independent and prevents a
    # stale persisted repository snapshot from affecting the measured result.
    with tempfile.TemporaryDirectory(prefix="patchpilot-rag-eval-") as temp_dir:
        retriever = LocalCodeRetriever(Path(temp_dir) / "qdrant", embedding_model=DEFAULT_EMBEDDING_MODEL)
        for name, sources in sources_by_repo.items():
            retriever.index_sources(repositories[name], sources, snapshot_id="rag-eval-v1")
        case_results = []
        for case in dataset["cases"]:
            retrieved = retriever.retrieve(repositories[case["repository"]], case["query"], limit=TOP_K)
            case_results.append(score_case(case, retrieved))

    result = {
        "evaluation_version": 1,
        "dataset_version": dataset["dataset_version"],
        "retriever": "LocalCodeRetriever",
        "embedding_model": DEFAULT_EMBEDDING_MODEL,
        "retrieval_limit": TOP_K,
        "metric_definitions": {
            "precision_at_5": "Relevant results in the returned ranking divided by 5; unavailable slots count as non-relevant.",
            "recall_at_5": "Distinct labelled locations retrieved in top 5 divided by labelled relevant locations; no-evidence and uncertain cases excluded.",
            "mrr": "Mean reciprocal rank of the first relevant result over evidence-positive cases; no-evidence and uncertain cases excluded.",
            "uncertain_cases": "Reported per-case but excluded from aggregate relevance metrics.",
        },
        "summary": summarize(case_results),
        "cases": case_results,
    }
    if output:
        output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return result


if __name__ == "__main__":
    destination = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).with_name("baseline.json")
    measured = evaluate(destination)
    print(json.dumps(measured["summary"], indent=2, sort_keys=True))
    print(f"Per-case results written to {destination}")
