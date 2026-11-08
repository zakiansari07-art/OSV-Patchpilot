"""Repeatable evaluation for the existing hybrid code retriever."""
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

DATASET = Path(__file__).with_name("cases-v3.json")
BASELINE = Path(__file__).with_name("baseline-v3.json")
EVALUATION_VERSION = 3
TOP_K = 5
EXCLUDED_DIRS = {".git", ".venv", "venv", "node_modules", "__pycache__", "saved report", "evals"}
EVIDENCE_CLASSES = {
    "direct_import", "api_usage", "test_only", "configuration",
    "semantic_context", "no_evidence",
}
SOURCE_EVIDENCE_CLASSES = EVIDENCE_CLASSES - {"configuration"}
METRIC_FIELDS = {
    "source_retrieval_eligible", "expected_relevant_count", "relevant_retrieved_count",
    "relevant_source_evidence_exists", "returned_count", "relevant_ranks",
    "matched_relevant_location_count", "precision_at_5", "recall_at_5",
    "reciprocal_rank", "non_relevant_results_at_5", "no_evidence_false_positive_results",
    "configuration_evidence_validated",
}


def _repo_paths(dataset: dict[str, Any]) -> dict[str, Path]:
    return {name: (ROOT / path).resolve() for name, path in dataset["repositories"].items()}


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


def validate_dataset(
    cases: list[dict[str, Any]],
    sources_by_repo: dict[str, dict[str, str]],
    repository_roots: dict[str, Path],
) -> None:
    """Validate labels against source, and reject incomplete/duplicated labels."""
    ids = [case.get("id") for case in cases]
    if any(not case_id for case_id in ids):
        raise ValueError("Every evaluation case must have a non-empty id")
    duplicates = sorted({case_id for case_id in ids if ids.count(case_id) > 1})
    if duplicates:
        raise ValueError(f"Duplicate dataset case ids: {duplicates}")

    for case in cases:
        case_id = case["id"]
        repository = case.get("repository")
        if repository not in sources_by_repo:
            raise ValueError(f"{case_id}: unknown repository {repository!r}")
        evidence_class = case.get("expected_evidence_classification")
        source_class = case.get("expected_source_evidence_classification")
        if evidence_class not in EVIDENCE_CLASSES:
            raise ValueError(f"{case_id}: invalid expected evidence classification {evidence_class!r}")
        if source_class not in SOURCE_EVIDENCE_CLASSES:
            raise ValueError(f"{case_id}: invalid source evidence classification {source_class!r}")
        locations = case.get("expected_relevant_locations")
        if not isinstance(locations, list):
            raise ValueError(f"{case_id}: expected_relevant_locations must be a list")
        source_exists = bool(locations)
        if case.get("relevant_source_evidence_exists") is not source_exists:
            raise ValueError(f"{case_id}: relevant_source_evidence_exists disagrees with labelled locations")
        if source_exists != (source_class != "no_evidence"):
            raise ValueError(f"{case_id}: source evidence classification disagrees with labelled locations")
        if source_exists and not case.get("source_retrieval_eligible", True):
            raise ValueError(f"{case_id}: labelled source locations cannot be excluded from source retrieval")

        seen_locations: set[tuple[str, str, str]] = set()
        sources = sources_by_repo[repository]
        for expected in locations:
            classification = expected.get("evidence_classification")
            if classification not in SOURCE_EVIDENCE_CLASSES:
                raise ValueError(f"{case_id}: invalid location evidence classification {classification!r}")
            key = (expected.get("path", ""), expected.get("symbol", ""), expected.get("required_text", ""))
            if not all(key) or key in seen_locations:
                raise ValueError(f"{case_id}: missing or duplicate expected source location {key}")
            seen_locations.add(key)
            source = sources.get(key[0])
            if source is None:
                raise ValueError(f"{case_id}: ground-truth source missing: {key[0]}")
            chunks = chunk_source(key[0], source)
            matching = [chunk for chunk in chunks if chunk["symbol"] == key[1]]
            if not any(key[2] in chunk["content"] for chunk in matching):
                raise ValueError(f"{case_id}: ground-truth symbol/snippet not found: {key[0]}::{key[1]}")

        refs = case.get("configuration_references", [])
        if evidence_class == "configuration":
            if case.get("source_retrieval_eligible") is not False:
                raise ValueError(f"{case_id}: configuration-only case must be excluded from source retrieval metrics")
            if not refs or not case.get("configuration_evidence_exists"):
                raise ValueError(f"{case_id}: configuration evidence must be labelled separately")
        for ref in refs:
            if ref.get("evidence_classification") != "configuration":
                raise ValueError(f"{case_id}: configuration reference must use configuration classification")
            path = repository_roots[repository] / ref["path"]
            try:
                text = path.read_text(encoding="utf-8")
            except (OSError, UnicodeError) as exc:
                raise ValueError(f"{case_id}: configuration ground truth is missing: {ref.get('path')}") from exc
            if ref.get("required_text", "") not in text:
                raise ValueError(f"{case_id}: configuration snippet is missing: {ref.get('path')}")


def _matching_expected_indices(result: dict[str, Any], expected_locations: list[dict[str, Any]]) -> set[int]:
    return {
        index for index, expected in enumerate(expected_locations)
        if result.get("path") == expected["path"]
        and result.get("symbol") == expected["symbol"]
        and expected["required_text"] in str(result.get("content", ""))
    }


def score_case(case: dict[str, Any], results: list[dict[str, Any]]) -> dict[str, Any]:
    if len(results) > TOP_K:
        raise ValueError(f"{case['id']}: got {len(results)} results for top-{TOP_K} scoring")
    expected = case["expected_relevant_locations"]
    eligible = case.get("source_retrieval_eligible", True)
    relevant_ranks: list[int] = []
    matched_expected: set[int] = set()
    retrieved = []
    for rank, item in enumerate(results, start=1):
        matched = _matching_expected_indices(item, expected)
        if matched:
            relevant_ranks.append(rank)
            matched_expected.update(matched)
        retrieved.append({
            "rank": rank, "path": item.get("path"), "line_start": item.get("line_start"),
            "line_end": item.get("line_end"), "symbol": item.get("symbol"),
            "content": str(item.get("content", "")),
            "relevant": bool(matched) if eligible else None,
        })

    source_exists = bool(expected)
    uncertain = bool(case.get("uncertain"))
    result = {
        "id": case["id"],
        "dependency": case["dependency"],
        "query": case["query"],
        "expected_evidence_classification": case["expected_evidence_classification"],
        "expected_source_evidence_classification": case["expected_source_evidence_classification"],
        "expected_relevant_locations": expected,
        "configuration_references": case.get("configuration_references", []),
        "configuration_evidence_validated": bool(case.get("configuration_references")),
        "uncertain": uncertain,
        "source_retrieval_eligible": eligible,
        "relevant_source_evidence_exists": source_exists,
        "expected_relevant_count": len(expected),
        "returned_count": len(results),
        "relevant_ranks": relevant_ranks,
        "relevant_retrieved_count": len(relevant_ranks),
        "matched_relevant_location_count": len(matched_expected),
        "precision_at_5": len(relevant_ranks) / TOP_K if eligible else None,
        "recall_at_5": len(matched_expected) / len(expected) if eligible and source_exists and not uncertain else None,
        "reciprocal_rank": (1 / relevant_ranks[0]) if eligible and source_exists and not uncertain and relevant_ranks
            else (0.0 if eligible and source_exists and not uncertain else None),
        "non_relevant_results_at_5": len(results) - len(relevant_ranks) if eligible and source_exists else None,
        "no_evidence_false_positive_results": len(results) if eligible and not source_exists else None,
        "retrieved": retrieved,
    }
    return result


def _mean(values: list[float]) -> float | None:
    return sum(values) / len(values) if values else None


def summarize(case_results: list[dict[str, Any]]) -> dict[str, Any]:
    eligible = [item for item in case_results if item["source_retrieval_eligible"] and not item["uncertain"]]
    positives = [item for item in eligible if item["relevant_source_evidence_exists"]]
    negatives = [item for item in eligible if not item["relevant_source_evidence_exists"]]
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for item in eligible:
        grouped[item["expected_evidence_classification"]].append(item)
    category_metrics = {}
    for category, items in sorted(grouped.items()):
        category_positive = [item for item in items if item["relevant_source_evidence_exists"]]
        category_negative = [item for item in items if not item["relevant_source_evidence_exists"]]
        category_metrics[category] = {
            "case_count": len(items),
            "with_relevant_source_evidence": len(category_positive),
            "without_relevant_source_evidence": len(category_negative),
            "precision_at_5": _mean([item["precision_at_5"] for item in items]),
            "recall_at_5": _mean([item["recall_at_5"] for item in category_positive]),
            "mrr": _mean([item["reciprocal_rank"] for item in category_positive]),
            "non_relevant_results_at_5": sum(item["non_relevant_results_at_5"] or 0 for item in category_positive),
            "no_evidence_false_positive_results": sum(item["no_evidence_false_positive_results"] or 0 for item in category_negative),
        }
    return {
        "case_count": len(case_results),
        "source_retrieval_case_count": sum(item["source_retrieval_eligible"] for item in case_results),
        "scored_source_retrieval_case_count": len(eligible),
        "configuration_only_case_count": sum(not item["source_retrieval_eligible"] for item in case_results),
        "uncertain_case_count": sum(item["uncertain"] for item in case_results),
        "with_relevant_source_evidence": len(positives),
        "without_relevant_source_evidence": len(negatives),
        "precision_at_5": _mean([item["precision_at_5"] for item in eligible]),
        "recall_at_5": _mean([item["recall_at_5"] for item in positives]),
        "mrr": _mean([item["reciprocal_rank"] for item in positives]),
        "no_evidence_false_positive_case_count": sum(bool(item["no_evidence_false_positive_results"]) for item in negatives),
        "no_evidence_false_positive_results": sum(item["no_evidence_false_positive_results"] or 0 for item in negatives),
        "non_relevant_results_at_5": sum(item["non_relevant_results_at_5"] or 0 for item in positives),
        "category_metrics": category_metrics,
    }


def validate_evaluation_ids(dataset_cases: list[dict[str, Any]], result_cases: list[dict[str, Any]]) -> None:
    def unique_ids(rows: list[dict[str, Any]], label: str) -> list[str]:
        ids = [row.get("id") for row in rows]
        if any(not value for value in ids):
            raise ValueError(f"{label} contains a case with no id")
        duplicates = sorted({value for value in ids if ids.count(value) > 1})
        if duplicates:
            raise ValueError(f"{label} contains duplicate case ids: {duplicates}")
        return ids

    dataset_ids = unique_ids(dataset_cases, "dataset")
    result_ids = unique_ids(result_cases, "evaluation results")
    missing = sorted(set(dataset_ids) - set(result_ids))
    unexpected = sorted(set(result_ids) - set(dataset_ids))
    if missing or unexpected:
        raise ValueError(f"Evaluation case id mismatch; missing={missing}, unexpected={unexpected}")


def validate_baseline(dataset: dict[str, Any], baseline: dict[str, Any]) -> None:
    """Check coverage and recompute every metric from stored retrieved chunks."""
    if baseline.get("evaluation_version") != dataset.get("dataset_version"):
        raise ValueError("Baseline evaluation_version does not match the labelled dataset")
    if baseline.get("retrieval_limit") != TOP_K:
        raise ValueError(f"Baseline retrieval_limit must remain {TOP_K}")
    if baseline.get("embedding_model") != DEFAULT_EMBEDDING_MODEL:
        raise ValueError("Baseline embedding model does not match the configured production model")
    dataset_cases = dataset["cases"]
    result_cases = baseline.get("cases", [])
    validate_evaluation_ids(dataset_cases, result_cases)
    if baseline.get("dataset_version") != dataset.get("dataset_version"):
        raise ValueError("Baseline dataset_version does not match the labelled dataset")
    dataset_by_id = {case["id"]: case for case in dataset_cases}
    recalculated = []
    for row in result_cases:
        case = dataset_by_id[row["id"]]
        expected_fields = {
            "query": case["query"],
            "dependency": case["dependency"],
            "expected_relevant_locations": case["expected_relevant_locations"],
            "configuration_references": case.get("configuration_references", []),
            "expected_evidence_classification": case["expected_evidence_classification"],
            "expected_source_evidence_classification": case["expected_source_evidence_classification"],
            "source_retrieval_eligible": case.get("source_retrieval_eligible", True),
            "uncertain": bool(case.get("uncertain")),
        }
        for field, expected_value in expected_fields.items():
            if row.get(field) != expected_value:
                raise ValueError(f"Baseline case {row['id']} disagrees with dataset field {field}")
        scored = score_case(case, [
            {key: value for key, value in result.items() if key in {"path", "line_start", "line_end", "symbol", "content"}}
            for result in row.get("retrieved", [])
        ])
        if any(row.get(field) != scored.get(field) for field in METRIC_FIELDS):
            raise ValueError(f"Baseline metrics do not match raw retrieved chunks for case {row['id']}")
        if row.get("retrieved") != scored.get("retrieved"):
            raise ValueError(f"Baseline relevance labels do not match raw retrieved chunks for case {row['id']}")
        recalculated.append(scored)
    if baseline.get("summary") != summarize(recalculated):
        raise ValueError("Baseline aggregate metrics do not match per-case metrics")


def evaluate(output: Path | None = None) -> dict[str, Any]:
    dataset = json.loads(DATASET.read_text(encoding="utf-8"))
    repositories = _repo_paths(dataset)
    sources_by_repo = {name: _load_sources(path) for name, path in repositories.items()}
    validate_dataset(dataset["cases"], sources_by_repo, repositories)

    # Temporary local indexes keep runs independent of stale persisted indexes.
    with tempfile.TemporaryDirectory(prefix="patchpilot-rag-eval-") as temp_dir:
        retriever = LocalCodeRetriever(Path(temp_dir) / "qdrant", embedding_model=DEFAULT_EMBEDDING_MODEL)
        for name, sources in sources_by_repo.items():
            retriever.index_sources(repositories[name], sources, snapshot_id=f"rag-eval-v{dataset['dataset_version']}")
        case_results = [
            score_case(case, retriever.retrieve(
                repositories[case["repository"]], case["query"], limit=TOP_K,
                package_name=case["dependency"],
            ))
            for case in dataset["cases"]
        ]

    validate_evaluation_ids(dataset["cases"], case_results)
    result = {
        "evaluation_version": dataset["dataset_version"],
        "dataset_version": dataset["dataset_version"],
        "retriever": "LocalCodeRetriever",
        "embedding_model": DEFAULT_EMBEDDING_MODEL,
        "retrieval_limit": TOP_K,
        "metric_definitions": {
            "precision_at_5": "Relevant retrieved source locations divided by 5; unfilled result slots count as non-relevant.",
            "recall_at_5": "Distinct labelled relevant source locations present in top 5 divided by total labelled locations; negative, configuration-only, and uncertain cases excluded.",
            "reciprocal_rank": "Reciprocal rank of the first relevant source location; averaged only across positive, non-uncertain source cases.",
            "non_relevant_results_at_5": "For positive source-evidence cases, retrieved source results not matching any labelled relevant location.",
            "no_evidence_false_positive_results": "Retrieved source results for eligible cases with no labelled source evidence; configuration-only cases are excluded.",
            "configuration_only_cases": "Validated against the named config file separately; not part of source-retrieval metrics because config files are not indexed.",
            "uncertain_cases": "Reported with per-case raw results, but excluded from aggregate precision, recall, and MRR.",
            "macro_averaging": "Aggregate scores are arithmetic means of eligible per-case scores; recall and MRR average positive source-evidence cases only.",
        },
        "summary": summarize(case_results),
        "cases": case_results,
    }
    validate_baseline(dataset, result)
    if output:
        output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return result


if __name__ == "__main__":
    destination = Path(sys.argv[1]) if len(sys.argv) > 1 else BASELINE
    measured = evaluate(destination)
    print(json.dumps(measured["summary"], indent=2, sort_keys=True))
    print(f"Per-case results written to {destination}")
