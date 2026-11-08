# RAG retrieval baseline

This is a manually labelled, repeatable benchmark for the existing hybrid
retriever. It calls `LocalCodeRetriever` with the production defaults and leaves
FastEmbed, Qdrant, chunking, BM25, RRF, and ranking untouched. Each run creates
a temporary local Qdrant index; it makes no OSV, LLM, or other service calls.

## Run

From the repository root, with `requirements.txt` installed:

```sh
python evals/rag/evaluate.py
```

The evaluator writes per-case results and aggregate metrics to
`evals/rag/baseline.json`. It uses the configured FastEmbed model
`BAAI/bge-small-en-v1.5`. The first run requires that model to be available in
FastEmbed's local cache or downloadable; subsequent runs can use the cached
model. Metrics must only be compared when the dataset version, model and
retrieval settings match.

## Dataset and labels

`cases.json` contains 30 cases based on inspected source from this repository
and the pinned `test-agents` snapshot documented in `fixtures/test-agents/PROVENANCE.md`.
Expected locations and snippets were manually selected from source, not from
retriever output. The harness checks each non-ambiguous path, AST symbol and
snippet before running. Cases cover direct imports/API calls, aliases and
submodules, transitive dependencies used by production code, tests and mocks,
configuration-only references, semantic context, and packages without source
usage. The cryptography semantic-context example is marked uncertain and
reported separately from scored cases.

## Metrics

- **Precision@5:** relevant returned locations divided by five; if fewer than
  five items are returned, unfilled positions count as non-relevant.
- **Recall@5:** distinct labelled relevant locations in the top five divided
  by the number of labelled relevant locations.
- **MRR:** mean reciprocal rank of the first relevant location.
- Recall and MRR exclude cases with no relevant location and cases marked
  uncertain. Precision includes scored no-evidence cases, where any returned
  result is a false positive.
- The report includes the number of cases, positive and no-evidence cases,
  no-evidence false-positive cases/results, category metrics and every
  retrieved location per case.

No benchmark score is interpreted as a security verdict or proof of vulnerable
API reachability.
