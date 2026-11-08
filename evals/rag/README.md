# RAG retrieval evaluation

The active benchmark evaluates the production `LocalCodeRetriever` used by the
Dependabot review workflow. It preserves Qdrant, FastEmbed, BM25, dense
retrieval, RRF and AST-based source chunks. The active review-focused dataset
is `cases-v3.json`; `baseline-v3.json` is its measured baseline.

## Run and validate

From the repository root, with `requirements.txt` installed and the configured
FastEmbed model available locally:

```sh
python evals/rag/evaluate.py
python -m pytest -q tests/test_rag_evaluation.py
```

To write an additional measured result artifact, pass its path:

```sh
python evals/rag/evaluate.py /tmp/rag-v3-results.json
```

The runner creates a temporary local Qdrant index. It does not call OSV, an LLM
or any live search service. If `BAAI/bge-small-en-v1.5` is not cached,
FastEmbed must download it once before evaluation; subsequent runs can use the
local model cache.

## Dataset and ground truth

`cases-v3.json` contains the review-focused package queries from OSV-Patchpilot
and the pinned, MIT-licensed `test-agents` source snapshot. Its 28 cases cover
production imports and API calls, aliases and submodules, transitive packages
used by application code, tests and mocks, semantic context, and dependencies
with no source use. It excludes the retired remediation graph and Git MCP
configuration-only case. One removed Git-MCP-only test label was also dropped
from the test-only case.

The frozen v2 dataset, baseline, saved results and diagnostic documents remain
unchanged as historical records. V2 is not the active benchmark: two of its
labels point into code removed when the product was narrowed to Dependabot
review. Do not use it to assess the current source tree.

Labels are manually checked against source. A relevant source result must
match a labelled file path and symbol and contain its required source snippet.
The runner validates these facts against current source and AST chunks before
indexing. Similarity alone never makes a location relevant.

Case classifications mean:

- `direct_import`: source explicitly imports the distribution's module or a
  known relevant module.
- `api_usage`: production code invokes or references a package API or symbol.
- `test_only`: the reference occurs in test code, not production code.
- `semantic_context`: the location is conceptually related but does not prove
  package use.
- `no_evidence`: no relevant application source location is labelled.

The current dataset has no configuration-only cases because configuration
files are outside source retrieval. Uncertain cases retain raw per-case
results but do not contribute to aggregate retrieval metrics.

## Metrics

- **Precision@5:** arithmetic mean of per-case relevant returned source
  locations divided by five; unfilled result slots count as non-relevant.
- **Recall@5:** arithmetic mean across positive, non-uncertain source cases of
  distinct labelled relevant locations retrieved in the top five divided by
  the number of labelled locations.
- **MRR:** arithmetic mean across positive, non-uncertain source cases of the
  reciprocal rank of the first relevant result.
- Negative cases have no recall or reciprocal-rank score. Uncertain cases are
  excluded from aggregate precision, recall and MRR.

Each baseline case stores the query, expected locations, retrieved chunk text,
and location/rank metadata. Validation checks case-ID parity, recomputes
per-case metrics from stored chunks, and confirms aggregate metrics match.
The current v3 baseline scores **40.74% Precision@5**, **94.42% Recall@5**,
and **100% MRR** across 27 scored cases; one uncertain case is excluded from
aggregate metrics. Precision is macro-averaged, so each scored query carries
equal weight.

## Scope and limitations

This is a manually labelled, limited benchmark, not a comprehensive measure of
package usage or security. Results depend on the pinned cases, repository
snapshot, embedding model and retrieval settings. A retrieved import or API
reference does not establish vulnerable API reachability. Scores are
engineering signals for this dataset, not statistical guarantees.
