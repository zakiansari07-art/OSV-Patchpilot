# RAG retrieval evaluation

This versioned benchmark evaluates the production `LocalCodeRetriever` using
Qdrant, FastEmbed, BM25, dense retrieval, RRF and AST-based source chunks. The
historical v2 baseline remains frozen; the package-aware implementation result
is recorded separately in `results-v2-precision-update.json` and explained in
`precision-update-v2.md`.

## Run and validate

From the repository root, with `requirements.txt` installed and the configured
FastEmbed model available locally:

```sh
python evals/rag/evaluate.py evals/rag/results-v2-precision-update.json
python -m pytest -q
```

The runner creates a temporary local Qdrant index and writes measured per-case
results to a separate artifact. The historical `baseline.json` is frozen and
must not be overwritten. The runner does not call OSV, an LLM or any live search
service. If `BAAI/bge-small-en-v1.5` is not cached, FastEmbed must download it
once before an evaluation can run; subsequent runs can use the local model
cache.

To validate an already recorded artifact without initializing Qdrant or
FastEmbed, use the pure-Python `validate_dataset`, `validate_evaluation_ids`,
and `validate_baseline` functions from `evals/rag/evaluate.py`. Their tests use
local repository files and saved chunks only.

## Dataset and ground truth

`cases.json` (dataset v2) contains 30 package queries from OSV-Patchpilot and
the pinned, MIT-licensed `test-agents` source snapshot. The fixture's repository
revision is recorded in `fixtures/test-agents/PROVENANCE.md`. Cases cover
production imports and API calls, aliases and submodules, transitive packages
used by application code, tests and mocks, config-only references, semantic
context, and dependencies with no source use.

Labels are manually checked against source. Retrieved results may identify
candidates to audit, but similarity alone never makes a location relevant. A
relevant source result must match a labelled file path and symbol and contain
its required source snippet. The runner checks these facts against the current
source and AST chunks before it builds an index. The case-level classification
uses these meanings:

- `direct_import`: the source file explicitly imports the distribution's
  module or a known relevant module.
- `api_usage`: production code invokes or references a package API or symbol.
- `test_only`: the package reference occurs in test code, not production code.
- `configuration`: the package is referenced by a configuration file.
- `semantic_context`: the location is conceptually related but does not prove
  package use.
- `no_evidence`: no relevant application source location is labelled.

`mcp-server-git-config-only` is checked against `mcp_config.json` separately.
The current index only reads Python and JavaScript/TypeScript code, so
configuration files are outside source retrieval. The case has source
classification `no_evidence`, configuration classification `configuration`,
and is excluded from source-retrieval metrics. It does not claim application
usage.

The complete label-change explanations are in `AUDIT.md`. One semantic-context
case is explicitly uncertain; its raw retrieval is retained, but it does not
contribute to aggregate precision, recall or MRR.

The updated retriever adds import/module and production/test metadata while
keeping chunk spans unchanged. Package-aware retrieval adds known import-module
terms to BM25, preserves the original dense query, ranks the existing BM25 and
dense candidates through RRF, and then qualifies results using syntax-derived
package references. Weak semantic candidates are retained only when the
repository has deterministic evidence of that package and are labelled as
`semantic_context`. A repository with no package-specific evidence returns no
source-use locations. See `diagnostic-v2.md` for the pre-change lane analysis.

## Metrics (evaluation v2)

- **Precision@5:** relevant returned source locations divided by 5. When fewer
  than five results are returned, missing slots count as non-relevant.
- **Recall@5:** distinct labelled relevant source locations returned in the
  top five divided by all labelled relevant source locations for the case.
- **Reciprocal rank:** reciprocal of the first relevant result's rank; MRR is
  averaged across positive, non-uncertain source cases only.
- **`non_relevant_results_at_5`:** retrieved source results that are not
  labelled relevant in positive cases.
- **`no_evidence_false_positive_results`:** all retrieved source results for
  eligible cases with no labelled source evidence. Configuration-only cases
  are excluded because their config evidence is validated separately.
- Aggregate precision, recall, and MRR are arithmetic means of per-case
  scores (macro averages); recall and MRR average only positive,
  non-uncertain source-evidence cases.
- Negative cases do not receive recall or reciprocal-rank values. Uncertain
  cases are excluded from all aggregate retrieval metrics. Configuration-only
  cases are outside the source metric population.

Every baseline case stores the query, expected locations, raw retrieved chunk
content and location/rank metadata. Automated validation checks case-ID parity,
recalculates per-case metrics from stored chunks, and verifies that aggregate
metrics equal the per-case results. Evaluation/dataset versions are explicit;
the v2 field names replace ambiguous v1 reporting and are not intended to be
silently interpreted as the same schema.

## Scope and limitations

This is a manually labelled, limited benchmark, not a comprehensive measure of
package usage or security. Results depend on the pinned cases, repository
snapshot, embedding model and retrieval settings. A retrieved import or API
reference does not establish vulnerable API reachability. Scores are
engineering signals for this dataset, not statistical guarantees.
