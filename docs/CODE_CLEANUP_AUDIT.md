# Code cleanup audit

> Historical note: this audit recorded the prior cleanup before the OSV
> remediation workflow was retired. The current product is Dependabot review
> only; the remediation-candidate inventory below is point-in-time history.

## Scope and baseline

Audit performed on branch `code-cleanup` with a clean working tree before
cleanup. The pre-cleanup full test suite completed with **213 passed**.

Repository inventory at audit time:

- 67 tracked files.
- 44 tracked Python files, including tests and the RAG fixture.
- Approximately 13,270 tracked Python source lines.
- 16 direct requirement entries.
- No project `pyproject.toml`, dependency lockfile, Ruff/Black configuration,
  or lint command is configured at the repository root. The RAG fixture has
  its own project metadata and lockfile; those belong to the pinned fixture.
- GitHub Actions examples are under `examples/github-actions/`; README and
  `docs/DEPENDABOT_REVIEW.md` describe how consumers install them.

The application entry points are `main.py` and the compatibility module
`agent_graph.py`. `vulnerability_agent/graph.py` registers the remediation
nodes explicitly; `vulnerability_agent/review_graph.py` registers the separate
Dependabot review workflow. Node functions, state, dependencies, CLI routes,
tracing variables, report validation, and MCP services are all reached through
these explicit entry points or workflow configuration.

## Confirmed unused candidates

| Candidate | Evidence | Risk | Recommendation |
|---|---|---|---|
| `pytest-mock` in `requirements.txt` | Repository tests use `unittest.mock`, pytest's built-in `monkeypatch`, and fixtures; no `mocker`, `pytest_mock`, or `pytest-mock` runtime/test integration is referenced. The two example Actions install this requirements file, but do not invoke the plugin. The fixture lockfile's own optional `pytest-mock` declarations are upstream fixture metadata and are not this project's direct dependency. | Low. A contributor relying on an undocumented transitive pytest plugin would need to add it explicitly. | Remove the direct requirement; do not modify fixture metadata or versions. |
| Legacy source-search helpers in `vulnerability_agent/nodes/patching.py`: `package_search_terms`, `find_package_usage_files`, `rank_source_candidates`, `_tree_source_candidates`, `_read_source_batch`, `_repository_revision`, `_targeted_source_context`, and `source_excerpt_for_package`; constants `SOURCE_FILE_GLOBS`, `INDEX_FILE_LIMIT`, `INDEX_BATCH_SIZE`, and `INDEX_TOTAL_CHAR_LIMIT` | The active remediation graph registers `node_investigate_and_plan`; that node only builds bounded dependency-manifest context and proposes dependency-file edits. No active production call reaches the listed source-search helpers. The helpers call each other only within the disconnected legacy path. Their only other references were four unit tests that exercised former MCP tree parsing and package-search helpers. RAG retrieval is a separate report-only workflow (`usage_analysis.py` / `retrieval.py`) and remains active. No dynamic registration, CLI, workflow YAML, or configuration reference to these helpers was found. | Low to moderate. The helper functions are module-level and some lack underscore prefixes, so an undocumented external consumer importing them directly could exist; they are not exported from the package or compatibility API. | Remove this disconnected path and its four tests, while preserving report-only RAG and its own `package_imports.py` utilities. |

## Probably unused candidates retained

| Candidate | Evidence | Why retained |
|---|---|---|
| Top-level `agent_graph.py` re-exports and `subprocess` import | The module documents itself as a compatibility API. Some re-exports have no in-repository references, and static analysis reports imported names as unused because `__all__` supplies their public use. Tests also patch `agent_graph.subprocess`, confirming that this import is part of the test/compatibility surface. | External scripts and tests may import or patch these historical names. No deprecation or compatibility policy proves removal safe. |
| `vulnerability_agent/report_validation.py::_normalize_legacy_v4` | It normalizes an older report shape, but ordinary call search cannot establish that persisted or externally supplied reports no longer use it. The validator is part of the artifact analysis boundary. | Preserve compatibility for saved reports and untrusted downloaded artifacts. |
| `vulnerability_agent/state.py::apply_search_replace_edits` and related report helpers | Several are surfaced through the compatibility module and are used by graph nodes/tests. | These remain active or are public compatibility exports; no deletion justified. |

## Uncertain candidates retained

- A static identifier scan is not sufficient to remove any other module-level
  functions or classes. In particular, LangGraph node callables are registered
  in graph dictionaries and can have no direct call expression.
- Test helpers and test-only symbols are retained unless they specifically
  exercise the confirmed disconnected legacy candidate described above.
- No obsolete migration, debugging, evaluation, or historical result files
  were identified. Evaluation v2 cases, frozen baseline, saved results, and
  experiment documentation are retained.
- No duplicate implementation was confirmed. The package inventory parser,
  source-usage analyzer, and RAG retriever serve distinct roles; consolidation
  would add coupling rather than remove it.

## Dependencies

`pytest-mock` is the only confirmed unused direct dependency. The other direct
requirements are referenced by application code, tests, or both: LangGraph,
LangGraph SQLite checkpointing, LangChain, LangChain OpenAI, LangSmith, MCP,
Pydantic, packaging, HTTPX, python-dotenv, pytest, pytest-asyncio, Qdrant with
FastEmbed, Tree-sitter language pack, and the Python-version-conditional
`tomli` fallback. Dependencies were not upgraded, and transitive dependencies
were not edited.

## Protected components and checks

- Qdrant, FastEmbed, BM25, dense retrieval, RRF, AST chunking, package-import
  mapping, evidence labels, and the evaluation v2 runner are outside the
  cleanup and remain intact.
- `evals/rag/cases.json`, `evals/rag/baseline.json`, and historical result
  files are preserved.
- LangGraph orchestration, LangSmith environment handling and trace metadata,
  report validation, and the two-workflow Actions security boundary are
  preserved.
- Workflow references were checked against scripts and CLI flags. The
  evidence job runs tests without write credentials; the comment job processes
  validated JSON and does not execute the Dependabot branch.

## Applied cleanup

Removed the direct `pytest-mock` requirement, the disconnected source-search
fallback and its four direct unit tests, plus nine confirmed unused imports.
No functions/classes used by the active application workflow were removed. No
retrieval implementation, mapping, evaluation input, baseline, or historical
result was modified.

## Validation results

- Full suite: **213 passed before cleanup; 209 passed after cleanup**. The four
  removed tests exercised only the deleted disconnected helper functions.
- `compileall`, application module imports, CLI `main.py --help`, and
  `git diff --check`: passed.
- Lint/format: no root lint or formatting configuration or corresponding
  installed command was found, so no such check was available.
- Actions: repository regression tests passed and verify workflow file paths,
  workflow identities, CLI flags, and the untrusted-evidence / trusted-comment
  split. The example workflows retain least-privilege permissions and do not
  execute the Dependabot branch in the commenting job.
- LangSmith: source and README still contain `LANGSMITH_TRACING`,
  `LANGSMITH_API_KEY`, `LANGSMITH_PROJECT`, and the trace metadata fields.
- RAG: a fresh evaluation was written outside the repository and validated
  against the frozen v2 dataset. Frozen baseline → post-cleanup run:
  Precision@5 **39.29% → 41.43%**; Recall@5 **87.88% → 92.57%**; MRR
  **93.06% → 100%**; positive-case non-relevant results **65 → 62**;
  no-evidence false-positive results **20 → 0**. The post-cleanup values match
  `results-v2-precision-update.json`; this cleanup did not change the RAG
  result. The output was written to `/tmp/osv-patchpilot-rag-cleanup.json`.
- Evaluation integrity: `cases.json`, `baseline.json`, and the saved updated
  result are unchanged.

## Before and after inventory

| Measure | Before | After |
|---|---:|---:|
| Tracked files | 67 | 67 |
| Tracked Python files | 44 | 44 |
| Tracked Python source lines (approx.) | 13,270 | 12,995 |
| Direct requirement entries | 16 | 15 |
| Full-suite passing tests | 213 | 209 |

The requested audit is an additional untracked document; `.gitignore` now
allows this one report while preserving the existing ignore rule for other
local Markdown files in `docs/`.
