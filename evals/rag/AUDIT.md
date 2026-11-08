# Ground-truth label audit (dataset v2)

All source labels below were inspected against the files and symbols named in
`cases.json`. The evaluator independently checks that every labelled source
path, chunk symbol, and required snippet still exists. It does not infer labels
from the retriever's result list. The pinned external source's revision and
license are recorded in `fixtures/test-agents/PROVENANCE.md`.

## Changes from dataset v1

| Case | Previous label | Dataset v2 label | Reason |
| --- | --- | --- | --- |
| `qdrant-retriever` | One expected location: `LocalCodeRetriever.__init__` | Five production locations (`__init__`, `index_sources`, `_repo_filter`, `_load_documents`, `retrieve`) plus one `test_only` integration-test location | Production code constructs the client/collection, creates points and upserts, builds Qdrant filters, scrolls persisted chunks, and queries vectors. The test calls the wrapper to verify persisted Qdrant behavior; it is labelled `test_only`, not production API usage. |
| `pydantic-report-models` | Only `_ReportModel` | `_ReportModel`, all 20 report/evidence model subclasses, `validate_evidence_report`, and `evidence_report_json_schema` | `_ReportModel` directly subclasses Pydantic `BaseModel`; the 20 schemas inherit that Pydantic model and the two functions invoke Pydantic validation/schema APIs. `_normalize_legacy_v4` only transforms dictionaries and is not labelled as Pydantic usage. |
| `langgraph-remediation-graph` | One expected `build_graph` chunk | Both `build_graph` chunks, including the later `graph.add_conditional_edges(...)` chunk | Both chunks contain LangGraph graph construction or routing API calls; the later routing setup is relevant evidence omitted from the first label. |
| `mcp-server-git-config-only` | Configuration class mixed into retrieval false positives | Configuration reference retained; source evidence explicitly `no_evidence`; excluded from source-retrieval metrics | `mcp_config.json` is checked independently. The production code index contains only Python/JS/TS source, so a config-only package is not a source-retrieval negative case. It establishes configuration, not application use. |
| Other audited cases | Single or incomplete expected location sets | Add direct `Version`/`Requirement` and tomli fallback uses; pytest fixtures/markers; LangChain message/schema/tool references; production and mocked SerpApi calls; the MCP client wrapper; SendGrid's mock test; and CLI review-graph invocation | Every addition was checked against the named source chunk and assigned its own evidence class, including `test_only` where the result exercises a mock or test fixture. Specific cases and snippets are versioned in `cases.json`. |

## Reviewed labels retained

- `httpx-osv-query` remains scoped to `osv_service.py::query_osv`. The retrieved
  `FakeHTTP`, `AsyncMock` and response-parser tests are test infrastructure,
  not production API usage. The HTTPX status helper is real code, but handles
  GitHub comment-posting failures, not the OSV request or release lookup.
- For `httpx-github-release`, `review_graph.py::_raise_for_github_status` is
  similarly outside the release lookup. The test results exercise status
  handling and remain test-only; `_release_context` is the labelled production
  release lookup location.
- Direct production API calls, direct imports, test-only references and
  transitive-but-imported fixture dependencies retain their source-backed
  labels. Mock classes remain `test_only` rather than production evidence.
- The cryptography semantic-context case remains uncertain. Its location
  exists, but filename/key-handling context does not establish cryptography
  package use. It is retained for inspection and excluded from aggregate
  precision, recall and MRR.
- The aiohttp, GitPython, requests, and Werkzeug cases remain no-source-evidence
  cases. Their lockfile or dependency metadata is not treated as application
  source usage.

Retrieved results were treated only as audit candidates. A candidate was added
as relevant only after the named source path, symbol, call/import or test
reference was independently inspected; semantic similarity alone did not
justify a label.

## Metric/reporting revision

Dataset and evaluation versions advanced from v1 to v2 so metric semantics and
per-case fields are not silently redefined. Positive cases now report
`non_relevant_results_at_5`; eligible negative cases report
`no_evidence_false_positive_results`. Configuration-only cases have no source
retrieval metric values. Each baseline row stores query, labels, and the
retrieved chunk content so its per-case and aggregate scores can be recomputed
and checked without Qdrant, FastEmbed or an external service.
