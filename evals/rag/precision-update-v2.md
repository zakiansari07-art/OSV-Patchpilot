# RAG retrieval v2 precision update

This report compares the updated retriever with the frozen evaluation v2
baseline on the same 30 cases, same manually labelled locations, same fixture
repositories and same `BAAI/bge-small-en-v1.5` embedding model. It does not
rewrite `baseline.json` or `cases.json`.

## Aggregate results

| Metric | Frozen v2 baseline | Updated retriever | Change |
|---|---:|---:|---:|
| Precision@5 | 39.29% | **41.43%** | +2.14 percentage points |
| Recall@5 | 87.88% | **92.57%** | +4.69 percentage points |
| MRR | 93.06% | **100.00%** | +6.94 percentage points |
| False-positive results in 4 no-evidence cases | 20 | **0** | −20 |
| Non-relevant results in positive source cases | 65 | **62** | −3 |

Precision uses the existing v2 definition: the denominator is always five,
including unfilled slots. Recall and MRR exclude the one uncertain case and the
configuration-only case. The four no-evidence cases remain in the precision
population but do not receive recall/MRR values.

## Results by evidence class

| Evidence class | Metric | Baseline | Updated |
|---|---|---:|---:|
| `api_usage` (15 cases) | Precision@5 | 36.00% | 37.33% |
|  | Recall@5 | 87.78% | 93.33% |
|  | MRR | 88.89% | 100.00% |
| `direct_import` (4 cases) | Precision@5 | 75.00% | 85.00% |
|  | Recall@5 | 73.10% | 80.43% |
|  | MRR | 100.00% | 100.00% |
| `test_only` (5 cases) | Precision@5 | 52.00% | 52.00% |
|  | Recall@5 | 100.00% | 100.00% |
|  | MRR | 100.00% | 100.00% |
| `no_evidence` (4 cases) | False-positive results | 20 | **0** |
| `configuration` (1 case) | Separate config check | unchanged | unchanged |
| `semantic_context` (1 uncertain case) | Raw result retained; excluded from aggregates | unchanged | unchanged |

## Case-level changes

| Case | Relevant results in top 5, baseline → updated | Notes |
|---|---:|---|
| `packaging-version-submodule` | 1/3 → 3/3 | Exact imported `packaging.version` API use is ranked ahead of generic version-handling code. |
| `pydantic-report-models` | 4/23 → 5/23 | One additional relevant model chunk enters the top five; the benchmark has many more labelled models than the retrieval limit. |
| `langgraph-review-graph` | 2/2 → 1/2 | `main.py::main` is no longer in the top five. It invokes the project's graph wrapper but does not itself import or reference LangGraph; it is weaker contextual evidence than the retrieved LangGraph API locations. |
| `dotenv-load` | 0/1 → 1/1 | The `python-dotenv → dotenv` mapping brings `load_dotenv()` into the top five. |
| `langchain-core-transitive-tool-use` | 3/3 → 2/3 | `tests/test_agent.py::test_flights_tool_maps_arguments_and_returns_search_results` falls below the top five because production LangChain tool use ranks ahead of test-only use for a query without test/mock intent. The production `flights_finder` and another test dispatch result remain. |
| `langchain-direct-distribution-import` | 3/4 → 4/4 | A fourth direct-import/API location enters the top five. |
| `aiohttp`, `GitPython`, `requests`, `Werkzeug` no-source cases | 0/5 results each → 0/5 | Dense-only generic chunks no longer appear as package-usage locations. |
| Configuration-only Git server case | 5 source chunks → 0 source chunks | Configuration evidence remains separately validated; source retrieval does not misrepresent code locations as config evidence. |
| `cryptography` uncertain semantic case | 5 → 0 | With no deterministic package-use signal, weak dense matches are not returned as package-use locations. The case remains uncertain and excluded from aggregates. |

Two previously relevant locations leave the top five: `main.py::main` is
production orchestration that calls an internal LangGraph wrapper without a
LangGraph import, and the other is test-only tool behavior outranked by
production API evidence. These are explicit ranking tradeoffs; aggregate
Recall@5 improved by 4.69 percentage points, above the frozen baseline.

## Implementation and evaluation method

- Kept Qdrant, FastEmbed, BM25, dense retrieval and RRF. Kept AST chunk
  boundaries, the embedding model and the 50-result BM25/dense candidate pools.
- Added versioned index metadata for source area, Python imports, aliases,
  imported bindings and names actually referenced in each chunk. Existing
  indexes with older metadata are rebuilt automatically.
- Added a maintainable distribution-to-module mapping, including
  `GitPython → git`, `python-dotenv → dotenv`, `Pillow → PIL`, and
  `pytest-asyncio → pytest`.
- Expanded BM25 terms with import-module aliases but left the dense embedding
  query unchanged. RRF ranks the existing top-50 BM25/dense candidate pools;
  the final response remains limited to five.
- Ranks verifiable production imports/API references ahead of weak contextual
  chunks. Test-only evidence is retained and classified; explicit test/mock
  evaluation queries can prioritize it, while production review calls disable
  test-query intent so advisory prose mentioning tests cannot elevate mocks.
  Generic semantic chunks are retained only as
  `semantic_context` when the repository has deterministic evidence of the
  package. A package with no such evidence returns no source-use locations.
- Uses no live OSV, LLM, Qdrant service or remote search in the benchmark.
  Qdrant is temporary/local and the saved result is validated against the
  same v2 labels and metric definitions.

Reproduce with:

```sh
.venv/bin/python evals/rag/evaluate.py evals/rag/results-v2-precision-update.json
.venv/bin/python -m pytest -q
```

The measured JSON is `results-v2-precision-update.json`. The frozen historical
v2 baseline and its ground-truth cases were not modified by this retrieval
work.

## Limitations

The benchmark contains 30 cases and is not statistically representative.
Import and API references demonstrate code-level use only; they do not prove
runtime execution, vulnerable API reachability, or exploitability. The JS/TS
import metadata parser recognizes common static/default/named imports and
CommonJS assignments; it is intentionally lightweight. The package mapping is
an extensible known-mapping table, not a complete PyPI-to-import database.
