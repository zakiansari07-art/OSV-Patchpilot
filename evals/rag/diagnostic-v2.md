# RAG evaluation v2 pre-optimization diagnosis

**Scope.** This is the required diagnosis before retrieval changes. It uses the frozen v2 cases and baseline as they stand in the working tree. No labels or baseline results were changed for this analysis. Individual BM25, dense, RRF and production-final rankings were captured against the pinned fixture repositories. The uncertain case is excluded from aggregate metrics; the configuration-only case is assessed separately.

## Baseline and retrieval lanes

| Lane | Precision@5 | No-evidence false-positive results | Positive-case non-relevant results |
|---|---:|---:|---:|
| BM25 | 35.00% | 10 | 71 |
| Dense | 35.71% | 20 | 70 |
| RRF fusion | 39.29% | 20 | 65 |
| Production final | 39.29% | 20 | 65 |

Frozen production baseline: P@5 **39.29%**, Recall@5 **87.88%**, MRR **93.06%**; 20 false-positive results across four no-evidence cases. Dense alone is less precise (35.71%); BM25 alone is 35.00%; RRF combines complementary matches and gives 39.29%. Thus changing RRF/candidate counts is not supported by this evidence.

## Root causes and evidence

1. **Semantic results are not qualified by package usage (highest impact).** All four no-evidence cases have no BM25 matches, but dense search supplies five generic locations apiece; RRF then returns all 20 as apparent results. For `aiohttp`, candidates include `tests/test_agent.py` test functions and generic `agents/agent.py` / `app.py` code. Similar generic locations recur for `GitPython`, `requests`, and `Werkzeug`. There is no package-specific syntax evidence behind these matches.
2. **Package-name to import-module mapping is incomplete/inconsistent.** `usage_analysis.py` knows `GitPython → git`, but retrieval/index metadata does not carry mapped package imports. The benchmark’s `python-dotenv` query (`dotenv-load`) returns unrelated project-environment functions in all lanes; `dotenv`/`load_dotenv` does not surface in top 50. `packaging.version` has a relevant `fixed_versions_for_finding` location at RRF rank 3, while other expected API locations are buried or absent from the top 5.
3. **Chunk metadata cannot support evidence-aware ranking.** AST chunking preserves path, symbol and lines, but indexing stores only path/symbol/content text. It does not preserve `test` versus production area, imports in a file, aliases, import-bound names, or whether the chunk uses those names. Consequently RRF cannot rank an actual imported API call over a similarly worded test or generic function.
4. **Test/mock and benchmark self-references can compete with production evidence.** In `pydantic-report-models`, a test helper (`_normalize_legacy_v4`) is one of five results though it does not match a Pydantic API use. Other positive cases include generic test fixtures, mocks, or unrelated test methods among top five. The `httpx` mock case and `pytest` test-only cases are correctly labelled ground truth, so test evidence must remain available but identified/ranked separately.
5. **False negatives are caused by query/evidence mismatch more than RRF.** `dotenv-load` is absent from top 50 in BM25 and dense, indicating query terms and package mapping fail before fusion. In `packaging-version-submodule`, `fixed_versions_for_finding` is recovered by RRF, but other expected locations are not in top five; RRF does not recover candidates absent or deeply ranked in both lanes. For strong exact-symbol cases (HTTPX, Pydantic APIs, LangGraph, Qdrant, FastEmbed, Tree-sitter and SendGrid), both lanes usually find relevant locations near the top and RRF retains them.
6. **Current hybrid query expansion is overly broad.** Production source usage queries include advisory identifiers, descriptions and summaries in addition to package terms. Evaluation queries also contain broad conceptual phrases. Those terms make dense retrieval useful for context, but cannot establish package usage and generate unrelated candidate locations when exact package evidence is absent.

## False-positive inventory (frozen v2 baseline)

This inventory covers every non-relevant result in the baseline top five for the scored cases. “False positive” here means the result did not match that case’s labelled package/query location; it does not assert that every test or other function is unrelated to the package in every context. Source snippets and the case explanation were checked for category assignment.

- **Test/mock candidates:** 39 (test paths surfaced without matching that case's labelled target).
- **Exact distribution-name references outside the labelled target:** 5.
- **Generic semantic similarity or unrelated symbols:** 41.

### Test/mock candidates

- `httpx-osv-query` — `tests/test_osv_service.py::test_query_osv_parses_vulnerabilities`
- `httpx-osv-query` — `tests/test_dependabot_review.py::test_release_lookup_status_is_explicit_and_machine_readable`
- `httpx-osv-query` — `tests/test_agent_graph.py::FakeHTTP.post`
- `httpx-github-release` — `tests/test_dependabot_review.py::test_release_lookup_status_is_explicit_and_machine_readable`
- `httpx-github-release` — `tests/test_workstream_f_regressions.py::test_ai_review_cannot_invent_upstream_release_explanation_after_lookup_failure`
- `packaging-specifiers` — `tests/test_osv_service.py::test_poetry_constraint_and_lockfile_verification`
- `langgraph-review-graph` — `tests/test_dependabot_review.py::test_cli_accepts_artifact_url_for_matching_repository_report`
- `langgraph-review-graph` — `tests/test_dependabot_review.py::test_review_graph_preserves_evidence_when_model_fails`
- `langchain-openai-model` — `tests/test_dependabot_review.py::test_review_graph_stores_ai_text_after_osv_contradiction_filtering`
- `langchain-openai-model` — `tests/test_workstream_f_regressions.py::test_ai_review_does_not_conflate_osv_affected_version_with_application_reachability`
- `langchain-openai-model` — `tests/test_workstream_f_regressions.py::test_ai_narrative_cannot_attribute_global_remaining_count_to_one_package`
- `mcp-client-session` — `tests/test_mcp_policy.py::RecordingClient.call`
- `fastembed-model` — `tests/test_dependabot_review.py::test_review_graph_stores_ai_text_after_osv_contradiction_filtering`
- `fastembed-model` — `tests/test_dependabot_review.py::test_review_graph_runs_ai_analysis_and_skips_comment_by_default`
- `tree-sitter-parser` — `tests/test_retrieval.py::test_javascript_chunking_preserves_common_declaration_boundaries`
- `dotenv-load` — `tests/test_branch_and_project_environment.py::test_test_command_uses_target_repo_venv_for_temporary_worktree`
- `pytest-async-test-only` — `tests/test_agent_graph.py::FakeHTTP.post`
- `httpx-mocked-test` — `tests/test_dependabot_review.py::test_comment_failure_includes_github_api_message`
- `httpx-mocked-test` — `tests/test_workstream_f_regressions.py::test_ai_review_cannot_invent_upstream_release_explanation_after_lookup_failure`
- `httpx-mocked-test` — `tests/test_dependabot_review.py::test_review_rejects_non_dependabot_pr_before_fetching_refs`
- `langchain-core-transitive-message-use` — `tests/test_agent.py::test_tool_node_returns_a_retry_message_for_unknown_tool`
- `langchain-core-transitive-tool-use` — `tests/test_agent.py::test_flights_tool_returns_provider_error_as_text`
- `langchain-core-transitive-tool-use` — `tests/test_agent.py::test_exists_action_routes_tool_calls_to_tool_node`
- `langchain-direct-distribution-import` — `tests/test_agent.py::test_tool_node_dispatches_known_tools_and_returns_tool_messages`
- `serpapi-production-api` — `tests/test_agent.py::test_hotels_tool_returns_at_most_five_properties`
- `serpapi-production-api` — `tests/test_agent.py::test_flights_tool_returns_provider_error_as_text`
- `serpapi-mocked-test-only` — `tests/test_agent.py::test_email_sender_formats_and_sends_email`
- `sendgrid-mocked-test-only` — `tests/test_agent.py::test_graph_pauses_before_email_delivery_without_calling_openai`
- `sendgrid-mocked-test-only` — `tests/test_agent.py::test_exists_action_routes_final_answer_to_email_checkpoint`
- `aiohttp-transitive-no-source-use` — `tests/test_agent.py::test_graph_pauses_before_email_delivery_without_calling_openai`
- `aiohttp-transitive-no-source-use` — `tests/test_agent.py::test_hotels_tool_propagates_provider_errors`
- `gitpython-transitive-no-source-use` — `tests/test_agent.py::test_email_sender_formats_and_sends_email`
- `gitpython-transitive-no-source-use` — `tests/test_agent.py::test_tool_node_returns_a_retry_message_for_unknown_tool`
- `gitpython-transitive-no-source-use` — `tests/test_agent.py::test_tool_node_dispatches_known_tools_and_returns_tool_messages`
- `gitpython-transitive-no-source-use` — `tests/test_agent.py::test_exists_action_routes_final_answer_to_email_checkpoint`
- `requests-transitive-no-source-use` — `tests/test_agent.py::test_email_sender_formats_and_sends_email`
- `requests-transitive-no-source-use` — `tests/test_agent.py::test_graph_pauses_before_email_delivery_without_calling_openai`
- `werkzeug-no-source-use` — `tests/test_workstream_f_regressions.py::test_werkzeug_changed_dependency_is_consistent_in_summary_and_detail`
- `werkzeug-no-source-use` — `tests/test_agent_graph.py::test_retry_routing_respects_attempt_limit`

### Exact package-name references outside the target

- `httpx-osv-query` — `vulnerability_agent/review_graph.py::_raise_for_github_status`
- `httpx-github-release` — `vulnerability_agent/review_graph.py::_raise_for_github_status`
- `httpx-github-release` — `vulnerability_agent/dependabot_review.py::review_dependabot_pull_request`
- `mcp-client-session` — `mcp_client.py::MCPCallError`
- `httpx-mocked-test` — `vulnerability_agent/review_graph.py::_raise_for_github_status`

### Generic semantic or unrelated-symbol candidates

- `packaging-version-submodule` — `osv_service.py::upgrade_guidance_for_finding`
- `packaging-version-submodule` — `vulnerability_agent/dependabot_review.py::_scan`
- `packaging-version-submodule` — `osv_service.py::parse_package_json`
- `packaging-version-submodule` — `osv_service.py::assess_version_affected_by_advisory`
- `packaging-specifiers` — `osv_service.py::verify_group_resolution`
- `packaging-specifiers` — `vulnerability_agent/dependabot_review.py::_compact_review_report`
- `pydantic-report-models` — `vulnerability_agent/report_validation.py::_normalize_legacy_v4`
- `langgraph-remediation-graph` — `vulnerability_agent/nodes/__init__.py::lines_1_1`
- `langgraph-remediation-graph` — `vulnerability_agent/__init__.py::lines_1_1`
- `langgraph-remediation-graph` — `agent_graph.py::lines_1_21`
- `langgraph-review-graph` — `vulnerability_agent/review_graph.py::DependabotReviewState`
- `langchain-openai-model` — `settings.py::model_name`
- `mcp-client-session` — `mcp_client.py::MCPPolicyProxy.call`
- `fastembed-model` — `vulnerability_agent/retrieval.py::LocalCodeRetriever`
- `fastembed-model` — `vulnerability_agent/dependencies.py::_model`
- `tree-sitter-parser` — `vulnerability_agent/retrieval.py::_javascript_fallback_chunks`
- `tree-sitter-parser` — `vulnerability_agent/retrieval.py::chunk_source`
- `tree-sitter-parser` — `vulnerability_agent/retrieval.py::_line_chunks`
- `dotenv-load` — `vulnerability_agent/state.py::_project_python`
- `dotenv-load` — `vulnerability_agent/dependabot_review.py::_prepare_review_environment`
- `dotenv-load` — `vulnerability_agent/dependabot_review.py::_safe_child_environment`
- `dotenv-load` — `vulnerability_agent/dependabot_review.py::_compact_test_result`
- `tomli-aliased-import` — `vulnerability_agent/retrieval.py::_tree_sitter_chunks`
- `pytest-async-test-only` — `osv_service.py::scan_packages`
- `pytest-async-test-only` — `osv_service.py::query_osv`
- `langchain-direct-distribution-import` — `app.py::main`
- `sendgrid-production-api` — `app.py::send_email`
- `sendgrid-production-api` — `app.py::render_email_form`
- `sendgrid-production-api` — `app.py::populate_envs`
- `sendgrid-mocked-test-only` — `agents/agent.py::Agent.email_sender`
- `sendgrid-mocked-test-only` — `app.py::send_email`
- `aiohttp-transitive-no-source-use` — `agents/agent.py::Agent.__init__`
- `aiohttp-transitive-no-source-use` — `app.py::process_query`
- `aiohttp-transitive-no-source-use` — `agents/agent.py::AgentState`
- `gitpython-transitive-no-source-use` — `app.py::populate_envs`
- `requests-transitive-no-source-use` — `app.py::main`
- `requests-transitive-no-source-use` — `app.py::process_query`
- `requests-transitive-no-source-use` — `agents/tools/hotels_finder.py::hotels_finder`
- `werkzeug-no-source-use` — `vulnerability_agent/dependabot_review.py::review_dependabot_pull_request`
- `werkzeug-no-source-use` — `vulnerability_agent/dependabot_review.py::parse_pull_request_reference`
- `werkzeug-no-source-use` — `vulnerability_agent/nodes/pull_requests.py::node_create_pull_request`

## Per-case lane evidence

| Case | Evidence class | Expected locations | BM25 relevant ranks | Dense relevant ranks | RRF relevant ranks | Final relevant / 5 |
|---|---|---:|---|---|---|---:|
| `httpx-osv-query` | api_usage | 1 | 1 | 2 | 1 | 1/5 |
| `httpx-github-release` | api_usage | 1 | 2 | 2 | 1 | 1/5 |
| `packaging-version-submodule` | api_usage | 3 | — | — | 3 | 1/5 |
| `packaging-specifiers` | api_usage | 2 | 1, 2 | 1, 2 | 1, 2 | 2/5 |
| `pydantic-report-models` | direct_import | 23 | 1, 3, 5 | 1, 2, 3, 4, 5 | 1, 2, 3, 5 | 4/5 |
| `langgraph-remediation-graph` | api_usage | 2 | 1, 2 | 1, 3 | 1, 2 | 2/5 |
| `langgraph-review-graph` | api_usage | 2 | 1, 4 | 1, 3 | 1, 2 | 2/5 |
| `langchain-openai-model` | api_usage | 1 | 1 | 1 | 1 | 1/5 |
| `mcp-client-session` | api_usage | 2 | 1, 3 | 1, 3 | 1, 3 | 2/5 |
| `qdrant-retriever` | api_usage | 6 | 1, 2, 3, 4 | 1, 2, 3, 5 | 1, 2, 3, 4, 5 | 5/5 |
| `fastembed-model` | api_usage | 1 | 1 | 4 | 1 | 1/5 |
| `tree-sitter-parser` | api_usage | 1 | 1 | 1 | 1 | 1/5 |
| `dotenv-load` | api_usage | 1 | — | — | — | 0/5 |
| `tomli-aliased-import` | direct_import | 4 | 1, 2, 3, 5 | 1, 3, 4 | 1, 2, 3, 5 | 4/5 |
| `pytest-test-only` | test_only | 5 | 1, 2, 3, 4 | 4, 5 | 1, 2, 3, 4, 5 | 5/5 |
| `pytest-async-test-only` | test_only | 2 | 1, 3 | 1, 3 | 1, 2 | 2/5 |
| `httpx-mocked-test` | test_only | 1 | 1 | 1 | 1 | 1/5 |
| `langchain-core-transitive-message-use` | direct_import | 4 | 1, 2, 4 | 1, 2, 3, 4 | 1, 2, 3, 5 | 4/5 |
| `langchain-core-transitive-tool-use` | api_usage | 3 | 1, 2, 3 | 1, 2, 4 | 1, 2, 3 | 3/5 |
| `langchain-direct-distribution-import` | direct_import | 4 | 1, 2 | 1, 2, 3 | 1, 2, 3 | 3/5 |
| `serpapi-production-api` | api_usage | 3 | 1, 2, 3 | 1, 2, 4 | 1, 2, 3 | 3/5 |
| `serpapi-mocked-test-only` | test_only | 4 | 1, 2, 3, 4 | 1, 2, 3, 4 | 1, 2, 3, 4 | 4/5 |
| `sendgrid-production-api` | api_usage | 2 | 1, 2 | 1, 3 | 1, 2 | 2/5 |
| `sendgrid-mocked-test-only` | test_only | 1 | 1 | 1 | 1 | 1/5 |
| `aiohttp-transitive-no-source-use` | no_evidence | 0 | — | — | — | 0/5 |
| `gitpython-transitive-no-source-use` | no_evidence | 0 | — | — | — | 0/5 |
| `requests-transitive-no-source-use` | no_evidence | 0 | — | — | — | 0/5 |
| `werkzeug-no-source-use` | no_evidence | 0 | — | — | — | 0/5 |
| `cryptography-weak-security-context` | semantic_context | 1 | — | — | — | 0/5 |

The complete lane rankings (candidate paths, symbols and relevance) were captured during diagnosis in a temporary local file, not committed as a benchmark artifact. The table exposes relevant ranks; false-positive top-five examples and categories above were reviewed against source snippets and labels.

## Evidence-based optimization direction

- Preserve AST chunk boundaries and current Qdrant, FastEmbed, BM25, dense retrieval and RRF architecture.
- Enrich indexed chunk metadata with language, production/test area, parsed imports and bound aliases. Compute metadata from the file AST, but do not treat an import by itself as proof that every chunk uses the package.
- Add a maintainable distribution-to-module map (including `python-dotenv → dotenv`, and reuse existing mappings such as `GitPython → git`) and use it to qualify/rank package-specific candidates.
- Keep test-only and configuration signals distinct. Retain exact package evidence in tests, but rank production usage ahead of test-only matches when evidence is otherwise comparable.
- Retain semantic matches only as explicitly weak context when they have package-specific lexical/import evidence; generic dense-only chunks should not fill a package-usage result list.
- Do not change RRF weights or candidate limits: lane data shows fusion currently helps aggregate precision; changes should target candidate qualification and ranking evidence.

## Limitations

This benchmark is small and manually labelled; the measured differences are engineering signals, not statistical guarantees. The exact per-lane diagnostic depends on the pinned source snapshot and local embedding model. Import/API metadata can establish code references, not vulnerable API reachability or runtime execution.
