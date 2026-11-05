from __future__ import annotations

import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from vulnerability_agent.retrieval import (
    LocalCodeRetriever,
    _trace_locations,
    bm25_rank,
    chunk_source,
    reciprocal_rank_fusion,
    render_context,
)
from vulnerability_agent.dependencies import AgentDependencies
from vulnerability_agent.nodes import patching, usage_analysis


def _run_usage_analysis(tmp_path, monkeypatch, *, package="demo", sources=None, retrieved=None, history=None):
    sources = sources or {}

    class EmptyIndexRetriever:
        def has_index(self, *_args, **_kwargs):
            return False

        def index_sources(self, *_args, **_kwargs):
            return 0

        def retrieve(self, *_args, **_kwargs):
            return retrieved or []

    monkeypatch.setattr(usage_analysis, "_source_paths", lambda *_args: (list(sources), len(sources)))
    monkeypatch.setattr(usage_analysis, "_read_sources", lambda *_args: sources)
    def run(command, *_args, **_kwargs):
        if command[:2] == ["git", "rev-parse"]:
            return SimpleNamespace(returncode=1, stdout="", stderr="")
        if command[:2] == ["git", "grep"]:
            return SimpleNamespace(returncode=1, stdout="", stderr="")
        return SimpleNamespace(returncode=1, stdout="", stderr="")
    monkeypatch.setattr(usage_analysis.subprocess, "run", run)
    result = usage_analysis.node_report_source_usage({
        "repo_path": str(tmp_path), "main_repo_path": str(tmp_path),
        "current_vuln": {"id": "OSV-DEMO", "summary": "demo advisory", "package": {"name": package}},
        "usage_analysis": history or [],
    }, AgentDependencies(tools=object(), code_retriever=EmptyIndexRetriever()))
    return result["current_usage_analysis"]


def test_python_code_is_chunked_by_function_with_line_metadata():
    source = """import requests

def fetch_data(url):
    response = requests.get(url)
    return response.json()

def unrelated():
    return 42
"""

    chunks = chunk_source("src/client.py", source)

    assert [chunk["symbol"] for chunk in chunks] == ["fetch_data", "unrelated"]
    assert chunks[0]["line_start"] == 3
    assert chunks[0]["line_end"] == 5
    assert "requests.get" in chunks[0]["content"]


def test_javascript_chunking_preserves_common_declaration_boundaries():
    chunks = chunk_source("src/client.js", """import axios from 'axios';
export function fetchClient(url) {
  return axios.get(url);
}
""")

    assert len(chunks) == 1
    assert chunks[0]["symbol"] == "fetchClient"
    assert chunks[0]["line_start"] == 2


def test_code_chunker_rejects_sensitive_and_non_code_paths():
    assert chunk_source(".env.py", "SECRET = 'value'") == []
    assert chunk_source("credentials/client.py", "def fetch(): pass") == []
    assert chunk_source("src/package-lock.json", '{"name": "demo"}') == []


def test_source_candidates_accept_filesystem_server_root_object(tmp_path, monkeypatch):
    tree = json.dumps({
        "name": "demo-repo",
        "type": "directory",
        "children": [
            {"name": "app.py", "type": "file"},
            {"name": "tests", "type": "directory", "children": [
                {"name": "test_app.py", "type": "file"},
            ]},
            {"name": ".env", "type": "file"},
        ],
    })
    monkeypatch.setattr(
        patching, "find_package_usage_files", lambda *_args: set(),
    )

    candidates = patching._tree_source_candidates(tree, tmp_path, "jinja2")

    assert candidates == ["app.py", "tests/test_app.py"]


def test_source_candidates_fall_back_to_git_tracked_files_when_mcp_tree_is_unrecognized(tmp_path, monkeypatch):
    monkeypatch.setattr(patching, "find_package_usage_files", lambda *_args: set())
    monkeypatch.setattr(
        patching.subprocess,
        "run",
        lambda *_args, **_kwargs: SimpleNamespace(
            returncode=0,
            stdout="app.py\0tests/test_app.py\0.env.py\0package-lock.json\0",
            stderr="",
        ),
    )

    candidates = patching._tree_source_candidates('{"tree": []}', tmp_path, "aiohttp")

    assert candidates == ["app.py", "tests/test_app.py"]


def test_zero_chunk_rag_index_uses_literal_fallback_for_report_only_locations(tmp_path, monkeypatch):
    app_source = "from demo import render_report\n\ndef show(value):\n    return render_report(value)\n"
    captured = {}

    class FakeTools:
        def call(self, _server, root, tool, args):
            if tool == "read_multiple_files":
                path = args["paths"][0]
                return f"{path}:\n{app_source}"
            if tool == "read_text_file":
                path = Path(args["path"])
                return path.read_text(encoding="utf-8")
            raise AssertionError(f"Unexpected MCP tool: {tool}")

    class EmptyIndexRetriever:
        def has_index(self, _repository, _snapshot_id=""):
            return False

        def index_sources(self, _repository, sources, *, snapshot_id=""):
            captured["sources"] = sources
            return 0

        def retrieve(self, _repository, _query, **_kwargs):
            return []

    monkeypatch.setattr(usage_analysis, "_source_paths", lambda *_args: (["app.py"], 1))
    monkeypatch.setattr(usage_analysis, "_read_sources", lambda *_args: {"app.py": app_source})
    monkeypatch.setattr(usage_analysis.subprocess, "run", lambda *_args, **_kwargs: SimpleNamespace(
        returncode=1, stdout="", stderr="",
    ))
    deps = AgentDependencies(
        tools=FakeTools(), code_retriever=EmptyIndexRetriever(),
    )
    state = {
        "repo_path": str(tmp_path), "main_repo_path": str(tmp_path),
        "current_vuln": {"id": "OSV-DEMO", "summary": "demo advisory", "package": {"name": "demo"}},
        "usage_analysis": [],
    }

    result = usage_analysis.node_report_source_usage(state, deps)

    assert "app.py" in captured["sources"]
    analysis = result["current_usage_analysis"]
    assert analysis["retrieval"]["backend"] == "qdrant_local_hybrid"
    assert "fallback" not in analysis["retrieval"]
    assert analysis["locations"][0]["path"] == "app.py"
    assert analysis["locations"][0]["symbol"] == "import"
    assert analysis["locations"][0]["evidence_classification"] == "direct_import"
    assert "from demo import render_report" in analysis["locations"][0]["excerpt"]
    assert "not prove" in analysis["note"]


def test_python_explicit_import_is_classified_as_direct_import(monkeypatch):
    monkeypatch.setattr(usage_analysis.subprocess, "run", lambda *_args, **_kwargs: SimpleNamespace(
        returncode=1, stdout="", stderr="",
    ))
    location = usage_analysis._explicit_locations(
        "aiohttp", {"src/client.py": "import aiohttp\n\ndef fetch():\n    return aiohttp.get('/')\n"}, Path("/repo"),
    )[0]
    assert location["evidence_classification"] == "direct_import"
    assert location["path"] == "src/client.py"
    assert location["line_start"] == location["line_end"] == 1


def test_package_reference_in_configuration_is_classified(monkeypatch, tmp_path):
    monkeypatch.setattr(usage_analysis.subprocess, "run", lambda *_args, **_kwargs: SimpleNamespace(
        returncode=0, stdout="pyproject.toml:8:aiohttp = '^3.9'\n", stderr="",
    ))
    locations = usage_analysis._configuration_references(tmp_path, "aiohttp")
    assert locations[0]["evidence_classification"] == "package_reference"
    assert locations[0]["path"] == "pyproject.toml"
    assert locations[0]["line_start"] == 8


def test_semantic_retrieval_is_labeled_context_not_package_usage(monkeypatch, tmp_path):
    analysis = _run_usage_analysis(tmp_path, monkeypatch, retrieved=[{
        "path": "src/flights.py", "line_start": 10, "line_end": 14,
        "symbol": "find_flights", "content": "def find_flights():\n    return search()",
    }])
    assert analysis["evidence_classification"] == "semantic_context"
    assert analysis["locations"][0]["evidence_classification"] == "semantic_context"


def test_no_source_match_returns_explicit_no_evidence(monkeypatch, tmp_path):
    analysis = _run_usage_analysis(tmp_path, monkeypatch)
    assert analysis["locations"] == []
    assert analysis["evidence_classification"] == "no_evidence"


def test_duplicate_retrieval_locations_are_removed_and_strongest_evidence_wins():
    locations = usage_analysis._deduplicate_locations([
        {"path": "src/a.py", "line_start": 4, "line_end": 6, "rank": 1, "evidence_classification": "semantic_context"},
        {"path": "src/a.py", "line_start": 4, "line_end": 6, "rank": 5, "evidence_classification": "direct_import"},
    ])
    assert len(locations) == 1
    assert locations[0]["evidence_classification"] == "direct_import"


def test_generic_semantic_location_is_not_reused_for_an_unrelated_package(monkeypatch, tmp_path):
    generic = {"path": "src/common.py", "line_start": 2, "line_end": 4,
               "symbol": "search", "content": "def search():\n    return query()"}
    history = [{"package": "first-package", "locations": [{
        **generic, "evidence_classification": "semantic_context",
    }]}]
    analysis = _run_usage_analysis(
        tmp_path, monkeypatch, package="second-package", retrieved=[generic], history=history,
    )
    assert analysis["locations"] == []
    assert analysis["evidence_classification"] == "no_evidence"


@pytest.mark.parametrize("retrieved", [
    [{"line_start": 1, "line_end": 2, "content": "context"}],
    [{"path": "src/a.py", "line_end": 2, "content": "context"}],
])
def test_retrieval_results_missing_path_or_line_metadata_are_skipped(monkeypatch, tmp_path, retrieved):
    analysis = _run_usage_analysis(tmp_path, monkeypatch, retrieved=retrieved)
    assert analysis["locations"] == []
    assert analysis["evidence_classification"] == "no_evidence"


def test_mcp_multiple_file_output_is_mapped_back_to_relative_paths(tmp_path):
    file_a = tmp_path / "src/a.py"
    file_b = tmp_path / "tests/test_a.py"

    class FakeProxy:
        audit_log = type("Audit", (), {"database_path": tmp_path / "audit.sqlite3"})()

        def call(self, _server, _root, tool, args):
            assert tool == "read_multiple_files"
            assert args["paths"] == [str(file_a), str(file_b)]
            return f"{file_a}:\ndef a():\n    return 1\n\n---\n{file_b}:\ndef test_a():\n    assert 1\n"

    result = AgentDependencies(FakeProxy()).filesystem_read_many(
        tmp_path, ["src/a.py", "tests/test_a.py"],
    )

    assert "def a" in result["src/a.py"]
    assert "def test_a" in result["tests/test_a.py"]


def test_bm25_finds_exact_package_and_symbol_terms():
    documents = [
        {"id": "callsite", "search_text": "src/client.py fetch_data requests.get proxy"},
        {"id": "other", "search_text": "src/format.py render_report jinja template"},
    ]

    assert bm25_rank("requests fetch_data", documents) == ["callsite"]


def test_reciprocal_rank_fusion_rewards_results_found_by_both_retrievers():
    fused = reciprocal_rank_fusion(
        ["shared", "keyword-only"], ["shared", "vector-only"], limit=3,
    )

    assert fused == ["shared", "keyword-only", "vector-only"]


def test_traceback_paths_are_extracted_and_context_has_reviewable_locations():
    frames = _trace_locations(
        'AssertionError\n  File "/repo/tests/test_client.py", line 27, in test_fetch'
    )
    context = render_context([{
        "path": "tests/test_client.py", "line_start": 25, "line_end": 30,
        "symbol": "test_fetch", "content": "assert fetch_data(url)",
    }])

    assert frames == [("test_client.py", 27)]
    assert "tests/test_client.py:25-30 (test_fetch)" in context
    assert "assert fetch_data(url)" in context


class FakeEmbedder:
    """Deterministic vectors let this test exercise real embedded Qdrant."""

    def embed(self, texts):
        for text in texts:
            vector = [0.0] * 384
            for token in set(text.lower().split()):
                slot = int(hashlib.sha256(token.encode()).hexdigest()[:8], 16) % len(vector)
                vector[slot] += 1.0
            yield vector


def test_qdrant_local_index_searches_and_reloads_persisted_chunks(tmp_path):
    pytest.importorskip("qdrant_client")
    repository = tmp_path / "demo-repo"
    repository.mkdir()
    storage = tmp_path / "qdrant"
    sources = {
        "src/client.py": """import requests
def fetch_data(url):
    return requests.get(url)
""",
        "tests/test_client.py": """def test_fetch_data():
    assert fetch_data('https://example.test')
""",
    }

    retriever = LocalCodeRetriever(storage, embedder=FakeEmbedder())
    indexed_count = retriever.index_sources(repository, sources)
    results = retriever.retrieve(repository, "requests fetch_data", limit=3)
    retriever.client.close()

    assert indexed_count >= 2
    assert results
    assert results[0]["path"] == "src/client.py"

    reopened = LocalCodeRetriever(storage, embedder=FakeEmbedder())
    persisted_results = reopened.retrieve(repository, "requests fetch_data", limit=3)
    reopened.client.close()
    assert persisted_results[0]["path"] == "src/client.py"


def test_patch_planner_does_not_retrieve_or_prompt_with_source_context(tmp_path):
    (tmp_path / "requirements.txt").write_text("demo==1.0\n", encoding="utf-8")
    (tmp_path / "app.py").write_text("def use_demo():\n    return True\n", encoding="utf-8")
    captured = {}

    class FakeTools:
        audit_log = type("Audit", (), {"database_path": tmp_path / "audit.sqlite3"})()

        def call(self, _server, _root, tool, args):
            if tool == "read_text_file":
                return Path(args["path"]).read_text(encoding="utf-8")
            raise AssertionError(f"Unexpected MCP tool: {tool}")

    class FakeRetriever:
        def has_index(self, *_args, **_kwargs):
            raise AssertionError("Patch planning must not access the source retriever")

    class FakeModel:
        def invoke(self, prompt):
            captured["prompt"] = prompt
            return SimpleNamespace(content=json.dumps({
                "plan": "Update demo", "edits": [{
                    "file": "requirements.txt", "old": "demo==1.0\n", "new": "demo==2.0\n",
                }],
            }))

    deps = AgentDependencies(tools=FakeTools(), model=FakeModel(), code_retriever=FakeRetriever())
    state = {
        "repo_path": str(tmp_path), "main_repo_path": str(tmp_path),
        "manifest_path": "requirements.txt",
        "current_vuln": {"id": "OSV-DEMO", "summary": "demo advisory", "package": {"name": "demo"}},
        "failure_log": "AssertionError: expected remediation behavior",
        "patch_code": {}, "original_files": {}, "attempt_count": 1,
        "manifest_path": "requirements.txt",
    }

    result = patching.node_investigate_and_plan(state, deps)

    assert "AssertionError" in captured["prompt"]
    assert "app.py" not in captured["prompt"]
    assert "return True" not in captured["prompt"]
    assert "dependency declaration files only" in captured["prompt"]
    assert "source_context" not in result
    assert "retrieval_status" not in result


def test_patch_planner_rejects_application_source_edits(tmp_path):
    (tmp_path / "requirements.txt").write_text("demo==1.0\n", encoding="utf-8")

    class FakeTools:
        audit_log = type("Audit", (), {"database_path": tmp_path / "audit.sqlite3"})()

        def call(self, _server, _root, tool, args):
            assert tool == "read_text_file"
            return Path(args["path"]).read_text(encoding="utf-8")

    class SourceEditModel:
        def invoke(self, _prompt):
            return SimpleNamespace(content=json.dumps({
                "plan": "Change application code", "edits": [{
                    "file": "app.py", "old": "unsafe()", "new": "safe()",
                }],
            }))

    deps = AgentDependencies(tools=FakeTools(), model=SourceEditModel())
    state = {
        "repo_path": str(tmp_path), "manifest_path": "requirements.txt",
        "current_vuln": {"id": "OSV-DEMO", "package": {"name": "demo"}},
        "patch_code": {}, "original_files": {}, "attempt_count": 1,
    }

    with pytest.raises(ValueError, match="not an allowed dependency declaration"):
        patching.node_investigate_and_plan(state, deps)


def test_apply_patch_rejects_source_files_before_creating_a_branch(tmp_path):
    class FakeDependencies:
        def git_call(self, *_args, **_kwargs):
            raise AssertionError("A rejected source patch must not create a branch")

    result = patching.node_apply_patch({
        "repo_path": str(tmp_path), "manifest_path": "requirements.txt",
        "current_vuln": {"package": {"name": "demo"}},
        "patch_code": {"app.py": "unsafe()\n"},
    }, FakeDependencies())

    assert result["error_code"] == "non_dependency_edit_rejected"
    assert "app.py" in result["error"]
