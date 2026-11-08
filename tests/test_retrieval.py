from __future__ import annotations

import hashlib
from pathlib import Path
from types import SimpleNamespace

import pytest

from vulnerability_agent.retrieval import (
    LocalCodeRetriever,
    _enrich_chunk_metadata,
    _package_evidence,
    _package_ranked_ids,
    _trace_locations,
    bm25_rank,
    chunk_source,
    reciprocal_rank_fusion,
    render_context,
)
from vulnerability_agent.package_imports import distribution_import_modules, package_search_terms
from vulnerability_agent.dependencies import AgentDependencies
from vulnerability_agent.nodes import usage_analysis


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
    assert analysis["retrieval"]["fallback"] == "literal package search"
    assert analysis["locations"][0]["path"] == "app.py"
    assert analysis["locations"][0]["symbol"] == "import statement"
    assert analysis["locations"][0]["evidence_classification"] == "direct_import"
    assert "render_report" in analysis["locations"][0]["excerpt"]
    assert "not prove" in analysis["note"]


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


def _indexed_chunk(path: str, source: str, symbol: str) -> dict:
    chunk = next(chunk for chunk in chunk_source(path, source) if chunk["symbol"] == symbol)
    return _enrich_chunk_metadata(path, source, chunk)


def test_package_import_mapping_includes_nonmatching_distribution_names():
    assert "git" in distribution_import_modules("GitPython")
    assert "dotenv" in distribution_import_modules("python-dotenv")
    assert "PIL" in distribution_import_modules("Pillow")
    assert "dotenv" in package_search_terms("python-dotenv")
    assert "pytest" in distribution_import_modules("pytest-asyncio")


def test_package_evidence_detects_aliased_production_api_usage():
    document = _indexed_chunk(
        "src/client.py",
        "import requests as http\n\ndef fetch(url):\n    return http.get(url)\n",
        "fetch",
    )

    assert document["source_area"] == "production"
    assert document["used_import_bindings"] == ["http"]
    assert _package_evidence(document, "requests") == "api_usage"


def test_package_evidence_detects_submodule_and_from_import_aliases():
    version = _indexed_chunk(
        "src/versions.py",
        "from packaging.version import Version as V\n\ndef parse(value):\n    return V(value)\n",
        "parse",
    )
    dotenv = _indexed_chunk(
        "src/config.py",
        "from dotenv import load_dotenv as load\n\ndef configure():\n    load()\n",
        "configure",
    )

    assert _package_evidence(version, "packaging") == "api_usage"
    assert _package_evidence(dotenv, "python-dotenv") == "api_usage"


def test_package_evidence_keeps_tests_and_mocks_out_of_production_usage():
    document = _indexed_chunk(
        "tests/test_client.py",
        "from sendgrid import SendGridAPIClient\n\ndef test_delivery():\n    client = SendGridAPIClient()\n    assert client.send('message')\n",
        "test_delivery",
    )

    assert document["source_area"] == "test"
    assert _package_evidence(document, "sendgrid") == "test_only"


def test_package_evidence_recognizes_a_mocked_symbol_from_another_module():
    document = _indexed_chunk(
        "tests/test_delivery.py",
        "def test_delivery(monkeypatch):\n"
        "    class FakeSendGrid: pass\n"
        "    monkeypatch.setattr(agent_module, 'SendGridAPIClient', FakeSendGrid)\n",
        "test_delivery",
    )

    assert _package_evidence(
        document, "sendgrid", query="sendgrid mocked test delivery",
        package_symbols={"SendGridAPIClient"},
    ) == "test_only"
    assert _package_evidence(
        document, "sendgrid", query="advisory release context includes tests",
        package_symbols={"SendGridAPIClient"}, test_context=False,
    ) is None


def test_package_evidence_drops_unrelated_semantic_chunks_but_keeps_literal_context():
    unrelated = _indexed_chunk(
        "src/workflow.py",
        "def process_request(value):\n    return handle(value)\n",
        "process_request",
    )
    context = _indexed_chunk(
        "src/workflow.py",
        "def explain():\n    return 'requests configure an HTTP client'\n",
        "explain",
    )

    assert _package_evidence(unrelated, "requests") is None
    assert _package_evidence(context, "requests") == "semantic_context"


def test_package_ranking_prioritizes_verified_production_over_weak_context():
    production = _indexed_chunk(
        "src/client.py", "import httpx\n\ndef fetch():\n    return httpx.get('/')\n", "fetch",
    )
    test = _indexed_chunk(
        "tests/test_client.py", "import httpx\n\ndef test_fetch():\n    return httpx.get('/')\n", "test_fetch",
    )
    unrelated = _indexed_chunk(
        "src/workflow.py", "def fetch():\n    return handle_request()\n", "fetch",
    )
    for index, item in enumerate((production, test, unrelated)):
        item["id"] = str(index)

    assert _package_evidence(unrelated, "httpx") is None
    assert _package_ranked_ids([production, test, unrelated], ["1", "2", "0"], "httpx") == ["0", "1", "2"]


def test_semantic_context_is_retained_only_when_repository_has_package_evidence():
    production = _indexed_chunk(
        "src/client.py", "import requests\n\ndef fetch():\n    return requests.get('/')\n", "fetch",
    )
    generic = _indexed_chunk(
        "src/workflow.py", "def handle():\n    return process_request()\n", "handle",
    )
    unrelated = _indexed_chunk(
        "src/workflow.py", "def handle():\n    return process_request()\n", "handle",
    )
    for index, item in enumerate((production, generic, unrelated)):
        item["id"] = str(index)

    assert _package_ranked_ids([production, generic], ["1"], "requests") == ["0", "1"]
    assert _package_ranked_ids([unrelated], ["2"], "requests") == []


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
