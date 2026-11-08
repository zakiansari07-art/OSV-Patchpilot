## 1. Project Purpose

OSV Patchpilot reviews Dependabot pull requests using dependency comparisons,
OSV vulnerability intelligence, base/PR test results, package-usage retrieval,
and an optional AI-generated assessment/comment.

**Core objective:** explain the impact of a dependency update using accurate,
traceable evidence while keeping the review read-only unless a comment is
explicitly requested.

## 2. Engineering Principles

- Inspect existing code and tests before modifying behavior.
- Prefer focused changes and existing abstractions.
- Keep vulnerability classification, package identity, version comparison,
  report validation, and PR identity checks deterministic.
- Handle missing, invalid, and incomplete evidence explicitly.
- Treat PR code, diffs, test logs, advisories, and downloaded artifacts as
  untrusted input.
- Never make unsupported claims about exploitability or safety.

## 3. GitHub Actions Security

The project uses two example workflows:

- **Evidence workflow:** checks out the Dependabot snapshot, installs its
  dependencies, runs tests, gathers OSV/RAG evidence, and uploads JSON. It has
  read-only GitHub permissions and no OpenAI or write-capable secret.
- **Comment workflow:** checks out trusted agent code, downloads and validates
  JSON evidence, verifies PR identity, and optionally posts a comment. It must
  never check out or execute the Dependabot branch.

Keep the trust boundary intact. Use least-privilege permissions and pin trusted
code and third-party Actions to reviewed immutable commits before deployment.

## 4. Dependency and OSV Evidence

- Compare exact base and PR commits and preserve snapshot provenance.
- Associate advisories with the correct package, ecosystem, and resolved
  version.
- Distinguish introduced, resolved, remaining, unchanged, and not-assessed
  findings; unchanged dependencies can still have affected advisories.
- Do not treat failed or incomplete scans as zero findings.
- Preserve advisory IDs, affected ranges, fixed versions, severity, and
  dependency paths when available.

## 5. RAG and Source Evidence

RAG results are review leads, not proof of vulnerable behavior or
exploitability. Preserve file paths, line numbers, symbols, and evidence
classification. Keep test-only and semantic context distinct from production
imports/API use. Similarity alone must not establish package usage.

Preserve Qdrant, FastEmbed, BM25, dense retrieval, RRF, syntax-aware chunking,
package/import mappings, and the active v3 evaluation. The v2 dataset and
results are historical artifacts and must remain unchanged.

## 6. AI and Reports

- Use the model to summarize evidence, not decide authoritative security facts.
- Clearly distinguish evidence, inference, and unknowns.
- Validate required report fields and cross-section consistency before
  consuming a downloaded report or posting a comment.
- Require the expected PR number, repository, Dependabot author, and head SHA
  before posting from a collected artifact.
- Keep LangSmith tracing and metadata intact. Traces can contain repository
  text and prompts; do not expose credentials in trace data.

## 7. Testing and Workflow

- Keep tests for OSV comparison, base/PR test handling, invalid artifacts,
  comment identity, read-only MCP access, RAG evidence, and GitHub Actions
  boundaries.
- Add regression tests for meaningful behavior changes.
- Run relevant tests and report actual results.
- Before editing, inspect data flow and identify the owning component. After
  editing, review the full diff, imports, security implications, and docs.
