# Open Source Vulnerability Patch Agent

A local Python project that demonstrates how an AI workflow can help with dependency security. It has two related workflows:

1. **Remediate OSV findings:** scan a clean local Git repository, propose a dependency-version update, run tests, verify the advisory with OSV, then pause for your approval before pushing a branch and opening a pull request.
2. **Review a Dependabot pull request:** compare the target branch and Dependabot change, run tests on both snapshots, compare OSV findings, collect report-only source usage clues with hybrid RAG, and produce a short review report. It can optionally post one concise comment to the existing PR.

This is an educational project, not an unattended security bot. Review every proposed diff and report. Use a disposable clone while learning.

## Contents

- [How the workflows work](#how-the-workflows-work)
- [Requirements and setup](#requirements-and-setup)
- [Configure credentials](#configure-credentials)
- [CLI commands](#cli-commands)
- [Dependabot automation with GitHub Actions](#dependabot-automation-with-github-actions)
- [Reports and where to find them](#reports-and-where-to-find-them)
- [RAG and source usage clues](#rag-and-source-usage-clues)
- [Run this project's tests](#run-this-projects-tests)
- [Project layout](#project-layout)
- [Limitations and safety notes](#limitations-and-safety-notes)
- [Troubleshooting](#troubleshooting)

## How the workflows work

### A. Remediate OSV findings in a local repository

```text
Read supported manifest/lockfile
        ↓
Resolve exact package versions and query Google's OSV API
        ↓
For each finding: create an isolated worktree and security branch
        ↓
Run baseline tests → propose dependency-only update → regenerate lockfile if needed
        ↓
Run tests again → re-scan OSV to check the advisory is gone
        ↓
Pause for your review and approval
        ↓
Commit and push the branch → request a GitHub PR
```

The workflow groups advisories for the same package and checks OSV's affected/fixed ranges for a common candidate version. If it cannot verify a safe shared version, it records a conflict for human review instead of guessing. It processes package groups one at a time and creates one PR for each successful package group. After a fix, it scans the changed dependency state again so advisories resolved by the same version update can be skipped. Failed groups are recorded and the batch continues where possible. The agent changes dependency declarations and generated lockfiles; RAG source search is report-only and does not generate application-code edits.

Every PR requires a human approval checkpoint. Approval allows the agent to push its branch and open a PR; it does **not** merge the PR.

### B. Review an existing Dependabot PR

```text
Read Dependabot PR metadata and exact base/head commits
        ↓
Create isolated snapshots → prepare test environments
        ↓
Run base tests, then PR tests
        ↓
Scan both snapshots with OSV and compare resolved/introduced/remaining advisories
        ↓
Collect RAG source usage clues and best-effort release context
        ↓
Write compact evidence JSON → optionally ask the LLM for a concise review
        ↓
Optionally update one comment on the existing PR
```

This mode reviews the existing Dependabot change. It does not edit the PR, create a branch, push, or merge. For CI, the recommended setup separates evidence collection (which executes dependency installs/tests) from the trusted job that analyzes the JSON and posts a comment.

## Requirements and setup

### Prerequisites

- Python 3.10 or newer.
- Git.
- Node.js with `npx` for the MCP filesystem server.
- `uv` with `uvx` for the MCP Git server.
- Poetry and/or `uv` when a target Python repository needs its lockfile regenerated.
- An OpenAI API key for AI patch planning or AI review. Collection-only Dependabot mode does not need it.
- A GitHub token for GitHub PR metadata, pushing/opening PRs, or posting comments, depending on the workflow.

The MCP servers are launched by the agent as needed; you do not start them in separate terminals.

### Install the agent

From this project's folder:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

On Windows PowerShell, activate with:

```powershell
.venv\Scripts\Activate.ps1
```

The agent's own dependencies are installed in this project's `.venv`. The target repository may need its own dependencies for tests; the Dependabot review mode prepares isolated test environments from that repository's lockfile or requirements file.

### Configure credentials

The CLI loads environment variables from a `.env` file in the current working directory. Create one in this project's root (do not commit it):

```dotenv
OPENAI_API_KEY=your-openai-api-key
OPENAI_MODEL=gpt-4o-mini
GITHUB_TOKEN=your-github-token
```

`OPENAI_MODEL` is optional; the default is `gpt-4o-mini`. OSV is free to query and does not require a key. For GitHub, use a token with only the permissions needed for the operation and the target repository. A token used for Dependabot review must be able to read the PR; posting a comment requires issue-comment write permission. Opening a PR or pushing requires write access to that repository.

LangSmith tracing is optional. Add these variables to `.env` to enable it:

```dotenv
LANGSMITH_TRACING=true
LANGSMITH_API_KEY=your-langsmith-api-key
LANGSMITH_PROJECT=local-vulnerability-patch-agent
```

Traces may include repository-derived text, prompts, test output, or proposed changes. Enable tracing only if you are comfortable sending that data to your LangSmith workspace.

## CLI commands

Activate the agent environment first, or use `.venv/bin/python` in place of `python`.

### Start a new OSV scan and remediation run

Use a clean Git checkout. The agent refuses to overwrite a working tree with local changes.

```bash
python main.py "/absolute/path/to/clean-repository"
```

Optional flags:

```bash
python main.py "/path/to/repository" \
  --thread-id my-demo-run \
  --report "/path/to/extra-copy.json" \
  --state-db "/path/to/workflow-state.sqlite3"
```

- `--thread-id` gives the workflow a known ID; otherwise the CLI generates one.
- `--report` saves an extra copy at the path you choose. Reports are also archived automatically; see [Reports and where to find them](#reports-and-where-to-find-them).
- `--state-db` changes the SQLite database used for resumable LangGraph state and MCP audit records.

### Approve a proposed change

The scan pauses before pushing/opening the PR. Read the terminal summary and saved JSON report, then approve the only pending run (or choose one if there are multiple):

```bash
python main.py --approve
```

You can also resume a specific run. The CLI prints its thread ID when it pauses:

```bash
python main.py --resume THREAD_ID --approve-pr
```

To resume a run that stopped before the approval checkpoint:

```bash
python main.py --resume THREAD_ID
```

Running `python main.py` without arguments in an interactive terminal opens a dashboard where you can start a scan, review pending approvals, resume a run, or view recent reports. In a non-interactive shell, provide the repository path or a CLI action.

### Review a Dependabot PR locally

Generate evidence and an AI review without posting a GitHub comment:

```bash
python main.py "/path/to/clean-clone" \
  --review-pr https://github.com/OWNER/REPOSITORY/pull/123
```

You can use the PR number instead of a URL if the clone's `origin` points to that GitHub repository:

```bash
python main.py "/path/to/clean-clone" --review-pr 123
```

### Safer two-step Dependabot review

Step 1 collects tests, OSV, dependency-change, and RAG evidence without calling an LLM. It does not need `OPENAI_API_KEY`:

```bash
python main.py "/path/to/clean-clone" \
  --review-pr 123 \
  --collect-only \
  --report "/tmp/dependabot-evidence.json"
```

Step 2 analyzes that report. To post/update the PR comment, include the expected PR number, repository, and full PR head commit SHA:

```bash
python main.py \
  --analyze-report "/tmp/dependabot-evidence.json" \
  --post-comment \
  --expected-pr 123 \
  --expected-repository OWNER/REPOSITORY \
  --expected-head-sha FULL_PR_HEAD_SHA
```

This second step reads the saved JSON; it does not check out or run the Dependabot branch. It needs `OPENAI_API_KEY` and a `GITHUB_TOKEN` with permission to create or update an issue comment. The report identity is checked against the expected repository, PR number, Dependabot author, and head SHA before posting.

To include a GitHub Actions artifact page in the report and PR comment, pass its URL when analyzing the collected report:

```bash
python main.py \
  --analyze-report "/tmp/dependabot-evidence.json" \
  --post-comment \
  --report-artifact-url "https://github.com/OWNER/REPOSITORY/actions/runs/RUN_ID/artifacts/ARTIFACT_ID" \
  --expected-pr 123 \
  --expected-repository OWNER/REPOSITORY \
  --expected-head-sha FULL_PR_HEAD_SHA
```

The CLI validates that the artifact URL is a GitHub Actions artifact for the same repository as the evidence. `--post-comment` cannot be combined with `--review-pr`; use the two-step flow when posting comments.

### See all CLI options

```bash
python main.py --help
```

## Dependabot automation with GitHub Actions

Example workflows are in [`examples/github-actions/`](examples/github-actions/):

- `dependabot-review-evidence.yml` runs for Dependabot PR events, collects evidence, and uploads a JSON artifact with a 30-day retention period. It does not receive an OpenAI secret or write-capable token.
- `dependabot-review-comment.yml` runs after evidence collection. It checks out the trusted agent revision, downloads the artifact, validates the PR identity, asks the model for a concise review, and posts or updates one comment. It does not check out or execute the Dependabot branch.

To enable the example in a target repository:

1. Copy both workflow files into the target repository's `.github/workflows/` folder.
2. Add repository variables:
   - `VULNERABILITY_AGENT_REPOSITORY`: `OWNER/REPOSITORY` for this agent's GitHub repository.
   - `VULNERABILITY_AGENT_COMMIT`: a reviewed, immutable full commit SHA for the agent. Do not use a moving branch name.
3. Add an Actions secret named `OPENAI_API_KEY`.
4. Add OPENAI_API_KEY and a fine-grained REVIEW_COMMENT_TOKEN secret. Limit REVIEW_COMMENT_TOKEN to this repository with Issues: Read and write permission. The built-in workflow token only needs actions:read and contents:read; the evidence job needs contents:read and pull-requests:read.
5. Open or update a Dependabot PR and inspect the workflow run and resulting comment.

The workflow files use version tags for GitHub Actions as readable examples. Before relying on them in a production repository, review and pin each third-party action to a verified immutable commit SHA. The evidence workflow executes dependency installation and tests, so use ephemeral GitHub-hosted runners or another isolated environment.

More details are in the [Dependabot review guide](docs/DEPENDABOT_REVIEW.md).

## Reports and where to find them

Every CLI run automatically saves a JSON report under:

```text
saved report/
```

The filenames start with `run-` for OSV remediation runs and `review-` for Dependabot PR reviews. The folder is inside this agent project. Use `--report PATH` to write an additional copy somewhere convenient, such as `/tmp` or a reports folder in your workspace.

### Dependabot review JSON

The Dependabot report uses a compact, navigable layout:

- `summary`: recommendation, dependency update, test outcomes, OSV counts, and brief RAG summary.
- `pull_request` and `dependency_changes`: PR identity and package version changes.
- `tests`: compact base and PR test outcomes; useful error output is retained when setup or tests fail.
- `osv_scans` and `security_delta`: package-advisory findings with installed versions, severity and affected/fixed range data when OSV supplies it, manifest provenance, dependency relationship/path, and references. Missing advisory metadata is marked unavailable. Findings are keyed by package, ecosystem, and advisory ID; `unique_advisory_count` is separate from package-advisory finding counts. Schema version 3 retains the prior introduced, resolved, remaining, unaffected, and not-assessed classifications.
- `source_usage`: up to three likely source locations per package, labeled as application or test code.
- `release_context`: best-effort release notes or links where available.
- `ai_review`: concise model assessment when analysis has run.
- `report_artifact_url`: available when an Actions artifact URL was supplied.

The GitHub PR comment presents the key results first, shows only a few source clues, collapses the AI details, and links to the full Actions artifact when available.

OSV remediation reports use a separate run-report structure with workflow status, scan findings, test attempts, verification, pending approval, branch/PR information, and failures. The approval checkpoint stores resumable state in SQLite (by default under `~/.vulnerability-patch-agent/`).

## RAG and source usage clues

RAG is used as a **reporting aid** during Dependabot review and OSV remediation. It indexes a bounded set of Python/JavaScript/TypeScript source files, chunks code with AST/Tree-sitter where possible, and combines local vector search (Qdrant/FastEmbed) with BM25 keyword search. Each reported location is labeled `direct_import`, `package_reference`, or `semantic_context`; packages with no traceable location are labeled `no_evidence`. Semantic matches are context only and are never presented as proof of package usage. Direct imports and textual references do not prove vulnerable code is reachable. Lockfile mentions alone are not treated as source evidence.

These results help a developer navigate to code that may use a dependency. They do not prove the dependency is reachable or vulnerable, and they are not instructions for an automatic source-code patch. The remediation LLM focuses on dependency declarations; it does not receive these source excerpts as patch context.

The local index is stored outside the target repository under the agent's state directory (normally `~/.vulnerability-patch-agent/code-index/`). The first run may download embedding/parser models. If vector retrieval cannot initialize, the agent falls back to literal package-name search and reports that fallback.

## Run this project's tests

From the agent project directory, with its virtual environment active:

```bash
pytest -q
```

Or run without activating the environment:

```bash
.venv/bin/python -m pytest -q
```

The suite uses mocks for OSV, GitHub, MCP, and model calls. It does not create real PRs or require API keys.

## Project layout

| Path | Purpose |
| --- | --- |
| `main.py` | CLI, interactive dashboard, progress messages, report saving, and workflow resume/approval. |
| `vulnerability_agent/graph.py` | LangGraph state machine for scanning, dependency patching, tests, verification, approval, and PR creation. |
| `vulnerability_agent/nodes/` | Focused graph nodes for scanning, patching, RAG usage reporting, batch worktrees, and PRs. |
| `vulnerability_agent/state.py` | Shared graph state and helper functions. |
| `vulnerability_agent/dependabot_review.py` | Dependabot PR fetching, test comparison, OSV scans, release context, and compact evidence generation. |
| `vulnerability_agent/review_graph.py` | Dependabot evidence analysis and concise, idempotent GitHub comment generation. |
| `vulnerability_agent/retrieval.py` | Code chunking, local vector indexing, and hybrid retrieval. |
| `osv_service.py` | Dependency parsing and OSV API requests. |
| `mcp_client.py`, `mcp_config.json` | Launch MCP servers, enforce tool policy, and audit tool calls. |
| `sandbox_runner.py` | Runs tests with a filtered child-process environment and timeout. This is not a full sandbox. |
| `persistence.py` | SQLite persistence for LangGraph checkpoints and audit data. |
| `reporting.py` | Structured remediation reports and source-text redaction. |
| `settings.py` | Shared model setting and default. |
| `examples/github-actions/` | Example split workflows for Dependabot evidence and comment posting. |
| `docs/DEPENDABOT_REVIEW.md` | Detailed Dependabot workflow and GitHub Actions setup. |
| `docs/BEGINNER_STUDY_GUIDE.md` | Beginner-oriented tour of the code and Python packages. |
| `tests/` | Unit tests for parsing, graph routing, retrieval, security guardrails, and Dependabot review. |

## Limitations and safety notes

- The agent can update dependency declarations and regenerate supported lockfiles; it does not fix application source vulnerabilities.
- OSV results depend on the manifest/lockfile formats and exact versions the parser can resolve. Supported inputs include Python `requirements.txt`, `poetry.lock`, and `uv.lock`, plus npm `package.json`, `package-lock.json`, and `npm-shrinkwrap.json`. Unpinned or unsupported dependency formats may be reported as unresolved; an empty scan does not prove a repository is vulnerability-free.
- The Dependabot test setup is best-effort. Projects with custom monorepo commands, platform-specific dependencies, or test services may need manual configuration. `requirements.txt` without a lockfile is not a reproducible snapshot.
- The test runner removes inherited API/cloud/SSH secrets from the test subprocess, but it is not a container or operating-system sandbox. Untrusted tests still run with the local user's filesystem permissions.
- RAG is bounded and may miss relevant use sites or return noisy matches. Treat every location as a navigation clue.
- OSV verification checks whether the scanned version still reports the advisory at scan time. It does not prove exploitability is removed in every deployment environment or prove the code is safe.
- Review the generated diff, lockfile, test output, and report before approving or merging. The agent creates a PR only after explicit approval; it never merges.
- GitHub Actions examples should be adapted and security-reviewed before use. In particular, pin actions by immutable commit SHA and keep the untrusted evidence job separate from the job that has secrets or write permissions.

## Troubleshooting

| Problem | What to check |
| --- | --- |
| `OPENAI_API_KEY is required` | Add it to `.env` in the agent folder or export it in the terminal. Collection-only Dependabot mode does not call the model. |
| MCP filesystem or Git server will not start | Confirm Node.js/`npx` and `uv`/`uvx` are installed and available in `PATH`. |
| Agent says the target has local changes | Run `git status` in the target repo; commit, stash, or discard your own changes before starting. |
| `--approve` says no run is waiting | Use the same state database as the original run. Without `--state-db`, the default database is under `~/.vulnerability-patch-agent/`. You can also resume with the thread ID shown in the report. |
| `--approve-pr` says the thread is not at approval | The run may have finished, failed, or be paused at a different step. Inspect the latest saved report and use `--resume THREAD_ID` only for a resumable run. |
| Dependabot base/head refs do not match | The PR may have changed during collection. Retry after GitHub finishes updating/rebasing the PR. |
| Test environment unavailable | Check the target's lockfile and package manager, Python/Node versions, and installation output in the saved review report. |
| No OSV findings appear | Confirm a supported manifest or lockfile contains exact resolved versions. Unpinned requirements cannot establish the installed package version. |
| Cannot find the report | Look in this project's `saved report/` folder; filenames begin with `run-` or `review-`. `--report PATH` also writes a copy to a chosen location. |
