
## 1. Project Purpose
OSV-Patchpilot is an AI-powered Dependabot PR review agent. It combines dependency analysis, OSV vulnerability intelligence, test comparisons, RAG-based code evidence and AI-generated GitHub reviews.

**Core objective:** Explain the actual impact of a dependency update using accurate, traceable evidence.

## 2. Engineering Principles
- Inspect existing code before modifying it.
- Understand the data flow and identify root causes.
- Prefer small, focused changes over architectural rewrites.
- Reuse existing abstractions and avoid unnecessary dependencies.
- Keep security-critical decisions deterministic.
- Handle missing, invalid and incomplete data explicitly.
- Preserve backward compatibility where practical.
- Add regression tests for meaningful changes.
- Never invent functionality, file paths or test commands.

## 3. GitHub Actions Security
The project uses two workflows:
- **Evidence workflow:** Processes PR changes, collects dependency, OSV and test evidence, and uploads a JSON artifact.
- **Comment workflow:** Verifies the PR author, validates the artifact, executes trusted agent code and posts the review.

Mandatory rules:
- Never execute untrusted Dependabot PR code in the privileged workflow.
- Never check out the Dependabot branch in the commenting workflow.
- Treat downloaded artifacts as untrusted input and validate them.
- Use minimum required GitHub token permissions.
- Keep API keys and write credentials out of the evidence workflow.
- Pin trusted agent code to a verified commit.
- Never weaken the two-workflow security boundary.

## 4. Dependency and OSV Analysis
- Identify changed manifests, lockfiles, packages and versions.
- Compare relevant base and PR dependency snapshots.
- Associate findings with the correct package, ecosystem and version.
- Support classifications: `introduced`, `resolved`, `remaining`, `unaffected`, `not_assessed`.
- Never attribute unrelated baseline findings to a PR.
- Do not associate Python lockfile findings with GitHub Actions updates.
- Do not treat failed or incomplete scans as zero findings.
- Preserve available advisory IDs, severity, affected ranges, fixed versions and dependency paths.
- Distinguish package-advisory matches from unique advisory IDs.
- Never invent missing security information.

## 5. RAG and Source-Code Evidence
RAG provides contextual evidence, not proof of exploitability.

Evidence classifications:
- `direct_import`: Explicit package or module import.
- `package_reference`: Explicit package reference in code or configuration.
- `semantic_context`: Related code without proof of package usage.
- `no_evidence`: No relevant evidence found.

Rules:
- Preserve file paths and line numbers.
- Deduplicate locations and prioritize stronger evidence.
- Never associate packages with files solely through embedding similarity.
- Never present semantic matches as confirmed package usage.
- Return unknown when evidence is insufficient.
- Do not confuse imports with vulnerable function reachability.

## 6. AI Behaviour
Use LLMs for explanation, summarization and evidence synthesis, not authoritative security decisions.

Keep vulnerability classification, version matching, dependency identity and scan status deterministic.

Clearly distinguish verified facts, inferences and unknowns. Avoid unsupported recommendations such as "safe to merge".

## 7. JSON Reports
- Maintain consistent field names and types.
- Validate required fields and handle missing optional fields.
- Preserve evidence provenance.
- Version schema changes.
- Update affected consumers and tests.
- Do not silently change existing field meanings.

## 8. Testing
Inspect existing test conventions before adding tests.

Cover Actions-only updates, introduced/resolved/unchanged vulnerabilities, failed scans, duplicate findings, irrelevant RAG results, invalid artifacts and comment generation.

Run relevant tests after changes. Report actual results; never claim tests passed without executing them.

## 9. Codex Workflow
Before editing:
1. Inspect relevant files and understand existing behaviour.
2. Identify root causes.
3. Plan complex changes.

During editing:
- Work in small, reviewable steps.
- Avoid unrelated refactoring.
- Add regression tests.
- Preserve existing interfaces where practical.

After editing:
- Run relevant tests.
- Review the complete diff.
- Check security implications.
- Update documentation when necessary.

Always report changed files, implementation details, test results and limitations.

## 10. Development Priorities
1. Evidence accuracy and OSV comparison.
2. Dependency graphs and dependency paths.
3. Package usage and application reachability.
4. Compatibility and breaking-change analysis.
5. Evidence-based recommendations and developer experience.

**Prioritize accuracy, traceability and developer trust over adding AI features.**
