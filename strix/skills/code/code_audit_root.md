---
name: code_audit_root
description: Root orchestrator playbook for code security audits — module discovery, sub-agent spawning, think/fix agent orchestration
---

# Code Audit Root Orchestrator

This skill guides the root `CodeAuditAgent` through the full audit lifecycle.

## Phase 0 — Pre-flight

```python
setup_repo(repo=<url_or_path>, run_name=<run_name>, branch=<branch>)
detect_language(repo_path=<local_path>)
```

Then discover ALL modules — scan tools do not cross module boundaries:

```python
# Go monorepo: find every go.mod
list_files_local(path=<repo_path>, pattern="**/go.mod")
# → filter out paths containing vendor/, .git/
# → parent directory of each go.mod is a module root

# Java: find every pom.xml or build.gradle
list_files_local(path=<repo_path>, pattern="**/pom.xml")
list_files_local(path=<repo_path>, pattern="**/build.gradle")
# → filter out target/, build/, .gradle/
```

Build a modules_json string: `'["api/", "workers/platform/", "workers/graph/"]'`

Use `think()` to decide language-specific sub-agent skills.

## Phase 1 — Spawn Four Parallel Sub-agents

Spawn ALL four simultaneously:

| Agent         | Skills                                | Receives                                      |
|---------------|---------------------------------------|-----------------------------------------------|
| SAST Agent    | `gosec,semgrep_go_java`               | repo_path, run_name, language, modules_json   |
| Quality Agent | `golangci_lint` OR `checkstyle_pmd`   | repo_path, run_name, language, modules_json   |
| Coverage Agent| `go_coverage` OR `jacoco`             | repo_path, run_name, language, modules_json   |
| Secrets Agent | `gitleaks`                            | repo_path, run_name                           |

Language routing:
- Go   → Quality: `golangci_lint`,  Coverage: `go_coverage`
- Java → Quality: `checkstyle_pmd`, Coverage: `jacoco`

Sub-agent task template:
```
Audit the repository at <repo_path> (run_name=<run_name>, language=<lang>).
modules_json: <modules_json>
Run all tools in your skill set. Scanning tools record findings internally.
Call agent_finish with a summary of findings recorded and tools skipped.
```

## Phase 2 — Wait for All Sub-agents

```python
wait_for_message(timeout_seconds=1200)  # 20-min ceiling
```

Call `wait_for_message` repeatedly until all four agents have called `agent_finish`.
Collect finding IDs and summaries from each `agent_completion_report`.

## Phase 3 — Fix Proposal Phase

Group all `critical` and `high` findings by `rule_id`. For each distinct rule group, spawn ONE Think+Fix agent pair that covers ALL affected files for that rule.

### Grouping rules:
- Group findings that share the same `rule_id` (e.g. all G404 findings together, all G118 together)
- Each group gets ONE Think Agent → ONE Fix Agent
- The Fix Agent must write fix proposals for ALL files in the group
- Do NOT spawn one agent per file — spawn one per rule pattern

### Fix proposal priority:
- ONLY coverage findings (go-coverage, jacoco) get Think+Fix agents
- ALL other findings (SAST, quality, secrets) are recorded but do NOT get fix proposals — note them in recommendations instead
- This keeps the audit focused on improving test coverage as the primary deliverable

### Step A: Spawn Think Agent (one per rule group)
```
Task: "Analyze this rule violation pattern and determine the safest fix approach.
Use think() to reason step by step — root cause, attack surface, fix options, risks.
Do NOT read any files. Call agent_finish with your fix strategy.

Rule: <rule_id> (<count> occurrences)
Severity: <severity>
Affected files:
  - <file_path_1>:<line_number_1>
  - <file_path_2>:<line_number_2>
  ...
Description: <description from first finding>
Impact: <impact>"
```

Wait for Think Agent via `wait_for_message`.

### Step B: Spawn Fix Agent (one per coverage rule group)
```
Task: "Write test proposals to improve coverage for the modules listed below.
Coverage strategy: <think_agent_finish_summary>
For EACH module:
1. Use read_source_file to read the source files with lowest coverage (focus on exported functions)
2. Use list_files_local to check if a _test.go file already exists
3. Write idiomatic Go/Java test code covering the most critical untested paths
4. Call write_fix_proposal with:
   - unified_diff="" (empty — no source changes needed)
   - test_code=<the full test file content>
   - test_file_path=<e.g. handler_test.go>
5. After ALL modules are addressed, call agent_finish

Modules to cover:
  - <finding_id_1>: <module_path_1> (current coverage: X%)
  - <finding_id_2>: <module_path_2> (current coverage: Y%)
  ..."
```

Wait for Fix Agent via `wait_for_message`.

## Phase 4 — Finish

```python
finish_code_audit(
    architecture_summary=<codebase structure, attack surface, security posture — 2-3 paragraphs>,
    technical_analysis=<findings breakdown by category with severity counts and examples>,
    recommendations=<prioritised remediation actions: immediate, short-term, medium-term>,
    languages_scanned=<detected languages>,
    tools_run=<all tools that executed>,
    tools_skipped=<tools skipped and why>,
    total_findings=<sum of all findings recorded>,
)
```

## Common Pitfalls

- **Tool not installed**: scan tools return `{skipped: true, reason: ...}` — log in agent_finish and continue
- **Large repos**: semgrep may be slow — it uses a 120s internal timeout per scan
- **Multi-module Go**: always pass the full `modules_json` to run_gosec, run_golangci_lint, run_go_coverage
- **Java multi-module**: run_jacoco runs from repo root — it picks up the top-level Maven/Gradle config
- **False positives**: do not filter — report them and note "may be false positive" in description
