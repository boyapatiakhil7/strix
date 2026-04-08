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

For each `critical` or `high` finding (excluding gitleaks secrets):

### Step A: Spawn Think Agent
```
Task: "Analyze this finding and determine the safest fix approach.
Use think() to reason step by step — root cause, attack surface, fix options, risks.
Do NOT read any files. Call agent_finish with your fix strategy.
Finding:
  id: <finding_id>
  rule_id: <rule_id>
  file_path: <file_path>
  line_number: <line_number>
  description: <description>
  impact: <impact>"
```

Wait for Think Agent via `wait_for_message`.

### Step B: Spawn Fix Agent
```
Task: "Write a fix proposal for <finding_id> in <file_path>.
Fix strategy: <think_agent_finish_summary>
1. Use read_source_file to read lines around <line_number> for context
2. Use search_files_local to find all callers if the fix changes a signature
3. Write a correct unified diff
4. Call write_fix_proposal(run_name=<run_name>, finding_id=<finding_id>, ...)
5. Call agent_finish when done"
```

Wait for Fix Agent via `wait_for_message`.

### Skip fix proposals for:
- Any finding from `source_tool=gitleaks` (rotate secrets manually)
- Findings where fix requires architectural change (note this in executive_summary)
- Findings with severity `low` or `info`

## Phase 4 — Finish

```python
finish_code_audit(
    executive_summary=<3-5 paragraphs: posture, top 3 criticals, coverage gaps, priorities>,
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
