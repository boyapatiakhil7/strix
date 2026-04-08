---
name: code_audit_root
description: Root orchestrator playbook for code security audits — language detection, sub-agent spawning, fix proposal phase
---

# Code Audit Root Orchestrator

This skill guides the root `CodeAuditAgent` through the full audit lifecycle.

## Phase 0 — Pre-flight

```bash
# Confirm repo is accessible and detect language
setup_repo(repo=<url_or_path>, run_name=<run_name>, branch=<branch>)
detect_language(repo_path=<local_path>)
```

Use `think` to decide language-specific sub-agent skills before spawning.

## Phase 1 — Spawn Four Parallel Sub-agents

Spawn ALL four simultaneously (single create_agent call per agent, do not wait between spawns):

| Agent Name        | Skills                                      | Task Includes                                        |
|-------------------|---------------------------------------------|------------------------------------------------------|
| SAST Agent        | `gosec,semgrep_go_java`                     | workspace path, run_name, language                   |
| Quality Agent     | `golangci_lint` OR `checkstyle_pmd`         | workspace path, run_name, language, build_system     |
| Coverage Agent    | `go_coverage` OR `jacoco`                   | workspace path, run_name, language, build_system     |
| Secrets Agent     | `gitleaks`                                  | workspace path, run_name                             |

Language routing:
- Go   → Quality: `golangci_lint`,  Coverage: `go_coverage`
- Java → Quality: `checkstyle_pmd`, Coverage: `jacoco`
- Unknown → spawn both Go and Java quality/coverage agents

Sub-agent task template:
```
Audit the repository at /workspace/<subdir> (run_name=<run_name>, language=<lang>).
Run all tools in your assigned skill set. For each finding call create_code_finding.
When done, call agent_finish with findings summary.
```

## Phase 2 — Wait for All Sub-agents

```python
wait_for_message(timeout_seconds=1200)  # 20 min ceiling
```

Call `wait_for_message` repeatedly until all four agents have called `agent_finish`.

## Phase 3 — Fix Proposal Phase

For each `critical` or `high` finding recorded:
1. Read the affected file: `terminal_execute("cat /workspace/<subdir>/<file_path>")`
2. Draft a minimal, correct unified diff
3. Draft a test stub that verifies the fix
4. Call `write_fix_proposal(run_name, finding_id, file_path, unified_diff, test_code, test_file_path)`

Skip fix proposals for:
- Findings with `source_tool=gitleaks` (secret rotation is manual)
- Findings where the fix spans >100 lines or requires architectural change

## Phase 4 — Finish

Call `finish_code_audit` with:
- `executive_summary`: 3-5 paragraphs on posture, top 3 criticals, coverage gap, priorities
- `languages_scanned`: detected languages
- `tools_run`: all tools that executed (from sub-agent finish reports)
- `tools_skipped`: tools that were skipped and why
- `total_findings`: sum of all `create_code_finding` calls

## Common Pitfalls

- **Tool not installed**: sub-agents handle gracefully and report in `agent_finish`; do not block
- **Large repos**: `semgrep` may time out — increase `--timeout` or scope to `--include '*.go'`
- **Java multi-module**: detect build file in subdirectory; pass module root to quality/coverage agents
- **False positives**: do not filter them out; report them and note "may be false positive" in description
