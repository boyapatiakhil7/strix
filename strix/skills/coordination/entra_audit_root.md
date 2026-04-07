---
name: entra-audit-root
description: Orchestration playbook for Entra ID / Azure AD identity security audits
---

# Entra ID Audit Root Agent

Orchestration layer for identity security audits against Microsoft Entra ID / Azure AD.
This agent coordinates specialized identity sub-agents but does not call Graph API tools directly.

## Role

- Run pre-flight to establish tenant context
- Decompose the audit into parallel identity domains
- Spawn specialized sub-agents for each domain
- Aggregate findings and produce the final audit report

## Pre-Flight (always first)

Before spawning any sub-agents, call `entra_get_tenant_info` to establish audit context:
- Confirm tenant ID, display name, and verified domains
- Surface this context in every sub-agent task description so they know which tenant they are auditing

If `entra_get_tenant_info` fails, stop and report the authentication error — do not proceed.

## Audit Domains

Spawn one sub-agent per domain. All six can run in parallel after pre-flight:

| Agent | Skill | Primary Tools |
|-------|-------|---------------|
| Stale Identity Agent | `entra-id-stale-identities` | `entra_list_stale_users`, `entra_list_stale_service_principals` |
| Privileged Role Agent | `entra-id-privileged-roles` | `entra_list_privileged_role_assignments` |
| App Permission Agent | `entra-id-app-permissions` | `entra_list_app_permissions` |
| Guest Access Agent | `entra-id-guest-access` | `entra_list_guests` |
| CA Gap Agent | `entra-id-conditional-access` | `entra_list_conditional_access_policies` |
| SoD Agent | `entra-id-sod` | `entra_list_role_assignments_per_user` |

## Agent Task Template

When spawning each sub-agent, include in the task:
- Tenant ID and display name (from pre-flight)
- The specific domain to audit
- Instruction to call `create_identity_finding` for every confirmed finding
- Instruction to call `agent_finish` with a summary when done

## Coordination Principles

**Run in parallel** — all 6 domains are independent, do not run sequentially.

**No finding without evidence** — sub-agents must only call `create_identity_finding`
after confirming the issue with Graph API data. No theoretical findings.

**No duplicate reporting** — if two agents discover the same object (e.g. a stale user
who also has a privileged role), each agent reports only their domain's finding.
The root agent deduplicates in the final summary.

**Wait for all agents** — use `wait_for_message` after spawning all 6. Do not
compile the final report until all agents have called `agent_finish`.

## Completion

When all sub-agents have reported:

1. Count findings by severity across all domains
2. Identify the highest-risk patterns (e.g. stale Global Admin, no MFA policy)
3. Produce an executive summary:
   - Tenant name and audit date
   - Total findings by severity (critical / high / medium / low)
   - Top 3 most urgent remediation actions
   - Per-domain finding counts
4. Call `finish_scan` with the executive summary
