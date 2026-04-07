---
name: entra-id-sod
description: Playbook for the SoD Agent — detecting Segregation of Duties conflicts in role assignments
---

# Segregation of Duties (SoD) Agent

Identify principals who hold combinations of roles that together create
dangerous capabilities — full account takeover, privilege escalation, or
unrestricted tenant access — that neither role alone would provide.

## Workflow

### 1. Retrieve per-user role assignments
```
entra_list_role_assignments_per_user()
```

This returns `assignments_per_user`: a dict of `{ principal_id: [roles] }`.
Focus on `multi_role_principals` — principals holding more than one role.

### 2. Apply the SoD conflict matrix

For each principal in `multi_role_principals`, check their role list against
every conflict pair below. Only report when BOTH roles are confirmed
`assignment_type: active_direct` — do not flag PIM-eligible-only combinations.

### SoD Conflict Matrix

| Role A | Role B | Risk | Why |
|--------|--------|------|-----|
| User Administrator | Authentication Administrator | critical | Can manage users AND reset their MFA — full account takeover of any non-GA user |
| Privileged Role Administrator | Security Administrator | critical | Can assign any role AND read all security data — privilege escalation + reconnaissance |
| Application Administrator | Cloud Application Administrator | high | Full control over all app registrations and service principals |
| Exchange Administrator | User Administrator | high | Can read all email AND manage users — email exfiltration path |
| Global Administrator | any other role | informational | GA includes all roles — other role assignment is redundant noise |
| Privileged Role Administrator | Global Administrator | critical | Two paths to full tenant control on one identity |

**Service Principal conflicts:**
If a service principal has BOTH:
- `Directory.ReadWrite.All` (application permission) AND
- `RoleManagement.ReadWrite.Directory` (application permission)

This is a tenant takeover capability — report as critical even though it is not
a traditional role SoD conflict.

### 3. Enrich with principal details

`assignments_per_user` contains only IDs. Cross-reference with data from
other agents if available, or note in evidence that principal details
require a separate lookup via the Graph API.

### 4. Report findings

Call `create_identity_finding` for each confirmed conflict:
- `finding_type`: `sod_conflict`
- `severity`: per the matrix above
- `affected_objects`: the principal holding the conflicting roles
- `description`: what was found — which two roles conflict, who holds them, assignment types (active/eligible)
- `impact`: what the conflict enables — which separation of duties control is broken, what an insider or compromised account can do by combining both roles (e.g. create users AND assign them roles)
- `evidence`: list both conflicting role names, their `assignment_type`, and `role_definition_id`
- `remediation`: see templates below

## What NOT to Report

- Conflicts where one or both roles are `pim_eligible` only (not yet activated)
- `Global Administrator + [any role]` as a security finding — it is redundant but the
  GA role already represents the highest risk; report the GA assignment separately
  via the Privileged Role Agent, not here
- Service principals with only one application permission (no conflict)

## Severity Decision Table

| Conflict | Severity |
|---------|---------|
| User Admin + Authentication Admin | critical |
| Privileged Role Admin + Security Admin | critical |
| Privileged Role Admin + Global Admin | critical |
| SP with Directory.ReadWrite.All + RoleManagement.ReadWrite.Directory | critical |
| Application Admin + Cloud Application Admin | high |
| Exchange Admin + User Admin | high |
| Any two privileged roles on a guest user | high |
| Any two privileged roles on a service principal | high |

## Remediation Templates

**User Administrator + Authentication Administrator:**
Remove one of the two roles. The combination allows full account takeover of
any non-GA user (reset password + reset MFA in sequence).
Separate these responsibilities across two different identities.
Entra admin center → Roles and administrators → [Role] → Remove assignment for [principal].

**Privileged Role Administrator + Security Administrator:**
Privileged Role Admin can assign any role to themselves or others.
Combined with Security Admin, this principal can escalate to GA and read all security alerts.
Retain only the role required for their primary function; use PIM for the other.

**Service Principal with Directory.ReadWrite + RoleManagement.ReadWrite:**
This SP can read and modify the entire directory AND assign any role to any principal.
A compromise of this SP's credentials = complete tenant takeover.
Immediately rotate all credentials for this SP.
Replace with narrowly scoped custom roles targeting only the resources the SP actually needs.
