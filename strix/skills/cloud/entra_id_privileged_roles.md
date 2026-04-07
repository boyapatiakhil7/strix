---
name: entra-id-privileged-roles
description: Playbook for the Privileged Role Agent — auditing role assignments and over-privilege
---

# Privileged Role Agent

Audit all privileged role assignments in the tenant. Identify over-privileged users,
service principals with administrative roles, guests in privileged positions,
and excessive Global Administrator counts.

## Workflow

### 1. Retrieve all privileged role assignments
```
entra_list_privileged_role_assignments(include_eligible=true)
```

This returns both active direct assignments and PIM-eligible assignments,
and automatically flags high-level risk patterns in `risk_flags`.

### 2. Analyze risk_flags first

The tool pre-computes these signals — check each one:
- `Excessive Global Administrators` → report if > 3 active direct GAs
- `guest user(s) hold privileged role assignments` → report each guest individually (critical)
- `service principal(s) hold privileged role assignments` → report each SP (high or critical)

### 3. Triage individual assignments

For each assignment in the `assignments` list:

**Global Administrator (active_direct):**
- Count total GAs. Recommended maximum is 2-3 break-glass accounts.
- Report as high if count is 4-5, critical if > 5.

**Guest users in any privileged role:**
- Always critical regardless of role — external identities should never hold privilege.

**Service principals with Global Administrator:**
- Critical — a compromised app = full tenant takeover.

**Service principals with other privileged roles:**
- High — assess what the SP can do with that role.

**PIM eligible assignments:**
- Informational for most roles.
- Flag as medium if a guest user is PIM-eligible for any privileged role.

### 4. Report findings

Call `create_identity_finding` for each confirmed issue:
- `finding_type`: `privileged_role`
- `affected_objects`: the principal (user, SP, or group)
- `description`: what was found — who holds which role, assignment type (active/eligible), how it was discovered
- `impact`: what an attacker can do with this role — tenant takeover for GA, user modification for User Admin, policy bypass for CA Admin
- `evidence`: include `role_name`, `assignment_type`, `principal_type`, `principal_user_type`

## Severity Decision Table

| Condition | Severity |
|-----------|---------|
| Guest user with any privileged role | critical |
| Service principal with Global Administrator | critical |
| Global Administrator count > 5 | critical |
| Global Administrator count 4–5 | high |
| Service principal with privileged role (non-GA) | high |
| Inactive user with privileged role | high |
| PIM-eligible guest for any role | medium |
| Non-privileged role with broad scope | low |

## Remediation Templates

**Guest with privileged role:**
Remove the role assignment immediately via Entra admin center → Roles and administrators
→ [Role] → Remove assignment for [guest].
If the guest requires access, scope to the minimum necessary permission via a custom role
or use Azure RBAC on specific resources only.

**Too many Global Administrators:**
Review each GA account. Retain only 2-3 break-glass accounts with GA.
Demote others to Security Reader or the minimum role required for their function.
Ensure GA accounts are cloud-only (not synced from on-premises AD).

**Service principal with privileged role:**
Identify the owning application and assess whether the role is necessary.
Replace GA/privileged roles with a custom role scoped to minimum required permissions.
Rotate the SP's credentials immediately if the assignment cannot be explained.
