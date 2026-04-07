---
name: entra-id-conditional-access
description: Playbook for the CA Gap Agent — identifying Conditional Access policy gaps
---

# Conditional Access Gap Agent

Retrieve all Conditional Access policies and identify gaps in coverage.
Conditional Access is the primary enforcement layer for MFA, device compliance,
location restrictions, and session controls in Entra ID.

## Workflow

### 1. Retrieve all CA policies
```
entra_list_conditional_access_policies()
```

### 2. Check gap_signals first

The tool pre-computes the most common gaps. Check each signal:
- `No enabled CA policy enforces MFA` → report as high immediately
- `No enabled CA policy blocks legacy authentication` → report as high
- `All policies in report-only mode` → report as high — nothing is being enforced

### 3. Build a coverage matrix

From the `policies` list, map which users and apps are covered by enabled policies:

**User coverage:**
- `conditions.users.includeUsers: ["All"]` → covers everyone
- `conditions.users.includeRoles: [...]` → only admins
- `conditions.users.includeGroups: [...]` → only specific groups
- Gap: if no enabled policy covers "All" users for MFA

**Application coverage:**
- `conditions.applications.includeApplications: ["All"]` → all apps
- `conditions.applications.includeApplications: ["Office365"]` → only M365
- Gap: if critical apps (Azure portal, admin center) are not explicitly covered

**Authentication method coverage:**
- `conditions.clientAppTypes` should include `exchangeActiveSync` and `other`
  to catch legacy auth protocols

### 4. Identify specific gaps to report

**No MFA for all users:**
Check if any enabled policy has:
- `conditions.users.includeUsers` containing `"All"`
- `grantControls.builtInControls` containing `"mfa"`

**Legacy authentication not blocked:**
Check if any enabled policy has:
- `conditions.clientAppTypes` containing both `"exchangeActiveSync"` and `"other"`
- `grantControls.builtInControls` containing `"block"`

**Admins without stronger MFA:**
Check if privileged roles are targeted by a dedicated policy requiring
phishing-resistant MFA (FIDO2 or Windows Hello) vs basic MFA.

**No sign-in risk policy:**
Check if any policy uses `conditions.signInRiskLevels` to block or challenge
high-risk sign-ins (requires Entra ID P2 license).

**All policies report-only:**
If `enabled_count=0` and `report_only_count > 0`, nothing is being enforced.

### 5. Report findings

Call `create_identity_finding` for each gap:
- `finding_type`: `ca_gap`
- `affected_objects`: use `[{"object_id": "tenant", "display_name": "All Users", "object_type": "group"}]`
  for tenant-wide gaps
- `evidence`: include relevant policy states and the specific gap detected

## Severity Decision Table

| Condition | Severity |
|-----------|---------|
| No enabled policy enforcing MFA for all users | high |
| Legacy authentication not blocked | high |
| All CA policies in report-only mode | high |
| No policy targeting privileged roles | high |
| Admins have no stronger auth requirement than standard users | medium |
| No sign-in risk-based policy (P2 feature) | medium |
| Named locations not defined (no trusted IP enforcement) | low |
| Some apps excluded from MFA policy without documented reason | low |

## Remediation Templates

**No MFA for all users:**
Create a new CA policy: Entra admin center → Security → Conditional Access → New policy.
Assign to All users (exclude break-glass accounts), target All cloud apps,
grant: Require multifactor authentication. Enable in enforcement mode.

**Legacy authentication not blocked:**
Create a CA policy targeting: All users, All cloud apps,
Client apps: Exchange ActiveSync clients + Other clients.
Grant: Block access. This prevents password spray attacks via legacy protocols.

**All policies in report-only:**
Review each report-only policy. For each that is ready for enforcement,
change state from "Report-only" to "On" via the policy settings.
Establish a process to graduate report-only policies to enforced after a monitoring period.
