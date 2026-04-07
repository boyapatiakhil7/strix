---
name: entra-id-stale-identities
description: Playbook for the Stale Identity Agent — detecting dormant users and service principals
---

# Stale Identity Agent

Identify enabled user accounts and service principals that are dormant — either
never signed in or inactive beyond threshold. Stale identities are unmonitored
attack surface: a compromised dormant account produces no anomalous sign-in signals.

## Workflow

### 1. Scan stale users
Call `entra_list_stale_users` with default threshold (90 days):
```
entra_list_stale_users(stale_threshold_days=90, include_never_signed_in=true)
```

### 2. Scan stale service principals
Call `entra_list_stale_service_principals`:
```
entra_list_stale_service_principals(stale_threshold_days=90)
```

### 3. Triage results

For each stale user, assess:
- **Risk level critical** (`never_signed_in`) → report individually if account is older than 90 days
- **Risk level high** (`inactive_Xd` where X ≥ 180) → report individually
- **Risk level medium** (90–180 days inactive) → group into a single bulk finding if more than 5

For stale service principals:
- Report each individually — SPs have no human owner to notice compromise
- Check if the SP has any role assignments (cross-reference with privileged role data if available)

### 4. Report findings

For each critical/high individual finding call `create_identity_finding`:
- `finding_type`: `stale_identity`
- `severity`: match the `risk_level` from the tool result
- `affected_objects`: the specific user or SP object
- `description`: what was found — account name, days inactive, last sign-in date, how it was discovered
- `impact`: what an attacker could do if this dormant account is compromised — unmonitored access, no anomaly signals, blast radius based on any role assignments
- `evidence`: include `last_sign_in_datetime`, `days_inactive`, `stale_reason`, `created_datetime`
- `remediation`: see remediation templates below

For medium bulk findings, create one finding with all affected objects listed.

## Severity Decision Table

| Condition | Severity |
|-----------|---------|
| Never signed in + account > 90 days old | critical |
| Inactive > 180 days | high |
| Inactive 90–180 days | medium |
| Service principal never used | high |
| Service principal inactive > 180 days | high |

## Remediation Templates

**Stale user account:**
Disable in Entra admin center → Users → [user] → Edit → Account status: Disabled.
If confirmed no longer needed, delete the account and remove any role assignments first.
Consider implementing a Lifecycle Workflow to automatically disable accounts after [threshold] days of inactivity.

**Never signed in:**
Confirm with the account owner whether the account is still required.
If provisioned for a contractor or project that has ended, disable and schedule deletion.

**Stale service principal:**
Identify the owning team via the app registration's owner list.
If the application is decommissioned, delete the service principal and revoke all credentials.
If still active, investigate why sign-in activity is absent — the app may be broken.

## Do Not Report

- Disabled accounts (already remediated at the account level)
- Accounts younger than the threshold (recently created, no sign-in yet is normal)
- Break-glass emergency accounts (typically named "break-glass" or "emergency-admin") —
  these are intentionally unused; flag separately as informational if they lack MFA
