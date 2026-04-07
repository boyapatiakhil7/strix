---
name: entra-id-guest-access
description: Playbook for the Guest Access Agent — auditing external B2B identities
---

# Guest Access Agent

Audit all guest (B2B external) accounts in the tenant. External identities
have a different risk profile from internal users — they cannot be managed
via internal HR processes and their home tenant security posture is unknown.

## Workflow

### 1. Retrieve all guests
```
entra_list_guests(check_role_assignments=true, check_group_memberships=true)
```

### 2. Check summary counts first

Review the top-level counts before individual records:
- `guests_with_roles` → any value > 0 is critical priority
- `guests_from_personal_domains` → personal email guests warrant immediate review
- `enabled_guests` vs `total_guests` → if many are disabled, confirm they were properly offboarded

### 3. Triage individual guests

**Guests with role assignments (`role_assignment_ids` not empty):**
- Critical — external identity controlling internal resources
- Report each individually regardless of which role

**Guests from personal domains (`is_personal_domain=true`):**
- High — personal email accounts (gmail.com, hotmail.com, etc.) have weaker security
  controls than corporate accounts; no corporate MDM, MFA policy, or offboarding process
- Report as a group finding if there are many, or individually if they also have role assignments

**Stale guests (`days_inactive > 180` and `account_enabled=true`):**
- Medium — former contractors, vendors, or partners who no longer need access
- Group into a single finding if more than 5 stale guests

**Guests who never signed in (`last_sign_in_datetime=null` and `account_enabled=true`):**
- Medium — invitation accepted but never used, or invitation never accepted
- May indicate an invitation sent to the wrong address

### 4. Check group memberships

For high-risk guests (roles or personal domains), review `group_memberships`:
- Membership in groups with broad permissions (e.g. "All Company", "IT Admins") elevates risk
- Include notable group memberships in the evidence field

### 5. Report findings

Call `create_identity_finding` for each confirmed issue:
- `finding_type`: `guest_access`
- `affected_objects`: the guest user object(s)
- `description`: what was found — guest UPN, domain, days inactive or never signed in, how it was discovered
- `impact`: what an attacker who compromises this guest account can access — tenant resources, group memberships, any role assignments; personal domain guests have no corporate security controls
- `evidence`: include `original_domain`, `is_personal_domain`, `role_assignment_ids`,
  `days_inactive`, `risk_reasons` from the tool result

## Severity Decision Table

| Condition | Severity |
|-----------|---------|
| Guest with any privileged role assignment | critical |
| Guest from personal domain with role assignment | critical |
| Guest from personal domain (no role) | high |
| Stale guest with role assignment (> 90 days inactive) | high |
| Guest with broad group memberships | medium |
| Stale guest, no roles (> 180 days inactive) | medium |
| Guest who never signed in (account enabled) | medium |
| Large number of guests from same unknown domain | low |

## Remediation Templates

**Guest with privileged role:**
Remove the role assignment immediately. If the external user requires access,
use resource-specific Azure RBAC (e.g. on a specific resource group) rather
than directory-level roles.

**Personal domain guest:**
Review whether a personal email account is appropriate for this access.
Request the vendor or contractor use a corporate email address.
Enforce terms of use and MFA via Conditional Access policies targeting guest users.

**Stale guest:**
Review with the sponsoring internal user whether access is still required.
Implement an access review: Entra admin center → Identity Governance → Access reviews.
Configure automatic guest expiration via External Collaboration Settings.

**Never signed in:**
Check whether the invitation email was delivered and accepted.
If the invitation has expired (> 30 days), delete and re-invite if still needed.
If no longer needed, delete the guest account.
