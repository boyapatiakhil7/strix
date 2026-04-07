---
name: entra-id-app-permissions
description: Playbook for the App Permission Agent — auditing OAuth permissions and credential hygiene
---

# App Permission Agent

Audit OAuth application permissions, delegated grants, and app registration
credential hygiene across the tenant. Over-permissioned apps and forgotten
credentials are a primary lateral movement path in Entra ID.

## Workflow

### 1. Retrieve all app permissions
```
entra_list_app_permissions(flag_high_risk_only=false)
```

Start with all permissions to get full coverage. You will triage by risk level.

### 2. Triage by finding type

The tool returns findings in these categories:

**`app_role_assignment` (application permissions):**
- Filter `is_high_risk=true` → report each individually as critical
- These are service-to-service permissions with no user involved
- `Directory.ReadWrite.All`, `RoleManagement.ReadWrite.Directory`, `Mail.ReadWrite` are the most dangerous

**`delegated_grant` (delegated permissions):**
- Filter `is_admin_consent=true` AND `is_high_risk=true` → report as high
- Admin-consented delegated grants apply to ALL users in the tenant, not just the consenting user
- Check `consent_type`: `AllPrincipals` = admin consent (tenant-wide), `Principal` = user consent (scoped)

**`expired_credential`:**
- Report as medium — expired secrets left on apps are a hygiene signal
- Old credentials may still be in use by legacy integrations

**`long_lived_credential`:**
- Report as low — secrets valid > 365 days violate least-privilege for credentials
- Recommend rotating to 6-12 month expiry

**`multi_tenant_app`:**
- Report as medium if the app has high-risk permissions AND is multi-tenant
- Multi-tenant alone is informational — context matters

### 3. Prioritize unverified publisher + high-risk permissions

If an app has `is_high_risk=true` permissions AND no verified publisher,
escalate severity by one level — unverified publishers cannot be held accountable.

### 4. Report findings

Call `create_identity_finding` for each confirmed issue:
- `finding_type`: `app_permission`
- `affected_objects`: the app registration or service principal
- `description`: what was found — app name, which permissions it holds, consent type (admin/user), whether publisher is verified
- `impact`: what an attacker who compromises this app can do with these permissions — read all mail, modify directory, assign roles, exfiltrate files; note if the app has no human oversight
- `evidence`: include `permission_value`, `permission_category`, `consent_type`, `is_high_risk`

## High-Risk Permission Reference

| Permission | Risk | Why |
|-----------|------|-----|
| `Directory.ReadWrite.All` | critical | Read and write all directory objects |
| `RoleManagement.ReadWrite.Directory` | critical | Assign any role including GA |
| `User.ReadWrite.All` | critical | Modify any user including admins |
| `Application.ReadWrite.All` | critical | Create/modify apps and SPs |
| `AppRoleAssignment.ReadWrite.All` | critical | Grant any permission to any app |
| `Mail.ReadWrite` | high | Read and write all users' email |
| `Mail.Send` | high | Send email as any user |
| `Files.ReadWrite.All` | high | Read and write all SharePoint/OneDrive files |
| `Sites.FullControl.All` | high | Full control of all SharePoint sites |

## Severity Decision Table

| Condition | Severity |
|-----------|---------|
| App role assignment with critical permission | critical |
| Admin-consented delegated grant with high-risk scope | high |
| Multi-tenant app with critical permissions + unverified publisher | high |
| Expired credential on app with high-risk permissions | medium |
| Multi-tenant app with high-risk permissions | medium |
| Expired credential (any app) | medium |
| Long-lived credential (> 365 days) | low |
| Multi-tenant app with no sensitive permissions | informational |

## Remediation Templates

**High-risk application permission:**
Review whether the permission is genuinely required. If not, remove via
Entra admin center → Enterprise applications → [app] → Permissions → Revoke.
If required, ensure the app's credentials are rotated regularly and the app is monitored.

**Admin-consented delegated grant:**
Revoke via Entra admin center → Enterprise applications → [app] → Permissions → Revoke admin consent.
Re-grant only the minimum scopes necessary.

**Expired/long-lived credential:**
Rotate the credential via App registrations → [app] → Certificates & secrets.
Implement a process to rotate secrets on a 6-12 month cadence.
Consider using certificate credentials instead of client secrets where possible.
