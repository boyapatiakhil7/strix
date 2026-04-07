---
name: entra-id-overview
description: Entra ID / Azure AD concepts and identity security fundamentals for audit agents
---

# Entra ID Overview

Reference knowledge for all identity audit agents. Load this skill to understand
the Entra ID object model, permission types, and risk taxonomy used across all domains.

## Core Object Types

**Users** — Human identities. Two types:
- `Member` — internal users in the tenant
- `Guest` — external B2B users invited from other tenants or personal email

**Service Principals** — Non-human app identities. Created automatically when an
app registration is consented to. Used by automation, CI/CD, and third-party SaaS.

**Groups** — Collections of users/SPs. Can be assigned roles directly.

**App Registrations** — The definition of an application in the tenant. Each has
one or more service principals (one per tenant that consented).

## Role Assignment Model

**Active Direct** — User holds the role right now, no activation needed.

**PIM Eligible** — User can activate the role on-demand via Privileged Identity
Management. Not currently active but represents latent privilege.

**Privileged Roles to prioritize:**
- Global Administrator — unrestricted tenant access
- Privileged Role Administrator — can assign any role, including GA
- Security Administrator — broad security configuration access
- Application Administrator — can manage all app registrations and service principals
- User Administrator — can reset passwords and manage users
- Authentication Administrator — can reset MFA for non-admin users

## Permission Types

**Application permissions** — Granted to a service principal, no user involved.
Operates at tenant scope. Highest risk category — a compromised SP with
`Directory.ReadWrite.All` can modify any object in the tenant.

**Delegated permissions** — Granted to an app acting on behalf of a signed-in user.
Scoped to what the user can do. Admin-consented delegated grants (`consentType=AllPrincipals`)
apply to all users in the tenant.

## Risk Taxonomy

| Risk Level | Meaning |
|-----------|---------|
| critical | Direct path to full tenant compromise (e.g. stale GA, SP with RoleManagement.ReadWrite) |
| high | Significant risk requiring prompt action (e.g. guest with privileged role, no MFA) |
| medium | Elevated risk with mitigating factors (e.g. stale account 90-180d, broad delegated grant) |
| low | Minor policy violation with limited direct impact |
| informational | Observation for awareness, no immediate action required |

## Sign-In Activity

`signInActivity.lastSignInDateTime` requires `AuditLog.Read.All` permission.
If this field is null it means either:
1. The user has never signed in, OR
2. The `AuditLog.Read.All` permission was not granted

Always check that the permission was consented before concluding "never signed in".

## Key Attack Paths

- Stale privileged account → attacker compromises it undetected → tenant takeover
- Guest with GA role → external party controls the tenant
- App with Directory.ReadWrite.All → app compromise = full directory access
- No MFA policy → password spray / credential stuffing succeeds silently
- SoD conflict (User Admin + Auth Admin) → full account takeover of any non-GA user
