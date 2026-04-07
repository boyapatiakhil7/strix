"""
Microsoft Graph API query tools for Entra ID / Azure AD identity security auditing.

All tools use sandbox_execution=False because they call the external
Microsoft Graph API, not the Docker tool server.

Required app permissions (application type, admin-consented):
  - Directory.Read.All
  - AuditLog.Read.All
  - Policy.Read.All
  - RoleManagement.Read.Directory
  - Application.Read.All
  - User.Read.All
  - Group.Read.All
"""

import logging
from datetime import UTC, datetime, timedelta
from typing import Any

from strix.tools.registry import register_tool

from .entra_auth import graph_get, graph_get_all_pages, graph_get_beta


logger = logging.getLogger(__name__)

# Roles considered privileged — used by Privileged Role Agent and SoD Agent
PRIVILEGED_ROLE_DISPLAY_NAMES = {
    "Global Administrator",
    "Privileged Role Administrator",
    "Security Administrator",
    "Application Administrator",
    "Cloud Application Administrator",
    "Exchange Administrator",
    "User Administrator",
    "Authentication Administrator",
    "Billing Administrator",
    "Conditional Access Administrator",
    "Helpdesk Administrator",
    "Password Administrator",
    "SharePoint Administrator",
    "Teams Administrator",
    "Intune Administrator",
}

# High-risk application permission values
HIGH_RISK_APP_PERMISSIONS = {
    "Directory.ReadWrite.All",
    "User.ReadWrite.All",
    "RoleManagement.ReadWrite.Directory",
    "Mail.ReadWrite",
    "Mail.Send",
    "Files.ReadWrite.All",
    "Sites.FullControl.All",
    "GroupMember.ReadWrite.All",
    "Application.ReadWrite.All",
    "AppRoleAssignment.ReadWrite.All",
    "Policy.ReadWrite.All",
}

# Personal email domains considered higher risk for guest access
PERSONAL_EMAIL_DOMAINS = {
    "gmail.com", "hotmail.com", "outlook.com", "yahoo.com",
    "live.com", "icloud.com", "me.com", "protonmail.com",
    "aol.com", "mail.com",
}


def _parse_datetime(dt_str: str | None) -> datetime | None:
    """Parse an ISO 8601 datetime string returned by Graph API."""
    if not dt_str:
        return None
    try:
        # Graph API returns strings like "2024-01-15T10:30:00Z"
        return datetime.fromisoformat(dt_str.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return None


def _days_since(dt: datetime | None) -> int | None:
    """Return number of days since a datetime, or None if dt is None."""
    if dt is None:
        return None
    return (datetime.now(UTC) - dt).days


def _extract_guest_domain(upn: str) -> str:
    """
    Extract the original domain from a guest UPN.
    Guest UPNs follow the pattern: user_domain.com#EXT#@tenant.onmicrosoft.com
    Returns the domain portion of the original email.
    """
    if "#EXT#" in upn:
        # e.g. john_contoso.com#EXT#@tenant.onmicrosoft.com
        local = upn.split("#EXT#")[0]
        # The last _ separates username from domain
        if "_" in local:
            parts = local.rsplit("_", 1)
            return parts[1] if len(parts) == 2 else ""
    # Fall back to domain part of the UPN
    if "@" in upn:
        return upn.split("@")[1]
    return ""


@register_tool(sandbox_execution=False)
def entra_get_tenant_info() -> dict[str, Any]:
    """
    Retrieve basic tenant information from Entra ID.
    Used by the root agent during pre-flight to establish audit scope context.
    """
    try:
        data = graph_get(
            "organization",
            params={"$select": "id,displayName,verifiedDomains,tenantType,createdDateTime"},
        )
        orgs = data.get("value", [])
        if not orgs:
            return {"success": False, "error": "No organization data returned"}

        org = orgs[0]
        verified_domains = [
            d.get("name", "") for d in org.get("verifiedDomains", [])
            if d.get("isDefault") or d.get("isInitial")
        ]

        return {
            "success": True,
            "tenant_id": org.get("id"),
            "display_name": org.get("displayName"),
            "tenant_type": org.get("tenantType"),
            "created_date": org.get("createdDateTime"),
            "verified_domains": verified_domains,
        }

    except Exception as e:  # noqa: BLE001
        return {"success": False, "error": f"Failed to retrieve tenant info: {e}"}


@register_tool(sandbox_execution=False)
def entra_list_stale_users(
    stale_threshold_days: int = 90,
    include_never_signed_in: bool = True,
) -> dict[str, Any]:
    """
    List enabled user accounts that are stale — either never signed in
    or inactive beyond the specified threshold.

    Args:
        stale_threshold_days: Number of days without sign-in to consider stale.
        include_never_signed_in: Include accounts that have never signed in.
    """
    try:
        users = graph_get_all_pages(
            "users",
            params={
                "$select": (
                    "id,displayName,userPrincipalName,accountEnabled,"
                    "userType,createdDateTime,signInActivity,"
                    "onPremisesSyncEnabled,mail"
                ),
                "$top": "999",
            },
        )

        stale = []
        threshold = datetime.now(UTC) - timedelta(days=stale_threshold_days)

        for user in users:
            if not user.get("accountEnabled"):
                continue

            sign_in_activity = user.get("signInActivity") or {}
            last_sign_in_str = sign_in_activity.get("lastSignInDateTime")
            last_sign_in = _parse_datetime(last_sign_in_str)
            days_inactive = _days_since(last_sign_in)
            created = _parse_datetime(user.get("createdDateTime"))

            if last_sign_in is None:
                # Never signed in
                if not include_never_signed_in:
                    continue
                # Only flag if account is older than the threshold
                if created and _days_since(created) < stale_threshold_days:
                    continue
                stale_reason = "never_signed_in"
                risk_level = "critical"
            elif last_sign_in < threshold:
                stale_reason = f"inactive_{days_inactive}d"
                risk_level = "high" if days_inactive >= 180 else "medium"
            else:
                continue

            stale.append({
                "object_id": user.get("id"),
                "display_name": user.get("displayName"),
                "upn": user.get("userPrincipalName"),
                "mail": user.get("mail"),
                "user_type": user.get("userType"),
                "account_enabled": user.get("accountEnabled"),
                "created_datetime": user.get("createdDateTime"),
                "last_sign_in_datetime": last_sign_in_str,
                "days_inactive": days_inactive,
                "stale_reason": stale_reason,
                "risk_level": risk_level,
                "on_premises_synced": user.get("onPremisesSyncEnabled", False),
            })

        # Sort by risk: critical first, then by days inactive descending
        stale.sort(
            key=lambda x: (
                0 if x["risk_level"] == "critical" else
                1 if x["risk_level"] == "high" else 2,
                -(x["days_inactive"] or 0),
            )
        )

        return {
            "success": True,
            "total_users_scanned": len(users),
            "stale_count": len(stale),
            "threshold_days": stale_threshold_days,
            "stale_users": stale,
        }

    except Exception as e:  # noqa: BLE001
        return {"success": False, "error": f"Failed to list stale users: {e}"}


@register_tool(sandbox_execution=False)
def entra_list_stale_service_principals(
    stale_threshold_days: int = 90,
) -> dict[str, Any]:
    """
    List enabled service principals with no recent sign-in activity.
    Uses the beta servicePrincipalSignInActivities endpoint.

    Args:
        stale_threshold_days: Days without activity to consider stale.
    """
    try:
        # Get all service principals
        service_principals = graph_get_all_pages(
            "servicePrincipals",
            params={
                "$select": "id,appId,displayName,accountEnabled,createdDateTime,servicePrincipalType",
                "$top": "999",
            },
        )

        # Get sign-in activity from beta endpoint
        activity_data = graph_get_all_pages(
            "reports/servicePrincipalSignInActivities",
            params={"$top": "999"},
            beta=True,
        )

        # Build lookup: appId -> lastSignInActivity
        activity_by_app_id: dict[str, Any] = {}
        for activity in activity_data:
            app_id = activity.get("appId")
            if app_id:
                activity_by_app_id[app_id] = activity

        threshold = datetime.now(UTC) - timedelta(days=stale_threshold_days)
        stale = []

        for sp in service_principals:
            if not sp.get("accountEnabled"):
                continue

            app_id = sp.get("appId", "")
            activity = activity_by_app_id.get(app_id, {})

            last_sign_in_str = (
                activity.get("lastSignInActivity", {}).get("lastSignInDateTime")
                if activity
                else None
            )
            last_sign_in = _parse_datetime(last_sign_in_str)
            days_inactive = _days_since(last_sign_in)
            created = _parse_datetime(sp.get("createdDateTime"))

            if last_sign_in is None:
                if created and _days_since(created) < stale_threshold_days:
                    continue
                stale_reason = "never_used"
                risk_level = "high"
            elif last_sign_in < threshold:
                stale_reason = f"inactive_{days_inactive}d"
                risk_level = "high" if days_inactive >= 180 else "medium"
            else:
                continue

            stale.append({
                "object_id": sp.get("id"),
                "app_id": app_id,
                "display_name": sp.get("displayName"),
                "sp_type": sp.get("servicePrincipalType"),
                "account_enabled": sp.get("accountEnabled"),
                "created_datetime": sp.get("createdDateTime"),
                "last_sign_in_datetime": last_sign_in_str,
                "days_inactive": days_inactive,
                "stale_reason": stale_reason,
                "risk_level": risk_level,
            })

        return {
            "success": True,
            "total_sps_scanned": len(service_principals),
            "stale_count": len(stale),
            "threshold_days": stale_threshold_days,
            "stale_service_principals": stale,
        }

    except Exception as e:  # noqa: BLE001
        return {"success": False, "error": f"Failed to list stale service principals: {e}"}


@register_tool(sandbox_execution=False)
def entra_list_privileged_role_assignments(
    include_eligible: bool = True,
) -> dict[str, Any]:
    """
    List all privileged role assignments in the tenant — both direct active
    assignments and PIM-eligible assignments.

    Args:
        include_eligible: If True, also returns PIM-eligible (not yet activated) assignments.
    """
    try:
        # Get role definitions to build a name lookup.
        # Note: isPrivileged is beta-only — filter by PRIVILEGED_ROLE_DISPLAY_NAMES instead.
        role_defs = graph_get_all_pages(
            "roleManagement/directory/roleDefinitions",
            params={"$select": "id,displayName,isBuiltIn"},
        )
        role_def_map: dict[str, dict[str, Any]] = {r["id"]: r for r in role_defs}

        # Active direct assignments
        active_assignments = graph_get_all_pages(
            "roleManagement/directory/roleAssignments",
            params={
                "$expand": "principal",
                "$top": "999",
            },
        )

        assignments = []

        for assignment in active_assignments:
            role_def_id = assignment.get("roleDefinitionId", "")
            role_def = role_def_map.get(role_def_id, {})
            role_name = role_def.get("displayName", role_def_id)

            if role_name not in PRIVILEGED_ROLE_DISPLAY_NAMES:
                continue

            principal = assignment.get("principal", {})
            principal_type = principal.get("@odata.type", "").split(".")[-1]  # user, group, servicePrincipal

            # Expand group members if principal is a group
            group_members: list[dict[str, Any]] = []
            if principal_type == "group":
                try:
                    members = graph_get_all_pages(
                        f"groups/{principal.get('id')}/members",
                        params={"$select": "id,displayName,userPrincipalName,userType"},
                    )
                    group_members = [
                        {
                            "object_id": m.get("id"),
                            "display_name": m.get("displayName"),
                            "upn": m.get("userPrincipalName"),
                            "user_type": m.get("userType"),
                        }
                        for m in members
                    ]
                except Exception:  # noqa: BLE001
                    pass

            assignments.append({
                "assignment_id": assignment.get("id"),
                "role_definition_id": role_def_id,
                "role_name": role_name,
                "is_privileged": True,
                "assignment_type": "active_direct",
                "principal_id": principal.get("id"),
                "principal_display_name": principal.get("displayName"),
                "principal_type": principal_type,
                "principal_upn": principal.get("userPrincipalName"),
                "principal_user_type": principal.get("userType"),
                "directory_scope_id": assignment.get("directoryScopeId"),
                "group_members": group_members,
            })

        # PIM eligible assignments
        if include_eligible:
            try:
                eligible = graph_get_all_pages(
                    "roleManagement/directory/roleEligibilitySchedules",
                    params={
                        "$expand": "principal",
                        "$top": "999",
                    },
                )
                for elig in eligible:
                    role_def_id = elig.get("roleDefinitionId", "")
                    role_def = role_def_map.get(role_def_id, {})
                    role_name = role_def.get("displayName", role_def_id)

                    if role_name not in PRIVILEGED_ROLE_DISPLAY_NAMES:
                        continue

                    principal = elig.get("principal", {})
                    principal_type = principal.get("@odata.type", "").split(".")[-1]

                    assignments.append({
                        "assignment_id": elig.get("id"),
                        "role_definition_id": role_def_id,
                        "role_name": role_name,
                        "is_privileged": True,
                        "assignment_type": "pim_eligible",
                        "principal_id": principal.get("id"),
                        "principal_display_name": principal.get("displayName"),
                        "principal_type": principal_type,
                        "principal_upn": principal.get("userPrincipalName"),
                        "principal_user_type": principal.get("userType"),
                        "schedule_info": elig.get("scheduleInfo"),
                        "group_members": [],
                    })
            except Exception as e:  # noqa: BLE001
                logger.warning(f"Could not retrieve PIM eligible assignments: {e}")

        # Identify high-risk patterns
        risk_flags: list[str] = []
        global_admins = [a for a in assignments if a["role_name"] == "Global Administrator" and a["assignment_type"] == "active_direct"]
        if len(global_admins) > 3:
            risk_flags.append(f"Excessive Global Administrators: {len(global_admins)} direct active assignments (recommended: ≤3 break-glass accounts)")
        guest_in_role = [a for a in assignments if a.get("principal_user_type") == "Guest"]
        if guest_in_role:
            risk_flags.append(f"{len(guest_in_role)} guest user(s) hold privileged role assignments")
        sp_in_role = [a for a in assignments if a.get("principal_type") == "servicePrincipal"]
        if sp_in_role:
            risk_flags.append(f"{len(sp_in_role)} service principal(s) hold privileged role assignments")

        return {
            "success": True,
            "total_privileged_assignments": len(assignments),
            "active_direct_count": sum(1 for a in assignments if a["assignment_type"] == "active_direct"),
            "pim_eligible_count": sum(1 for a in assignments if a["assignment_type"] == "pim_eligible"),
            "risk_flags": risk_flags,
            "assignments": assignments,
        }

    except Exception as e:  # noqa: BLE001
        return {"success": False, "error": f"Failed to list privileged role assignments: {e}"}


@register_tool(sandbox_execution=False)
def entra_list_app_permissions(
    flag_high_risk_only: bool = False,
) -> dict[str, Any]:
    """
    Audit OAuth application permissions, delegated grants, and app registration
    credential hygiene across the tenant.

    Args:
        flag_high_risk_only: If True, only return permissions matching the high-risk list.
    """
    try:
        # App registrations — for credential hygiene
        applications = graph_get_all_pages(
            "applications",
            params={
                "$select": "id,appId,displayName,signInAudience,verifiedPublisher,passwordCredentials,keyCredentials,createdDateTime",
                "$top": "999",
            },
        )

        # Service principals — for permission grants
        service_principals = graph_get_all_pages(
            "servicePrincipals",
            params={
                "$select": "id,appId,displayName,accountEnabled,verifiedPublisher,signInAudience",
                "$top": "999",
            },
        )
        sp_by_id: dict[str, dict[str, Any]] = {sp["id"]: sp for sp in service_principals}
        sp_by_app_id: dict[str, dict[str, Any]] = {sp["appId"]: sp for sp in service_principals}

        # Delegated permission grants (oauth2PermissionGrants)
        delegated_grants = graph_get_all_pages(
            "oauth2PermissionGrants",
            params={
                "$select": "id,clientId,consentType,principalId,resourceId,scope",
                "$top": "999",
            },
        )

        # Application role assignments — query from the resource side (appRoleAssignedTo)
        # for the key Microsoft APIs that host high-risk permissions.
        # This is O(k) calls where k = number of key resource SPs (~5), not O(n) per client SP.
        KEY_RESOURCE_APP_IDS = {
            "00000003-0000-0000-c000-000000000000",  # Microsoft Graph
            "00000002-0000-0ff1-ce00-000000000000",  # Exchange Online
            "00000003-0000-0ff1-ce00-000000000000",  # SharePoint Online
            "00000004-0000-0ff1-ce00-000000000000",  # Skype for Business
            "c5393580-f805-4401-95e8-94b7a6ef2fc2",  # Office 365 Management APIs
        }
        app_role_assignments: list[dict[str, Any]] = []
        for sp in service_principals:
            if sp.get("appId") not in KEY_RESOURCE_APP_IDS:
                continue
            try:
                assignments = graph_get_all_pages(
                    f"servicePrincipals/{sp['id']}/appRoleAssignedTo",
                    params={"$top": "999"},
                )
                for assignment in assignments:
                    client_sp = sp_by_id.get(assignment.get("principalId", ""), {})
                    assignment["_sp_display_name"] = client_sp.get("displayName", assignment.get("principalDisplayName", ""))
                    assignment["_sp_app_id"] = client_sp.get("appId", "")
                    assignment["_resource_display_name"] = sp.get("displayName", "")
                app_role_assignments.extend(assignments)
            except Exception:  # noqa: BLE001
                pass

        now = datetime.now(UTC)
        findings: list[dict[str, Any]] = []

        # --- Check application credential hygiene ---
        for app in applications:
            app_id = app.get("appId", "")
            display_name = app.get("displayName", "")

            for cred in app.get("passwordCredentials", []):
                end_dt = _parse_datetime(cred.get("endDateTime"))
                if end_dt:
                    days_until_expiry = (end_dt - now).days
                    if days_until_expiry < 0:
                        findings.append({
                            "type": "expired_credential",
                            "app_id": app_id,
                            "display_name": display_name,
                            "credential_type": "client_secret",
                            "credential_hint": cred.get("displayName", ""),
                            "end_datetime": cred.get("endDateTime"),
                            "days_until_expiry": days_until_expiry,
                            "risk_level": "medium",
                            "detail": "Expired client secret not removed — credential hygiene issue",
                        })
                    elif days_until_expiry > 365:
                        findings.append({
                            "type": "long_lived_credential",
                            "app_id": app_id,
                            "display_name": display_name,
                            "credential_type": "client_secret",
                            "credential_hint": cred.get("displayName", ""),
                            "end_datetime": cred.get("endDateTime"),
                            "days_until_expiry": days_until_expiry,
                            "risk_level": "low",
                            "detail": f"Client secret valid for {days_until_expiry} days — exceeds 365-day recommended maximum",
                        })

            # Check multi-tenant apps
            sign_in_audience = app.get("signInAudience", "")
            if sign_in_audience in ("AzureADMultipleOrgs", "AzureADandPersonalMicrosoftAccount"):
                findings.append({
                    "type": "multi_tenant_app",
                    "app_id": app_id,
                    "display_name": display_name,
                    "sign_in_audience": sign_in_audience,
                    "risk_level": "medium",
                    "detail": f"App accepts sign-ins from multiple tenants ({sign_in_audience}) — verify this is intentional",
                })

            # Check unverified publisher
            sp = sp_by_app_id.get(app_id)
            if sp and not sp.get("verifiedPublisher") and not app.get("verifiedPublisher"):
                pass  # Only flag if combined with high-risk permissions below

        # --- Check application permissions (appRoleAssignments) ---
        for assignment in app_role_assignments:
            sp = sp_by_id.get(assignment.get("principalId", ""), {})
            resource_sp = sp_by_id.get(assignment.get("resourceId", ""), {})

            # Look up the specific permission value from the resource SP's appRoles
            permission_value = assignment.get("_permission_value", "")
            app_role_id = assignment.get("appRoleId", "")

            # Try to resolve the permission value from the resource SP's appRoles
            for role in resource_sp.get("appRoles", []):
                if role.get("id") == app_role_id:
                    permission_value = role.get("value", "")
                    break

            is_high_risk = permission_value in HIGH_RISK_APP_PERMISSIONS
            if flag_high_risk_only and not is_high_risk:
                continue

            findings.append({
                "type": "app_role_assignment",
                "permission_category": "application",
                "app_id": assignment.get("_sp_app_id", ""),
                "sp_display_name": assignment.get("_sp_display_name", ""),
                "principal_id": assignment.get("principalId"),
                "resource_id": assignment.get("resourceId"),
                "resource_display_name": resource_sp.get("displayName", ""),
                "permission_value": permission_value,
                "app_role_id": app_role_id,
                "risk_level": "critical" if is_high_risk else "low",
                "is_high_risk": is_high_risk,
                "created_datetime": assignment.get("createdDateTime"),
            })

        # --- Check delegated grants ---
        for grant in delegated_grants:
            client_sp = sp_by_id.get(grant.get("clientId", ""), {})
            scopes = (grant.get("scope") or "").split()

            for scope_value in scopes:
                is_high_risk = scope_value in HIGH_RISK_APP_PERMISSIONS
                if flag_high_risk_only and not is_high_risk:
                    continue

                findings.append({
                    "type": "delegated_grant",
                    "permission_category": "delegated",
                    "client_id": grant.get("clientId"),
                    "client_display_name": client_sp.get("displayName", ""),
                    "consent_type": grant.get("consentType"),  # "AllPrincipals" = admin consent
                    "principal_id": grant.get("principalId"),  # null for admin consent
                    "resource_id": grant.get("resourceId"),
                    "permission_value": scope_value,
                    "risk_level": "high" if is_high_risk else "low",
                    "is_high_risk": is_high_risk,
                    "is_admin_consent": grant.get("consentType") == "AllPrincipals",
                })

        return {
            "success": True,
            "total_applications": len(applications),
            "total_service_principals": len(service_principals),
            "total_findings": len(findings),
            "high_risk_count": sum(1 for f in findings if f.get("risk_level") in ("critical", "high")),
            "findings": findings,
        }

    except Exception as e:  # noqa: BLE001
        return {"success": False, "error": f"Failed to list app permissions: {e}"}


@register_tool(sandbox_execution=False)
def entra_list_guests(
    check_role_assignments: bool = True,
    check_group_memberships: bool = True,
) -> dict[str, Any]:
    """
    List all guest (B2B) accounts in the tenant and assess their risk.

    Args:
        check_role_assignments: Cross-reference guests against role assignments.
        check_group_memberships: Retrieve group memberships for each guest.
    """
    try:
        guests = graph_get_all_pages(
            "users",
            params={
                "$filter": "userType eq 'Guest'",
                "$select": "id,displayName,mail,userPrincipalName,accountEnabled,createdDateTime,signInActivity",
                "$top": "999",
            },
        )

        # Optionally get all role assignments for cross-reference
        role_assignment_map: dict[str, list[str]] = {}
        if check_role_assignments:
            try:
                all_assignments = graph_get_all_pages(
                    "roleManagement/directory/roleAssignments",
                    params={"$select": "principalId,roleDefinitionId", "$top": "999"},
                )
                for assignment in all_assignments:
                    pid = assignment.get("principalId", "")
                    role_id = assignment.get("roleDefinitionId", "")
                    if pid:
                        role_assignment_map.setdefault(pid, []).append(role_id)
            except Exception:  # noqa: BLE001
                pass

        guest_records: list[dict[str, Any]] = []

        for guest in guests:
            guest_id = guest.get("id", "")
            upn = guest.get("userPrincipalName", "")
            domain = _extract_guest_domain(upn)
            is_personal_domain = domain.lower() in PERSONAL_EMAIL_DOMAINS

            sign_in_activity = guest.get("signInActivity") or {}
            last_sign_in_str = sign_in_activity.get("lastSignInDateTime")
            last_sign_in = _parse_datetime(last_sign_in_str)
            days_inactive = _days_since(last_sign_in)

            # Group memberships
            group_memberships: list[dict[str, Any]] = []
            if check_group_memberships:
                try:
                    memberships = graph_get_all_pages(
                        f"users/{guest_id}/memberOf",
                        params={"$select": "id,displayName,groupTypes", "$top": "100"},
                    )
                    group_memberships = [
                        {
                            "group_id": m.get("id"),
                            "display_name": m.get("displayName"),
                        }
                        for m in memberships
                        if m.get("@odata.type", "").endswith("group")
                    ]
                except Exception:  # noqa: BLE001
                    pass

            # Role assignments for this guest
            roles = role_assignment_map.get(guest_id, [])

            # Risk classification
            risk_level = "low"
            risk_reasons: list[str] = []

            if roles:
                risk_level = "critical"
                risk_reasons.append(f"Guest holds {len(roles)} privileged role assignment(s)")
            if is_personal_domain and guest.get("accountEnabled"):
                risk_level = max(risk_level, "high") if risk_level != "critical" else risk_level
                risk_reasons.append(f"Guest from personal email domain: {domain}")
            if guest.get("accountEnabled") and days_inactive is not None and days_inactive > 180:
                if risk_level == "low":
                    risk_level = "medium"
                risk_reasons.append(f"Guest enabled but inactive for {days_inactive} days")
            if last_sign_in is None and guest.get("accountEnabled"):
                if risk_level == "low":
                    risk_level = "medium"
                risk_reasons.append("Guest account enabled but has never signed in")

            guest_records.append({
                "object_id": guest_id,
                "display_name": guest.get("displayName"),
                "upn": upn,
                "mail": guest.get("mail"),
                "account_enabled": guest.get("accountEnabled"),
                "created_datetime": guest.get("createdDateTime"),
                "last_sign_in_datetime": last_sign_in_str,
                "days_inactive": days_inactive,
                "original_domain": domain,
                "is_personal_domain": is_personal_domain,
                "role_assignment_ids": roles,
                "group_memberships": group_memberships,
                "risk_level": risk_level,
                "risk_reasons": risk_reasons,
            })

        # Sort by risk
        risk_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        guest_records.sort(key=lambda x: risk_order.get(x["risk_level"], 4))

        return {
            "success": True,
            "total_guests": len(guests),
            "enabled_guests": sum(1 for g in guest_records if g["account_enabled"]),
            "guests_with_roles": sum(1 for g in guest_records if g["role_assignment_ids"]),
            "guests_from_personal_domains": sum(1 for g in guest_records if g["is_personal_domain"]),
            "guests": guest_records,
        }

    except Exception as e:  # noqa: BLE001
        return {"success": False, "error": f"Failed to list guests: {e}"}


@register_tool(sandbox_execution=False)
def entra_list_conditional_access_policies() -> dict[str, Any]:
    """
    Retrieve all Conditional Access policies and named locations.
    The CA Gap Agent uses this raw data to build a coverage matrix
    and identify security gaps.
    """
    try:
        policies = graph_get_all_pages(
            "identity/conditionalAccess/policies",
            params={
                "$select": "id,displayName,state,conditions,grantControls,sessionControls,createdDateTime,modifiedDateTime",
            },
        )

        named_locations = graph_get_all_pages(
            "identity/conditionalAccess/namedLocations",
        )

        enabled = [p for p in policies if p.get("state") == "enabled"]
        report_only = [p for p in policies if p.get("state") == "enabledForReportingButNotEnforced"]
        disabled = [p for p in policies if p.get("state") == "disabled"]

        # Quick gap detection
        gap_signals: list[str] = []

        # Check if any enabled policy enforces MFA
        mfa_policies = [
            p for p in enabled
            if "mfa" in (p.get("grantControls") or {}).get("builtInControls", [])
        ]
        if not mfa_policies:
            gap_signals.append("No enabled CA policy enforces MFA — all users can authenticate without MFA")

        # Check if legacy authentication is blocked
        legacy_auth_block = [
            p for p in enabled
            if any(
                cat in (p.get("conditions") or {}).get("clientAppTypes", [])
                for cat in ("exchangeActiveSync", "other")
            )
        ]
        if not legacy_auth_block:
            gap_signals.append("No enabled CA policy blocks legacy authentication protocols (exchangeActiveSync, other)")

        # All policies in report-only
        if not enabled and report_only:
            gap_signals.append(
                f"All {len(report_only)} CA policies are in report-only mode — "
                "no policies are actively enforced"
            )

        return {
            "success": True,
            "total_policies": len(policies),
            "enabled_count": len(enabled),
            "report_only_count": len(report_only),
            "disabled_count": len(disabled),
            "gap_signals": gap_signals,
            "policies": policies,
            "named_locations": named_locations,
        }

    except Exception as e:  # noqa: BLE001
        return {"success": False, "error": f"Failed to list conditional access policies: {e}"}


@register_tool(sandbox_execution=False)
def entra_list_role_assignments_per_user() -> dict[str, Any]:
    """
    Return all privileged role assignments pivoted to a per-user dict.
    Used by the SoD Agent to apply the conflict matrix across all users.
    Returns: { user_id: [{ role_name, role_definition_id, assignment_type }] }
    """
    try:
        # Get role definitions (isPrivileged is beta-only, omit from $select)
        role_defs = graph_get_all_pages(
            "roleManagement/directory/roleDefinitions",
            params={"$select": "id,displayName"},
        )
        role_def_map: dict[str, str] = {r["id"]: r["displayName"] for r in role_defs}

        # Get all active assignments
        active_assignments = graph_get_all_pages(
            "roleManagement/directory/roleAssignments",
            params={
                "$select": "id,principalId,roleDefinitionId,directoryScopeId",
                "$top": "999",
            },
        )

        # Get PIM eligible assignments
        eligible_assignments: list[dict[str, Any]] = []
        try:
            eligible_assignments = graph_get_all_pages(
                "roleManagement/directory/roleEligibilitySchedules",
                params={
                    "$select": "id,principalId,roleDefinitionId",
                    "$top": "999",
                },
            )
        except Exception:  # noqa: BLE001
            pass

        # Pivot to per-user
        per_user: dict[str, list[dict[str, Any]]] = {}

        for assignment in active_assignments:
            principal_id = assignment.get("principalId", "")
            role_def_id = assignment.get("roleDefinitionId", "")
            role_name = role_def_map.get(role_def_id, role_def_id)

            if principal_id:
                per_user.setdefault(principal_id, []).append({
                    "role_name": role_name,
                    "role_definition_id": role_def_id,
                    "assignment_type": "active_direct",
                })

        for assignment in eligible_assignments:
            principal_id = assignment.get("principalId", "")
            role_def_id = assignment.get("roleDefinitionId", "")
            role_name = role_def_map.get(role_def_id, role_def_id)

            if principal_id:
                per_user.setdefault(principal_id, []).append({
                    "role_name": role_name,
                    "role_definition_id": role_def_id,
                    "assignment_type": "pim_eligible",
                })

        # Find users with multiple roles (SoD candidates)
        multi_role_users = {uid: roles for uid, roles in per_user.items() if len(roles) > 1}

        return {
            "success": True,
            "total_principals_with_roles": len(per_user),
            "multi_role_principals": len(multi_role_users),
            "assignments_per_user": per_user,
        }

    except Exception as e:  # noqa: BLE001
        return {"success": False, "error": f"Failed to list role assignments per user: {e}"}
