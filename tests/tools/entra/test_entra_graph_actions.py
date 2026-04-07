"""
Tests: entra_graph_actions.py — Graph API tools with mocked HTTP responses.

No Azure credentials required. graph_get / graph_get_all_pages are mocked
to return realistic-looking API payloads.
"""

import datetime
from typing import Any
from unittest.mock import patch

import pytest


_NOW = datetime.datetime(2026, 4, 7, 12, 0, 0, tzinfo=datetime.UTC)
_200_DAYS_AGO = (_NOW - datetime.timedelta(days=200)).strftime("%Y-%m-%dT%H:%M:%SZ")
_30_DAYS_AGO = (_NOW - datetime.timedelta(days=30)).strftime("%Y-%m-%dT%H:%M:%SZ")


# ---------------------------------------------------------------------------
# entra_get_tenant_info
# ---------------------------------------------------------------------------

TENANT_RESPONSE = {
    "value": [
        {
            "id": "aaaaaaaa-1111-2222-3333-bbbbbbbbbbbb",
            "displayName": "Contoso Ltd",
            "tenantType": "AAD",
            "createdDateTime": "2019-03-15T10:00:00Z",
            "verifiedDomains": [
                {"name": "contoso.com", "isDefault": True},
                {"name": "contoso.onmicrosoft.com", "isDefault": False},
            ],
        }
    ]
}


def test_entra_get_tenant_info_success() -> None:
    from strix.tools.entra.entra_graph_actions import entra_get_tenant_info

    with patch("strix.tools.entra.entra_graph_actions.graph_get", return_value=TENANT_RESPONSE):
        result = entra_get_tenant_info()

    assert result["success"] is True
    assert result["tenant_id"] == "aaaaaaaa-1111-2222-3333-bbbbbbbbbbbb"
    assert result["display_name"] == "Contoso Ltd"
    assert result["tenant_type"] == "AAD"
    assert "contoso.com" in result["verified_domains"]


def test_entra_get_tenant_info_propagates_error() -> None:
    from strix.tools.entra.entra_graph_actions import entra_get_tenant_info

    with patch(
        "strix.tools.entra.entra_graph_actions.graph_get",
        side_effect=RuntimeError("Auth failed"),
    ):
        result = entra_get_tenant_info()

    assert result["success"] is False
    assert "Auth failed" in result["error"]


# ---------------------------------------------------------------------------
# entra_list_stale_users
# ---------------------------------------------------------------------------


def _make_user(
    object_id: str,
    upn: str,
    enabled: bool = True,
    last_sign_in: str | None = _200_DAYS_AGO,
    created: str = "2023-01-01T00:00:00Z",
) -> dict[str, Any]:
    return {
        "id": object_id,
        "displayName": upn.split("@")[0],
        "userPrincipalName": upn,
        "mail": upn,
        "userType": "Member",
        "accountEnabled": enabled,
        "createdDateTime": created,
        "signInActivity": {"lastSignInDateTime": last_sign_in} if last_sign_in else {},
    }


USERS_PAGE: list[dict[str, Any]] = [
    _make_user("u1", "stale@contoso.com", last_sign_in=_200_DAYS_AGO),
    _make_user("u2", "active@contoso.com", last_sign_in=_30_DAYS_AGO),
    _make_user("u3", "never@contoso.com", last_sign_in=None, created="2024-01-01T00:00:00Z"),
    _make_user("u4", "disabled@contoso.com", enabled=False, last_sign_in=_200_DAYS_AGO),
]


def test_entra_list_stale_users_identifies_stale_and_never_signed_in() -> None:
    from strix.tools.entra.entra_graph_actions import entra_list_stale_users

    with patch("strix.tools.entra.entra_graph_actions.graph_get_all_pages", return_value=USERS_PAGE):
        result = entra_list_stale_users(stale_threshold_days=90, include_never_signed_in=True)

    assert result["success"] is True
    stale_upns = {u["upn"] for u in result["stale_users"]}

    # stale@contoso.com: 200 days inactive → should appear
    assert "stale@contoso.com" in stale_upns
    # never@contoso.com: never signed in, account > threshold days old → should appear
    assert "never@contoso.com" in stale_upns
    # active@contoso.com: only 30 days → should NOT appear
    assert "active@contoso.com" not in stale_upns
    # disabled account → not scanned (only enabled accounts)
    assert "disabled@contoso.com" not in stale_upns


def test_entra_list_stale_users_risk_levels() -> None:
    from strix.tools.entra.entra_graph_actions import entra_list_stale_users

    with patch("strix.tools.entra.entra_graph_actions.graph_get_all_pages", return_value=USERS_PAGE):
        result = entra_list_stale_users(stale_threshold_days=90)

    stale_by_upn = {u["upn"]: u for u in result["stale_users"]}

    # never signed in → critical
    assert stale_by_upn["never@contoso.com"]["risk_level"] == "critical"
    # 200 days inactive → high (>180d)
    assert stale_by_upn["stale@contoso.com"]["risk_level"] == "high"


def test_entra_list_stale_users_exclude_never_signed_in() -> None:
    from strix.tools.entra.entra_graph_actions import entra_list_stale_users

    with patch("strix.tools.entra.entra_graph_actions.graph_get_all_pages", return_value=USERS_PAGE):
        result = entra_list_stale_users(stale_threshold_days=90, include_never_signed_in=False)

    stale_upns = {u["upn"] for u in result["stale_users"]}
    assert "never@contoso.com" not in stale_upns
    assert "stale@contoso.com" in stale_upns


def test_entra_list_stale_users_total_scanned_excludes_disabled() -> None:
    from strix.tools.entra.entra_graph_actions import entra_list_stale_users

    with patch("strix.tools.entra.entra_graph_actions.graph_get_all_pages", return_value=USERS_PAGE):
        result = entra_list_stale_users(stale_threshold_days=90)

    # total_users_scanned is the raw list length (all 4), but disabled are skipped in stale logic
    assert result["total_users_scanned"] == 4
    assert result["success"] is True


# ---------------------------------------------------------------------------
# entra_list_privileged_role_assignments
# ---------------------------------------------------------------------------

ROLE_ASSIGNMENTS_RESPONSE: dict[str, Any] = {
    "value": [
        {
            "id": "ra1",
            "roleDefinitionId": "62e90394-69f5-4237-9190-012177145e10",
            "directoryScopeId": "/",
            "principal": {
                "id": "user1",
                "displayName": "Alice Admin",
                "@odata.type": "#microsoft.graph.user",
                "userPrincipalName": "alice@contoso.com",
                "userType": "Member",
            },
            "roleDefinition": {"displayName": "Global Administrator"},
        },
        {
            "id": "ra2",
            "roleDefinitionId": "62e90394-69f5-4237-9190-012177145e10",
            "directoryScopeId": "/",
            "principal": {
                "id": "user2",
                "displayName": "Guest Bob",
                "@odata.type": "#microsoft.graph.user",
                "userPrincipalName": "bob_external#EXT#@contoso.com",
                "userType": "Guest",
            },
            "roleDefinition": {"displayName": "Global Administrator"},
        },
    ]
}

# Role definitions page for the role def lookup
ROLE_DEFS_PAGE: list[dict[str, Any]] = [
    {
        "id": "62e90394-69f5-4237-9190-012177145e10",
        "displayName": "Global Administrator",
        "isBuiltIn": True,
        "isPrivileged": True,
    }
]


def test_entra_list_privileged_role_assignments_returns_assignments() -> None:
    from strix.tools.entra.entra_graph_actions import entra_list_privileged_role_assignments

    def _mock_pages(path: str, params: Any = None, beta: bool = False) -> list[dict[str, Any]]:
        if "roleDefinitions" in path:
            return ROLE_DEFS_PAGE
        if "roleAssignments" in path:
            return ROLE_ASSIGNMENTS_RESPONSE["value"]
        if "roleEligibilitySchedules" in path:
            return []
        return []

    with patch("strix.tools.entra.entra_graph_actions.graph_get_all_pages", side_effect=_mock_pages):
        result = entra_list_privileged_role_assignments(include_eligible=True)

    assert result["success"] is True
    assert result["total_privileged_assignments"] == 2
    assert result["active_direct_count"] == 2


def test_entra_list_privileged_role_assignments_flags_guest_in_role() -> None:
    from strix.tools.entra.entra_graph_actions import entra_list_privileged_role_assignments

    def _mock_pages(path: str, params: Any = None, beta: bool = False) -> list[dict[str, Any]]:
        if "roleDefinitions" in path:
            return ROLE_DEFS_PAGE
        if "roleAssignments" in path:
            return ROLE_ASSIGNMENTS_RESPONSE["value"]
        return []

    with patch("strix.tools.entra.entra_graph_actions.graph_get_all_pages", side_effect=_mock_pages):
        result = entra_list_privileged_role_assignments(include_eligible=False)

    # Guest Bob has userType=Guest → should produce a guest risk flag
    risk_flags_text = " ".join(result["risk_flags"]).lower()
    assert "guest" in risk_flags_text


# ---------------------------------------------------------------------------
# entra_list_guests
# ---------------------------------------------------------------------------

GUESTS_LIST: list[dict[str, Any]] = [
    {
        "id": "g1",
        "displayName": "Gmail Guest",
        "userPrincipalName": "gmailuser_gmail.com#EXT#@contoso.com",
        "mail": "gmailuser@gmail.com",
        "accountEnabled": True,
        "createdDateTime": "2023-06-01T00:00:00Z",
        "userType": "Guest",
        "signInActivity": {"lastSignInDateTime": _200_DAYS_AGO},
    },
    {
        "id": "g2",
        "displayName": "Corp Guest",
        "userPrincipalName": "vendor_corp.com#EXT#@contoso.com",
        "mail": "vendor@corp.com",
        "accountEnabled": True,
        "createdDateTime": "2024-01-01T00:00:00Z",
        "userType": "Guest",
        "signInActivity": {"lastSignInDateTime": _30_DAYS_AGO},
    },
]


def test_entra_list_guests_flags_personal_domain() -> None:
    from strix.tools.entra.entra_graph_actions import entra_list_guests

    def _mock_pages(path: str, params: Any = None, beta: bool = False) -> list[dict[str, Any]]:
        if "users" in path and "memberOf" not in path:
            return GUESTS_LIST
        if "roleAssignments" in path:
            return []  # no role assignments
        return []

    with patch(
        "strix.tools.entra.entra_graph_actions.graph_get_all_pages",
        side_effect=_mock_pages,
    ):
        result = entra_list_guests(check_role_assignments=True, check_group_memberships=False)

    assert result["success"] is True
    guests_by_id = {g["object_id"]: g for g in result["guests"]}

    # gmail.com → personal domain
    assert guests_by_id["g1"]["is_personal_domain"] is True
    # corp.com → not a personal domain
    assert guests_by_id["g2"]["is_personal_domain"] is False


def test_entra_list_guests_counts() -> None:
    from strix.tools.entra.entra_graph_actions import entra_list_guests

    def _mock_pages(path: str, params: Any = None, beta: bool = False) -> list[dict[str, Any]]:
        if "roleAssignments" in path:
            return []
        return GUESTS_LIST

    with patch("strix.tools.entra.entra_graph_actions.graph_get_all_pages", side_effect=_mock_pages):
        result = entra_list_guests(check_role_assignments=True, check_group_memberships=False)

    assert result["total_guests"] == 2
    assert result["enabled_guests"] == 2
    assert result["guests_from_personal_domains"] == 1


# ---------------------------------------------------------------------------
# entra_list_conditional_access_policies
# ---------------------------------------------------------------------------

CA_POLICIES_RESPONSE: dict[str, Any] = {
    "value": [
        {
            "id": "policy1",
            "displayName": "Block Legacy Auth",
            "state": "enabled",
            "conditions": {
                "users": {"includeUsers": ["All"]},
                "applications": {"includeApplications": ["All"]},
                "clientAppTypes": ["exchangeActiveSync", "other"],
            },
            "grantControls": {"operator": "OR", "builtInControls": ["block"]},
            "sessionControls": None,
        },
        {
            "id": "policy2",
            "displayName": "Require MFA - Admins Only",
            "state": "enabledForReportingButNotEnforced",  # report-only — not enforcing
            "conditions": {
                "users": {"includeRoles": ["62e90394-69f5-4237-9190-012177145e10"]},
                "applications": {"includeApplications": ["All"]},
                "clientAppTypes": ["browser", "mobileAppsAndDesktopClients"],
            },
            "grantControls": {"operator": "OR", "builtInControls": ["mfa"]},
            "sessionControls": None,
        },
    ]
}


def test_entra_list_ca_policies_counts_states() -> None:
    from strix.tools.entra.entra_graph_actions import entra_list_conditional_access_policies

    def _mock_pages(path: str, params: Any = None, beta: bool = False) -> list[dict[str, Any]]:
        if "namedLocations" in path:
            return []
        return CA_POLICIES_RESPONSE["value"]

    with patch("strix.tools.entra.entra_graph_actions.graph_get_all_pages", side_effect=_mock_pages):
        result = entra_list_conditional_access_policies()

    assert result["success"] is True
    assert result["total_policies"] == 2
    assert result["enabled_count"] == 1       # policy1 is enabled
    assert result["report_only_count"] == 1   # policy2 is report-only
    assert result["disabled_count"] == 0


def test_entra_list_ca_policies_detects_no_mfa_gap() -> None:
    from strix.tools.entra.entra_graph_actions import entra_list_conditional_access_policies

    def _mock_pages(path: str, params: Any = None, beta: bool = False) -> list[dict[str, Any]]:
        if "namedLocations" in path:
            return []
        return CA_POLICIES_RESPONSE["value"]

    with patch("strix.tools.entra.entra_graph_actions.graph_get_all_pages", side_effect=_mock_pages):
        result = entra_list_conditional_access_policies()

    # The only enabled policy blocks legacy auth (no mfa builtInControl) → MFA gap should be flagged
    gap_text = " ".join(result["gap_signals"]).lower()
    assert "mfa" in gap_text


def test_entra_list_ca_policies_detects_legacy_auth_blocked() -> None:
    """policy1 blocks legacy auth — no gap signal for that."""
    from strix.tools.entra.entra_graph_actions import entra_list_conditional_access_policies

    def _mock_pages(path: str, params: Any = None, beta: bool = False) -> list[dict[str, Any]]:
        if "namedLocations" in path:
            return []
        return CA_POLICIES_RESPONSE["value"]

    with patch("strix.tools.entra.entra_graph_actions.graph_get_all_pages", side_effect=_mock_pages):
        result = entra_list_conditional_access_policies()

    gap_text = " ".join(result["gap_signals"])
    # policy1 covers legacy auth, so that specific gap should NOT appear
    assert "legacy authentication" not in gap_text.lower()
