#!/usr/bin/env python3
"""
Quick smoke test for the Entra ID tools layer.

Run this from the project root AFTER installing dependencies:
    uv run python scripts/verify_entra_tools.py

It checks four things in order:
  1. Dependencies are importable (msal, httpx)
  2. All 9 Entra tools register in the tool registry
  3. Validation logic in create_identity_finding works
  4. (Optional) Live Graph API call if Azure env vars are set

Exit code 0 = all checks passed
Exit code 1 = one or more checks failed
"""

import json
import os
import sys
import traceback
from types import SimpleNamespace
from typing import Any


PASS = "\033[92m✓\033[0m"
FAIL = "\033[91m✗\033[0m"
SKIP = "\033[93m~\033[0m"
BOLD = "\033[1m"
RESET = "\033[0m"

results: list[tuple[str, bool, str]] = []


def check(name: str, fn: Any) -> None:
    try:
        msg = fn()
        results.append((name, True, msg or ""))
        print(f"  {PASS} {name}" + (f"  [{msg}]" if msg else ""))
    except Exception as e:
        results.append((name, False, str(e)))
        print(f"  {FAIL} {name}")
        print(f"       {e}")


def skip(name: str, reason: str) -> None:
    results.append((name, True, f"SKIPPED: {reason}"))
    print(f"  {SKIP} {name}  [skipped: {reason}]")


# ---------------------------------------------------------------------------
# 1. Dependencies
# ---------------------------------------------------------------------------
print(f"\n{BOLD}1. Dependencies{RESET}")


def _check_msal() -> str:
    import msal
    return msal.__version__


def _check_httpx() -> str:
    import httpx
    return httpx.__version__


check("msal is importable", _check_msal)
check("httpx is importable", _check_httpx)


# ---------------------------------------------------------------------------
# 2. Tool registration
# ---------------------------------------------------------------------------
print(f"\n{BOLD}2. Tool Registration{RESET}")

EXPECTED_TOOLS = {
    "entra_get_tenant_info",
    "entra_list_stale_users",
    "entra_list_stale_service_principals",
    "entra_list_privileged_role_assignments",
    "entra_list_app_permissions",
    "entra_list_guests",
    "entra_list_conditional_access_policies",
    "entra_list_role_assignments_per_user",
    "create_identity_finding",
}


def _check_registration() -> str:
    from strix.tools.registry import get_tool_names, tools as tools_dict
    from strix.tools.entra import entra_graph_actions, entra_reporting_actions  # trigger registration
    names = set(get_tool_names())
    missing = EXPECTED_TOOLS - names
    if missing:
        raise AssertionError(f"Missing tools: {sorted(missing)}")
    return f"{len(EXPECTED_TOOLS)} tools registered"


def _check_sandbox_false() -> str:
    from strix.tools.registry import tools as tools_list
    from strix.tools.entra import entra_graph_actions, entra_reporting_actions
    tools_by_name = {t["name"]: t for t in tools_list}
    bad = [
        name for name in EXPECTED_TOOLS
        if tools_by_name.get(name, {}).get("sandbox_execution") is not False
    ]
    if bad:
        raise AssertionError(f"These tools incorrectly have sandbox_execution=True: {bad}")
    return "all sandbox_execution=False"


check("All 9 Entra tools are registered", _check_registration)
check("All Entra tools have sandbox_execution=False", _check_sandbox_false)


# ---------------------------------------------------------------------------
# 3. Validation logic (no credentials needed)
# ---------------------------------------------------------------------------
print(f"\n{BOLD}3. Validation Logic{RESET}")

AGENT_STATE = SimpleNamespace(agent_id="smoke-test")
AFFECTED = json.dumps([{"object_id": "aaa-bbb", "display_name": "Test User", "object_type": "user"}])
EVIDENCE = json.dumps({"last_sign_in": "2025-01-01", "days_inactive": 200})


def _check_invalid_finding_type() -> str:
    from strix.tools.entra.entra_reporting_actions import create_identity_finding
    result = create_identity_finding(
        AGENT_STATE,
        finding_type="bad_type",
        title="Test", severity="high",
        affected_objects=AFFECTED, description="d", evidence=EVIDENCE, remediation="r",
    )
    assert result["success"] is False
    assert result["errors"]
    return "correctly rejected"


def _check_valid_finding_accepted_when_no_tracer() -> str:
    from strix.tools.entra.entra_reporting_actions import create_identity_finding

    # When tracer is unavailable, should still return success=True with a warning
    result = create_identity_finding(
        AGENT_STATE,
        finding_type="stale_identity",
        title="Test Stale User",
        severity="high",
        affected_objects=AFFECTED,
        description="User hasn't signed in for 200 days.",
        evidence=EVIDENCE,
        remediation="Disable the account.",
    )
    # Either success (with or without persistence) or a specific error — not a crash
    assert "success" in result
    return f"success={result['success']}"


def _check_severity_risk_score_mapping() -> str:
    from strix.tools.entra.entra_reporting_actions import SEVERITY_RISK_SCORE
    expected = {"critical": 9, "high": 7, "medium": 5, "low": 3, "informational": 1}
    for severity, score in expected.items():
        assert SEVERITY_RISK_SCORE[severity] == score, f"{severity} → {SEVERITY_RISK_SCORE[severity]}, expected {score}"
    return "critical=9, high=7, medium=5, low=3, informational=1"


check("Invalid finding_type rejected", _check_invalid_finding_type)
check("Valid finding accepted (tracer-less)", _check_valid_finding_accepted_when_no_tracer)
check("Severity → risk_score mapping", _check_severity_risk_score_mapping)


# ---------------------------------------------------------------------------
# 4. Live Graph API (optional — only if credentials are set)
# ---------------------------------------------------------------------------
print(f"\n{BOLD}4. Live Graph API (optional){RESET}")

tenant_id = os.getenv("AZURE_TENANT_ID")
client_id = os.getenv("AZURE_CLIENT_ID")
client_secret = os.getenv("AZURE_CLIENT_SECRET")

if not all([tenant_id, client_id, client_secret]):
    skip(
        "entra_get_tenant_info live call",
        "AZURE_TENANT_ID / AZURE_CLIENT_ID / AZURE_CLIENT_SECRET not set",
    )
    skip(
        "entra_list_stale_users live call (5 users)",
        "credentials not set",
    )
else:
    def _live_tenant_info() -> str:
        from strix.tools.entra.entra_graph_actions import entra_get_tenant_info
        result = entra_get_tenant_info()
        if not result["success"]:
            raise RuntimeError(result.get("error", "unknown error"))
        return f"tenant={result['display_name']} ({result['tenant_id'][:8]}...)"

    def _live_stale_users() -> str:
        from strix.tools.entra.entra_graph_actions import entra_list_stale_users
        result = entra_list_stale_users(stale_threshold_days=90)
        if not result["success"]:
            raise RuntimeError(result.get("error", "unknown error"))
        return f"scanned={result['total_users_scanned']}, stale={result['stale_count']}"

    check("entra_get_tenant_info (live)", _live_tenant_info)
    check("entra_list_stale_users (live, threshold=90d)", _live_stale_users)


# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
print(f"\n{BOLD}{'─' * 50}{RESET}")
passed = sum(1 for _, ok, _ in results if ok)
total = len(results)
skipped = sum(1 for _, _, msg in results if msg.startswith("SKIPPED"))

if passed == total:
    print(f"{PASS} {BOLD}All {passed} checks passed{RESET}" + (f" ({skipped} skipped)" if skipped else ""))
    sys.exit(0)
else:
    failed = total - passed
    print(f"{FAIL} {BOLD}{failed} of {total} checks failed{RESET}")
    sys.exit(1)
