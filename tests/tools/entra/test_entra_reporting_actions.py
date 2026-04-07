"""
Tests: create_identity_finding — validation, deduplication, and success path.

No Azure credentials or network access required.
Tracer is mocked to avoid needing a real telemetry backend.
"""

import json
from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from strix.tools.entra.entra_reporting_actions import create_identity_finding


AGENT_STATE = SimpleNamespace(agent_id="test-agent")

VALID_AFFECTED_OBJECTS = json.dumps(
    [{"object_id": "aaaa-bbbb", "display_name": "John Smith", "object_type": "user"}]
)
VALID_EVIDENCE = json.dumps({"last_sign_in_datetime": "2025-01-01", "days_inactive": 200})


def _make_mock_tracer(existing: list[dict[str, Any]] | None = None) -> MagicMock:
    tracer = MagicMock()
    tracer.get_existing_vulnerabilities.return_value = existing or []
    tracer.add_vulnerability_report.return_value = "finding-id-123"
    return tracer


def _patch_tracer(tracer: MagicMock) -> Any:
    mock_tracer_module = MagicMock()
    mock_tracer_module.get_global_tracer.return_value = tracer
    return patch.dict("sys.modules", {"strix.telemetry.tracer": mock_tracer_module})


# ---------------------------------------------------------------------------
# Validation — finding_type
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "finding_type",
    ["stale_identity", "privileged_role", "app_permission", "guest_access", "ca_gap", "sod_conflict"],
)
def test_valid_finding_types_are_accepted(finding_type: str) -> None:
    tracer = _make_mock_tracer()
    with _patch_tracer(tracer):
        result = create_identity_finding(
            AGENT_STATE,
            finding_type=finding_type,
            title="Test Finding",
            severity="high",
            affected_objects=VALID_AFFECTED_OBJECTS,
            description="A test description",
            evidence=VALID_EVIDENCE,
            remediation="Fix it.",
        )
    assert result["success"] is True


def test_invalid_finding_type_returns_error() -> None:
    result = create_identity_finding(
        AGENT_STATE,
        finding_type="network_vuln",  # not valid for identity findings
        title="Test Finding",
        severity="high",
        affected_objects=VALID_AFFECTED_OBJECTS,
        description="A test description",
        evidence=VALID_EVIDENCE,
        remediation="Fix it.",
    )
    assert result["success"] is False
    assert any("finding_type" in e for e in result["errors"])


# ---------------------------------------------------------------------------
# Validation — severity
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("severity", ["critical", "high", "medium", "low", "informational"])
def test_valid_severities_are_accepted(severity: str) -> None:
    tracer = _make_mock_tracer()
    with _patch_tracer(tracer):
        result = create_identity_finding(
            AGENT_STATE,
            finding_type="stale_identity",
            title=f"Test {severity}",
            severity=severity,
            affected_objects=VALID_AFFECTED_OBJECTS,
            description="A test description",
            evidence=VALID_EVIDENCE,
            remediation="Fix it.",
        )
    assert result["success"] is True


def test_invalid_severity_returns_error() -> None:
    result = create_identity_finding(
        AGENT_STATE,
        finding_type="stale_identity",
        title="Test Finding",
        severity="CRITICAL",  # wrong case
        affected_objects=VALID_AFFECTED_OBJECTS,
        description="A test description",
        evidence=VALID_EVIDENCE,
        remediation="Fix it.",
    )
    assert result["success"] is False
    assert any("severity" in e for e in result["errors"])


# ---------------------------------------------------------------------------
# Validation — required fields
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "missing_field",
    ["title", "description", "affected_objects", "evidence", "remediation"],
)
def test_empty_required_field_returns_error(missing_field: str) -> None:
    kwargs: dict[str, Any] = {
        "finding_type": "stale_identity",
        "title": "Test Finding",
        "severity": "high",
        "affected_objects": VALID_AFFECTED_OBJECTS,
        "description": "A test description",
        "evidence": VALID_EVIDENCE,
        "remediation": "Fix it.",
    }
    kwargs[missing_field] = ""  # empty string

    result = create_identity_finding(AGENT_STATE, **kwargs)

    assert result["success"] is False
    assert result["errors"]


# ---------------------------------------------------------------------------
# Validation — risk_score
# ---------------------------------------------------------------------------


def test_risk_score_out_of_range_returns_error() -> None:
    result = create_identity_finding(
        AGENT_STATE,
        finding_type="stale_identity",
        title="Test Finding",
        severity="high",
        affected_objects=VALID_AFFECTED_OBJECTS,
        description="desc",
        evidence=VALID_EVIDENCE,
        remediation="fix",
        risk_score=11,  # > 10
    )
    assert result["success"] is False
    assert any("risk_score" in e for e in result["errors"])


def test_risk_score_zero_derives_from_severity() -> None:
    tracer = _make_mock_tracer()
    with _patch_tracer(tracer):
        result = create_identity_finding(
            AGENT_STATE,
            finding_type="stale_identity",
            title="Test Finding",
            severity="critical",
            affected_objects=VALID_AFFECTED_OBJECTS,
            description="desc",
            evidence=VALID_EVIDENCE,
            remediation="fix",
            risk_score=0,
        )
    assert result["success"] is True
    assert result["risk_score"] == 9  # critical → 9


@pytest.mark.parametrize(
    "severity,expected_score",
    [("critical", 9), ("high", 7), ("medium", 5), ("low", 3), ("informational", 1)],
)
def test_severity_to_risk_score_mapping(severity: str, expected_score: int) -> None:
    tracer = _make_mock_tracer()
    with _patch_tracer(tracer):
        result = create_identity_finding(
            AGENT_STATE,
            finding_type="privileged_role",
            title=f"Test {severity}",
            severity=severity,
            affected_objects=VALID_AFFECTED_OBJECTS,
            description="desc",
            evidence=VALID_EVIDENCE,
            remediation="fix",
        )
    assert result["success"] is True
    assert result["risk_score"] == expected_score


# ---------------------------------------------------------------------------
# Deduplication
# ---------------------------------------------------------------------------


def test_duplicate_finding_is_rejected() -> None:
    existing = [
        {
            "id": "existing-id",
            "title": "Stale Global Admin Account — jsmith@contoso.com",
            "finding_type": "stale_identity",
        }
    ]
    tracer = _make_mock_tracer(existing=existing)

    with _patch_tracer(tracer):
        result = create_identity_finding(
            AGENT_STATE,
            finding_type="stale_identity",
            title="Stale Global Admin Account — jsmith@contoso.com",  # exact duplicate
            severity="critical",
            affected_objects=VALID_AFFECTED_OBJECTS,
            description="desc",
            evidence=VALID_EVIDENCE,
            remediation="fix",
        )

    assert result["success"] is False
    assert "Duplicate" in result["message"]
    assert result["duplicate_of"] == "existing-id"


def test_same_title_different_type_is_not_duplicate() -> None:
    existing = [
        {
            "id": "existing-id",
            "title": "Test Finding",
            "finding_type": "stale_identity",
        }
    ]
    tracer = _make_mock_tracer(existing=existing)

    with _patch_tracer(tracer):
        result = create_identity_finding(
            AGENT_STATE,
            finding_type="privileged_role",  # different type
            title="Test Finding",
            severity="high",
            affected_objects=VALID_AFFECTED_OBJECTS,
            description="desc",
            evidence=VALID_EVIDENCE,
            remediation="fix",
        )

    assert result["success"] is True


# ---------------------------------------------------------------------------
# Success path
# ---------------------------------------------------------------------------


def test_create_identity_finding_success_returns_report_id() -> None:
    tracer = _make_mock_tracer()
    with _patch_tracer(tracer):
        result = create_identity_finding(
            AGENT_STATE,
            finding_type="ca_gap",
            title="No MFA Policy for All Users",
            severity="high",
            affected_objects=VALID_AFFECTED_OBJECTS,
            description="No Conditional Access policy enforces MFA.",
            evidence=VALID_EVIDENCE,
            remediation="Create a CA policy requiring MFA for all users.",
        )

    assert result["success"] is True
    assert result["report_id"] == "finding-id-123"
    assert result["finding_type"] == "ca_gap"
    assert result["severity"] == "high"


def test_create_identity_finding_calls_tracer_add_vulnerability_report() -> None:
    tracer = _make_mock_tracer()
    with _patch_tracer(tracer):
        create_identity_finding(
            AGENT_STATE,
            finding_type="guest_access",
            title="Guest with GA Role",
            severity="critical",
            affected_objects=VALID_AFFECTED_OBJECTS,
            description="desc",
            evidence=VALID_EVIDENCE,
            remediation="Remove the role.",
        )

    tracer.add_vulnerability_report.assert_called_once()
    call_kwargs = tracer.add_vulnerability_report.call_args.kwargs
    assert call_kwargs["title"] == "Guest with GA Role"
    assert call_kwargs["severity"] == "critical"
    # Identity-specific metadata in extra
    assert call_kwargs["extra"]["finding_type"] == "guest_access"
