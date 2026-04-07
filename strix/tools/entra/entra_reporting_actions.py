"""
Identity finding reporting tool for Entra ID / Azure AD audits.

Analogous to create_vulnerability_report but shaped for identity audit findings:
no CVSS vector, no PoC exploit code, no HTTP endpoint — instead uses
affected_objects (list of Entra object IDs) and evidence (API response excerpts).
"""

import logging
from typing import Any

from strix.tools.registry import register_tool


logger = logging.getLogger(__name__)

VALID_FINDING_TYPES = {
    "stale_identity",
    "privileged_role",
    "app_permission",
    "guest_access",
    "ca_gap",
    "sod_conflict",
}

VALID_SEVERITIES = {"critical", "high", "medium", "low", "informational"}

SEVERITY_RISK_SCORE: dict[str, int] = {
    "critical": 9,
    "high": 7,
    "medium": 5,
    "low": 3,
    "informational": 1,
}


def _validate_required_fields(**kwargs: str | None) -> list[str]:
    errors: list[str] = []
    required = {
        "title": "Title cannot be empty",
        "description": "Description cannot be empty",
        "affected_objects": "affected_objects cannot be empty — provide at least one Entra object",
        "evidence": "Evidence cannot be empty — provide API response excerpts confirming the finding",
        "remediation": "Remediation cannot be empty",
    }
    for field, msg in required.items():
        value = kwargs.get(field)
        if not value or not str(value).strip():
            errors.append(msg)
    return errors


@register_tool(sandbox_execution=False)
def create_identity_finding(
    agent_state: Any,
    finding_type: str,
    title: str,
    severity: str,
    affected_objects: str,
    description: str,
    evidence: str,
    remediation: str,
    risk_score: int = 0,
    tenant_id: str | None = None,
) -> dict[str, Any]:
    """
    Create an identity security finding for the audit report.

    Use this tool to document a confirmed identity security issue discovered
    during the Entra ID audit. Only call this after you have validated the
    finding — do not report based on policy observation alone.

    DO NOT USE:
    - For theoretical or unconfirmed issues
    - When affected_objects is empty or unknown
    - To re-report an already reported finding
    - For general observations without a specific identity object

    Args:
        agent_state: Injected by the framework — do not pass manually.
        finding_type: Category of finding. One of:
            stale_identity, privileged_role, app_permission,
            guest_access, ca_gap, sod_conflict
        title: Short descriptive title, e.g. "Stale Global Admin Account — jsmith@contoso.com"
        severity: critical | high | medium | low | informational
        affected_objects: JSON string — list of affected Entra objects.
            Format: [{"object_id": "...", "display_name": "...", "object_type": "user|servicePrincipal|group|app"}]
        description: Explanation of the finding and how it was discovered.
        evidence: JSON string — raw API response excerpts confirming the finding.
        remediation: Specific, actionable remediation steps.
        risk_score: Override risk score 1–10. If 0, derived from severity.
        tenant_id: Azure tenant ID. Inferred from AZURE_TENANT_ID env var if omitted.
    """
    # --- Validation ---
    validation_errors: list[str] = []

    if finding_type not in VALID_FINDING_TYPES:
        validation_errors.append(
            f"Invalid finding_type: '{finding_type}'. "
            f"Must be one of: {', '.join(sorted(VALID_FINDING_TYPES))}"
        )

    if severity not in VALID_SEVERITIES:
        validation_errors.append(
            f"Invalid severity: '{severity}'. "
            f"Must be one of: {', '.join(sorted(VALID_SEVERITIES))}"
        )

    validation_errors.extend(
        _validate_required_fields(
            title=title,
            description=description,
            affected_objects=affected_objects,
            evidence=evidence,
            remediation=remediation,
        )
    )

    if risk_score != 0 and not (1 <= risk_score <= 10):
        validation_errors.append("risk_score must be between 1 and 10, or 0 to derive from severity")

    if validation_errors:
        return {
            "success": False,
            "message": "Validation failed",
            "errors": validation_errors,
        }

    # Derive risk_score from severity if not provided
    effective_risk_score = risk_score if risk_score != 0 else SEVERITY_RISK_SCORE.get(severity, 5)

    # Resolve tenant_id
    import os
    resolved_tenant_id = tenant_id or os.getenv("AZURE_TENANT_ID", "unknown")

    # --- Deduplication ---
    try:
        from strix.telemetry.tracer import get_global_tracer

        tracer = get_global_tracer()
        if tracer:
            existing = tracer.get_existing_vulnerabilities()

            # Lightweight dedup: same title + finding_type = likely duplicate
            for existing_finding in existing:
                if (
                    existing_finding.get("title", "").strip().lower() == title.strip().lower()
                    and existing_finding.get("finding_type") == finding_type
                ):
                    return {
                        "success": False,
                        "message": (
                            f"Duplicate finding detected: '{title}' "
                            f"(type={finding_type}) was already reported. "
                            "Do not re-submit the same finding."
                        ),
                        "duplicate_of": existing_finding.get("id", ""),
                        "duplicate_title": existing_finding.get("title", ""),
                    }

            report_id = tracer.add_vulnerability_report(
                title=title,
                description=description,
                severity=severity,
                impact=description,  # identity findings use description as impact
                target=f"Entra ID Tenant: {resolved_tenant_id}",
                technical_analysis=evidence,
                poc_description=f"Identity finding — see affected_objects and evidence fields.",
                poc_script_code=f"# Affected objects:\n# {affected_objects}\n\n# Evidence:\n# {evidence}",
                remediation_steps=remediation,
                cvss=float(effective_risk_score),
                cvss_breakdown={},
                endpoint=None,
                method=None,
                cve=None,
                cwe=None,
                code_locations=None,
            )

            return {
                "success": True,
                "message": f"Identity finding '{title}' created successfully",
                "report_id": report_id,
                "finding_type": finding_type,
                "severity": severity,
                "risk_score": effective_risk_score,
            }

        # Tracer unavailable — log and return success without persistence
        logger.warning("Tracer not available — identity finding not persisted")
        return {
            "success": True,
            "message": f"Identity finding '{title}' created (not persisted — tracer unavailable)",
            "finding_type": finding_type,
            "severity": severity,
            "risk_score": effective_risk_score,
            "warning": "Finding could not be persisted",
        }

    except (ImportError, AttributeError) as e:
        return {
            "success": False,
            "message": f"Failed to create identity finding: {e}",
        }
