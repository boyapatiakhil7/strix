import logging
from typing import Any

from strix.tools.registry import register_tool


logger = logging.getLogger(__name__)

_VALID_FINDING_TYPES = {"sast", "quality", "coverage", "secret"}
_VALID_SEVERITIES = {"critical", "high", "medium", "low", "info"}
_VALID_SOURCE_TOOLS = {
    "gosec",
    "semgrep",
    "golangci-lint",
    "checkstyle",
    "pmd",
    "gitleaks",
    "go-coverage",
    "jacoco",
    "manual",
}

_finding_counter: dict[str, int] = {}


def _next_finding_id(run_name: str) -> str:
    count = _finding_counter.get(run_name, 0) + 1
    _finding_counter[run_name] = count
    return f"CODE-{count:04d}"


@register_tool(sandbox_execution=False)
def create_code_finding(  # noqa: PLR0912, PLR0913
    agent_state: Any,
    finding_type: str,
    severity: str,
    rule_id: str,
    file_path: str,
    line_number: int,
    description: str,
    impact: str,
    source_tool: str,
    remediation: str = "",
    cwe: str = "",
    fix_proposal_ref: str = "",
) -> dict[str, Any]:
    """Report a code audit finding (SAST, quality, coverage, or secret).

    Each finding gets a unique CODE-XXXX identifier.
    Findings are stored in the global tracer's code_findings list.
    """
    validation_errors: list[str] = []

    if not finding_type or finding_type not in _VALID_FINDING_TYPES:
        validation_errors.append(
            f"finding_type must be one of: {', '.join(sorted(_VALID_FINDING_TYPES))}"
        )
    if not severity or severity.lower() not in _VALID_SEVERITIES:
        validation_errors.append(
            f"severity must be one of: {', '.join(sorted(_VALID_SEVERITIES))}"
        )
    if not rule_id or not rule_id.strip():
        validation_errors.append("rule_id cannot be empty")
    if not file_path or not file_path.strip():
        validation_errors.append("file_path cannot be empty")
    if not isinstance(line_number, int) or line_number < 0:
        validation_errors.append("line_number must be a non-negative integer")
    if not description or not description.strip():
        validation_errors.append("description cannot be empty")
    if not impact or not impact.strip():
        validation_errors.append("impact cannot be empty")
    if not source_tool or source_tool not in _VALID_SOURCE_TOOLS:
        validation_errors.append(
            f"source_tool must be one of: {', '.join(sorted(_VALID_SOURCE_TOOLS))}"
        )

    if validation_errors:
        return {"success": False, "message": "Validation failed", "errors": validation_errors}

    severity = severity.lower()

    try:
        from strix.telemetry.tracer import get_global_tracer

        tracer = get_global_tracer()

        run_name = ""
        if tracer and hasattr(tracer, "scan_config") and tracer.scan_config:
            run_name = tracer.scan_config.get("scan_id", "") or tracer.scan_config.get("run_name", "")

        finding_id = _next_finding_id(run_name)

        finding: dict[str, Any] = {
            "id": finding_id,
            "finding_type": finding_type,
            "severity": severity,
            "rule_id": rule_id.strip(),
            "file_path": file_path.strip(),
            "line_number": line_number,
            "description": description.strip(),
            "impact": impact.strip(),
            "source_tool": source_tool,
            "remediation": remediation.strip() if remediation else "",
            "cwe": cwe.strip() if cwe else "",
            "fix_proposal_ref": fix_proposal_ref.strip() if fix_proposal_ref else "",
        }

        if tracer:
            if not hasattr(tracer, "code_findings"):
                tracer.code_findings = []  # type: ignore[attr-defined]
            tracer.code_findings.append(finding)  # type: ignore[attr-defined]

            exec_id = tracer.log_tool_execution_start(
                agent_id=agent_state.agent_id if agent_state else "unknown",
                tool_name="create_code_finding",
                args=finding,
            )
            tracer.update_tool_execution(exec_id, "completed", {"finding_id": finding_id})

            if hasattr(tracer, "vulnerability_found_callback") and tracer.vulnerability_found_callback:
                tracer.vulnerability_found_callback(finding)

        return {
            "success": True,
            "finding_id": finding_id,
            "severity": severity,
            "message": f"Finding {finding_id} ({severity.upper()}) recorded — {rule_id}",
        }

    except (ImportError, AttributeError) as e:
        return {"success": False, "message": f"Failed to record finding: {e!s}"}


@register_tool(sandbox_execution=False)
def finish_code_audit(
    agent_state: Any,
    architecture_summary: str,
    technical_analysis: str,
    recommendations: str,
    languages_scanned: str,
    tools_run: str,
    tools_skipped: str,
    total_findings: int,
    coverage_summary: str = "",
) -> dict[str, Any]:
    """Complete the code audit and write the final summary.

    IMPORTANT: Can only be called by the root CodeAuditAgent (not sub-agents).
    Sub-agents must use agent_finish from agents_graph.

    All sub-agents must have completed before calling this tool.
    """
    if agent_state and hasattr(agent_state, "parent_id") and agent_state.parent_id is not None:
        return {
            "success": False,
            "error": "finish_code_audit_wrong_agent",
            "message": "This tool can only be used by the root CodeAuditAgent",
            "suggestion": "If you are a sub-agent, use agent_finish from agents_graph instead",
        }

    validation_errors: list[str] = []
    if not architecture_summary or not architecture_summary.strip():
        validation_errors.append("architecture_summary cannot be empty")
    if not technical_analysis or not technical_analysis.strip():
        validation_errors.append("technical_analysis cannot be empty")
    if not recommendations or not recommendations.strip():
        validation_errors.append("recommendations cannot be empty")
    if not languages_scanned or not languages_scanned.strip():
        validation_errors.append("languages_scanned cannot be empty")
    if not tools_run or not tools_run.strip():
        validation_errors.append("tools_run cannot be empty")
    if not isinstance(total_findings, int) or total_findings < 0:
        validation_errors.append("total_findings must be a non-negative integer")

    if validation_errors:
        return {"success": False, "message": "Validation failed", "errors": validation_errors}

    try:
        from strix.telemetry.tracer import get_global_tracer

        tracer = get_global_tracer()
        if tracer:
            methodology_parts = [f"Languages: {languages_scanned.strip()}"]
            methodology_parts.append(f"Tools run: {tools_run.strip()}")
            if tools_skipped and tools_skipped.strip():
                methodology_parts.append(f"Tools skipped: {tools_skipped.strip()}")
            if coverage_summary and coverage_summary.strip():
                methodology_parts.append(f"Coverage: {coverage_summary.strip()}")
            methodology_parts.append(f"Total findings: {total_findings}")

            tracer.update_scan_final_fields(
                executive_summary=architecture_summary.strip(),
                methodology="\n".join(methodology_parts),
                technical_analysis=technical_analysis.strip(),
                recommendations=recommendations.strip(),
                section_labels={
                    "executive_summary": "Architecture Summary",
                    "methodology": "Scan Methodology",
                },
            )

            finding_count = len(getattr(tracer, "code_findings", []))

            return {
                "success": True,
                "audit_completed": True,
                "message": "Code audit completed successfully",
                "total_findings_recorded": finding_count,
            }

        logger.warning("Tracer not available — audit results not stored")

    except (ImportError, AttributeError) as e:
        return {"success": False, "message": f"Failed to complete audit: {e!s}"}
    else:
        return {
            "success": True,
            "audit_completed": True,
            "message": "Code audit completed (not persisted — tracer unavailable)",
        }
