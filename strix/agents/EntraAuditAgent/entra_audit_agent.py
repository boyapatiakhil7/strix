"""
EntraAuditAgent — identity security audit agent for Microsoft Entra ID / Azure AD.

Extends BaseAgent with identity-audit-specific task construction.
Loads the entra_audit_root skill by default on the root agent.
No Docker sandbox required — all tools use sandbox_execution=False.
"""

import os
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape

from strix.agents.base_agent import BaseAgent
from strix.llm import LLM
from strix.llm.config import LLMConfig
from strix.skills import load_skills
from strix.tools.registry import tools as _all_tools
from strix.utils.resource_paths import get_strix_resource_path


# The only tool modules the identity audit agents should see.
# Everything else (terminal, browser, proxy, python, file_edit, etc.) is excluded.
_ALLOWED_MODULES = {
    "entra",          # all 9 Entra Graph + reporting tools
    "agents_graph",   # create_agent, agent_finish, wait_for_message, send_message_to_agent
    "finish",         # finish_scan
    "thinking",       # think
    "notes",          # create_note, get_note, list_notes, update_note (shared agent state)
    "load_skill",     # load_skill (sub-agents load domain skills dynamically)
}


def _identity_get_tools_prompt() -> str:
    """Filtered get_tools_prompt — only exposes identity-relevant tool modules."""
    tools_by_module: dict[str, list[dict[str, Any]]] = {}
    for tool in _all_tools:
        module = tool.get("module", "unknown")
        if module not in _ALLOWED_MODULES:
            continue
        tools_by_module.setdefault(module, []).append(tool)

    xml_sections = []
    for module, module_tools in sorted(tools_by_module.items()):
        tag_name = f"{module}_tools"
        section_parts = [f"<{tag_name}>"]
        for tool in module_tools:
            tool_xml = tool.get("xml_schema", "")
            if tool_xml:
                indented = "\n".join(f"  {line}" for line in tool_xml.split("\n"))
                section_parts.append(indented)
        section_parts.append(f"</{tag_name}>")
        xml_sections.append("\n".join(section_parts))

    return "\n\n".join(xml_sections)


class IdentityLLM(LLM):
    """
    LLM subclass for identity audit agents.

    Differences from the base LLM:
    - get_tools_prompt is replaced with a filtered version (_identity_get_tools_prompt)
      that only exposes Entra + coordination tools — pentest tools are hidden.
    - _get_skills_to_load does NOT append scan_modes/deep (a pentest skill).
    """

    def _get_skills_to_load(self) -> list[str]:
        """Only load explicitly requested skills — no scan_mode or whitebox skills."""
        deduped: list[str] = []
        seen: set[str] = set()
        for skill_name in self._active_skills:
            if skill_name not in seen:
                deduped.append(skill_name)
                seen.add(skill_name)
        return deduped

    def _load_system_prompt(self, agent_name: str | None) -> str:
        if not agent_name:
            return ""
        try:
            prompt_dir = get_strix_resource_path("agents", agent_name)
            skills_dir = get_strix_resource_path("skills")
            env = Environment(
                loader=FileSystemLoader([prompt_dir, skills_dir]),
                autoescape=select_autoescape(enabled_extensions=(), default_for_string=False),
            )

            skills_to_load = self._get_skills_to_load()
            skill_content = load_skills(skills_to_load)
            env.globals["get_skill"] = lambda name: skill_content.get(name, "")

            result = env.get_template("system_prompt.jinja").render(
                get_tools_prompt=_identity_get_tools_prompt,  # ← filtered
                loaded_skill_names=list(skill_content.keys()),
                interactive=self.config.interactive,
                system_prompt_context=self._system_prompt_context,
                **skill_content,
            )
            return str(result)
        except Exception:  # noqa: BLE001
            return ""


class EntraAuditAgent(BaseAgent):
    max_iterations = 300

    async def _initialize_sandbox_and_state(self, task: str) -> None:
        """
        Override base implementation to skip Docker sandbox creation entirely.
        Identity audit tools are all sandbox_execution=False (direct Graph API calls),
        so no Docker container is needed.  We only set the task on the agent state.
        """
        if not self.state.task:
            self.state.task = task
        self.state.add_message("user", task)

    def __init__(self, config: dict[str, Any]):
        default_skills: list[str] = []

        # Root agent (no parent) loads the orchestration skill
        state = config.get("state")
        if state is None or (hasattr(state, "parent_id") and state.parent_id is None):
            default_skills = ["coordination/entra_audit_root"]

        self.default_llm_config = LLMConfig(skills=default_skills)

        super().__init__(config)

        # Replace the LLM instance with our filtered subclass
        self.llm = IdentityLLM(self.llm_config, agent_name=self.agent_name)

    async def execute_audit(self, audit_config: dict[str, Any]) -> dict[str, Any]:
        """
        Entry point for an identity security audit.

        audit_config keys:
            tenant_id: Azure tenant ID (falls back to AZURE_TENANT_ID env var)
            user_instructions: Optional custom instructions
            run_name: Unique run identifier
        """
        tenant_id = audit_config.get("tenant_id") or os.getenv("AZURE_TENANT_ID", "unknown")
        user_instructions = audit_config.get("user_instructions", "")

        task_parts = [
            "Perform a comprehensive identity security audit on the Microsoft Entra ID tenant.",
            f"\nTenant ID: {tenant_id}",
            "\nAudit scope — cover all six identity domains in parallel:",
            "  1. Stale Identities — users and service principals with no recent sign-in",
            "  2. Privileged Role Assignments — over-privilege, guest in roles, excessive GAs",
            "  3. Application Permissions — OAuth grants, credential hygiene, high-risk permissions",
            "  4. Guest Access — external B2B accounts and their risk profile",
            "  5. Conditional Access Gaps — MFA enforcement, legacy auth, policy coverage",
            "  6. Segregation of Duties — toxic role combinations on single principals",
            "\nStart with entra_get_tenant_info for pre-flight context,",
            "then spawn all six domain sub-agents in parallel.",
            "Each sub-agent must call create_identity_finding for every confirmed issue",
            "and call agent_finish with a domain summary when done.",
            "\nWhen all sub-agents complete, produce an executive summary with:",
            "  - Total findings by severity (critical / high / medium / low)",
            "  - Top 3 most urgent remediation actions",
            "  - Per-domain finding counts",
        ]

        if user_instructions:
            task_parts.append(f"\nSpecial instructions: {user_instructions}")

        task_description = "\n".join(task_parts)

        return await self.agent_loop(task=task_description)
