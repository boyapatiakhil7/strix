from pathlib import Path
from typing import Any

from strix.agents.base_agent import BaseAgent
from strix.llm.config import LLMConfig


class CodeAuditAgent(BaseAgent):
    """Root agent for code security and quality audits.

    Orchestrates SAST, quality, coverage, and secrets scanning against
    Go or Java repositories. Proposes fixes for human review — never commits.

    Docker sandbox is used for running scanning tools (gosec, semgrep, etc.)
    via terminal_execute. The repository is mounted at /workspace/<subdir>.
    """

    max_iterations = 200

    def __init__(self, config: dict[str, Any]):
        state = config.get("state")
        is_root = state is None or (hasattr(state, "parent_id") and state.parent_id is None)
        default_skills = ["code_audit_root"] if is_root else []

        self.default_llm_config = LLMConfig(
            skills=default_skills,
            scan_mode=config.get("scan_mode", "deep"),
        )

        super().__init__(config)

    async def run_audit(
        self,
        repo: str,
        branch: str,
        language: str,
        run_name: str,
        user_instructions: str = "",
    ) -> dict[str, Any]:
        """Run a full code audit against the given repository."""
        workspace_subdir = Path(repo).name if not repo.startswith(("http://", "https://", "git@", "ssh://")) else "repo"

        task_parts = [
            f"Perform a comprehensive code security and quality audit.",
            f"\n\nRepository: {repo}",
            f"\nBranch: {branch}",
            f"\nLanguage hint: {language}",
            f"\nRun name: {run_name}",
            f"\nWorkspace path: /workspace/{workspace_subdir}",
        ]

        if user_instructions:
            task_parts.append(f"\n\nSpecial instructions: {user_instructions}")

        task = "".join(task_parts)
        return await self.agent_loop(task=task)
