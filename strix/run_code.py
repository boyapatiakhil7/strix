#!/usr/bin/env python3
# strix-code runs WITHOUT Docker — scanning tools execute locally on the host.
# STRIX_SANDBOX_MODE=false ensures sandbox_execution=False tools (run_command,
# create_code_finding, etc.) are registered. The CodeAuditAgent overrides
# _initialize_sandbox_and_state to skip Docker entirely.
import os
os.environ["STRIX_SANDBOX_MODE"] = "false"

"""
Strix Code — AI-powered code security and quality auditor.

Usage:
  strix-code --repo https://github.com/OWASP/Go-SCP --branch master --lang go
  strix-code --repo /path/to/local/project --lang java
  strix-code --repo . --lang auto
"""

import argparse
import asyncio
import atexit
import logging
import signal
import sys
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from strix.config import Config, apply_saved_config


apply_saved_config()

logging.getLogger().setLevel(logging.ERROR)


def _get_version() -> str:
    try:
        from importlib.metadata import version

        return version("strix-agent")
    except Exception:  # noqa: BLE001
        return "unknown"


def _validate_environment() -> None:
    console = Console()
    strix_llm = Config.get("strix_llm")
    if not strix_llm:
        error = Text()
        error.append("STRIX_LLM is not set\n\n", style="bold red")
        error.append("Set the model to use, e.g.:\n", style="white")
        error.append("  export STRIX_LLM='openai/gpt-4o'\n", style="dim white")
        console.print(Panel(error, title="[bold white]STRIX CODE", border_style="red", padding=(1, 2)))
        sys.exit(1)


def _parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Strix Code — AI code security and quality auditor",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Audit a public GitHub repo (Go)
  strix-code --repo https://github.com/OWASP/Go-SCP --branch master --lang go

  # Audit a local Java project
  strix-code --repo /path/to/java-service --lang java

  # Auto-detect language
  strix-code --repo . --lang auto

  # Custom instructions
  strix-code --repo https://github.com/example/app --instruction "Focus on auth package"
        """,
    )

    parser.add_argument(
        "-v",
        "--version",
        action="version",
        version=f"strix-code {_get_version()}",
    )

    parser.add_argument(
        "--repo",
        type=str,
        required=True,
        help="Git URL, SSH URL, or local path / folder to audit.",
    )
    parser.add_argument(
        "--branch",
        type=str,
        default="main",
        help="Branch or tag to checkout for URL repos (default: main).",
    )
    parser.add_argument(
        "--lang",
        type=str,
        default="auto",
        choices=["auto", "go", "java"],
        help="Primary language (default: auto-detect).",
    )
    parser.add_argument(
        "--run-name",
        type=str,
        default=None,
        help="Custom run name (default: auto-generated from repo name + timestamp).",
    )
    parser.add_argument(
        "--instruction",
        type=str,
        default="",
        help="Optional custom instructions for the audit.",
    )

    return parser.parse_args()


def _generate_run_name(repo: str) -> str:
    import re
    import time

    ts = int(time.time()) % 100000
    slug = re.sub(r"[^a-z0-9]+", "-", Path(repo).name.lower()).strip("-") or "code"
    return f"code-{slug}-{ts}"


def _display_startup(repo: str, branch: str, lang: str, run_name: str) -> None:
    console = Console()

    header = Text()
    header.append("Code audit initiated", style="bold #22c55e")

    repo_text = Text()
    repo_text.append("Repo    ", style="dim")
    repo_text.append(repo, style="bold white")

    branch_text = Text()
    branch_text.append("Branch  ", style="dim")
    branch_text.append(branch, style="white")

    lang_text = Text()
    lang_text.append("Language", style="dim")
    lang_text.append("  ")
    lang_text.append(lang, style="white")

    out_text = Text()
    out_text.append("Output  ", style="dim")
    out_text.append(f"strix_runs/{run_name}", style="#60a5fa")

    note = Text()
    note.append("\n\nFindings will be displayed in real-time.", style="dim")

    panel = Panel(
        Text.assemble(header, "\n\n", repo_text, "\n", branch_text, "\n", lang_text, "\n", out_text, note),
        title="[bold white]STRIX CODE",
        title_align="left",
        border_style="#22c55e",
        padding=(1, 2),
    )
    console.print("\n")
    console.print(panel)
    console.print()


def _display_finding(finding: dict[str, Any]) -> None:
    console = Console()
    fid = finding.get("id", "CODE-????")
    severity = finding.get("severity", "?").upper()
    sev_color = {"CRITICAL": "bold red", "HIGH": "red", "MEDIUM": "yellow", "LOW": "dim yellow", "INFO": "dim"}.get(severity, "white")

    body = Text()
    body.append(f'{finding.get("rule_id","?")}', style="bold white")
    body.append(f'  {finding.get("source_tool","?")}', style="dim")
    body.append(f'\n{finding.get("file_path","?")}:{finding.get("line_number",0)}', style="#60a5fa")
    body.append(f'\n\n{finding.get("description","")[:300]}', style="white")
    body.append(f'\n\nImpact: {finding.get("impact","")[:200]}', style="dim white")
    if finding.get("remediation"):
        body.append(f'\nFix:    {finding["remediation"][:200]}', style="dim")

    panel = Panel(
        body,
        title=f"[{sev_color}]{fid}  {severity}",
        title_align="left",
        border_style="red" if severity in ("CRITICAL", "HIGH") else "yellow",
        padding=(1, 2),
    )
    console.print(panel)
    console.print()


def _display_completion(run_name: str, finding_count: int) -> None:
    console = Console()

    body = Text()
    body.append("Code audit completed", style="bold #22c55e")
    body.append(f"\n\nFindings recorded: ", style="white")
    body.append(str(finding_count), style="bold white")
    body.append(f"\nOutput:           ", style="dim")
    body.append(f"strix_runs/{run_name}", style="#60a5fa")

    panel = Panel(
        body,
        title="[bold white]STRIX CODE",
        title_align="left",
        border_style="#22c55e",
        padding=(1, 2),
    )
    console.print("\n")
    console.print(panel)
    console.print()


async def _run_audit(args: argparse.Namespace) -> None:
    from strix.agents.CodeAuditAgent import CodeAuditAgent
    from strix.llm.config import LLMConfig
    from strix.telemetry.tracer import Tracer, set_global_tracer
    from strix.tools.code.code_actions import setup_repo

    console = Console()
    run_name = args.run_name or _generate_run_name(args.repo)

    _display_startup(args.repo, args.branch, args.lang, run_name)

    # Phase 0: Clone / validate repo BEFORE creating agent (so Docker gets the repo mounted)
    with console.status("[dim]Setting up repository...[/]", spinner="dots"):
        setup_result = setup_repo(repo=args.repo, run_name=run_name, branch=args.branch)

    if not setup_result.get("success"):
        console.print(f"[bold red]Repository setup failed:[/] {setup_result.get('error')}")
        sys.exit(1)

    repo_path = setup_result["repo_path"]
    workspace_subdir = setup_result["workspace_subdir"]
    commit_sha = setup_result.get("commit_sha", "")

    info = Text()
    info.append("Repository ready  ", style="dim")
    info.append(repo_path, style="white")
    if commit_sha:
        info.append(f"  ({commit_sha[:8]})", style="dim")
    console.print(info)
    console.print()

    # Set up tracer
    scan_config = {
        "scan_id": run_name,
        "run_name": run_name,
        "targets": [{"type": "local_code", "details": {"target_path": args.repo, "workspace_subdir": workspace_subdir}}],
    }

    tracer = Tracer(run_name)
    tracer.set_scan_config(scan_config)
    tracer.vulnerability_found_callback = _display_finding  # type: ignore[assignment]
    set_global_tracer(tracer)

    def _cleanup() -> None:
        tracer.cleanup()

    def _signal_handler(_signum: int, _frame: Any) -> None:
        tracer.cleanup()
        sys.exit(1)

    atexit.register(_cleanup)
    signal.signal(signal.SIGINT, _signal_handler)
    signal.signal(signal.SIGTERM, _signal_handler)
    if hasattr(signal, "SIGHUP"):
        signal.signal(signal.SIGHUP, _signal_handler)

    llm_config = LLMConfig(
        skills=["code_audit_root"],
        scan_mode="deep",
        is_whitebox=True,
    )

    agent_config: dict[str, Any] = {
        "llm_config": llm_config,
        "max_iterations": 200,
    }

    try:
        agent = CodeAuditAgent(agent_config)
        await agent.run_audit(
            repo=args.repo,
            repo_path=repo_path,
            branch=args.branch,
            language=args.lang,
            run_name=run_name,
            user_instructions=args.instruction or "",
        )
    except Exception as e:
        console.print(f"[bold red]Audit error:[/] {e}")
        raise

    finding_count = len(getattr(tracer, "code_findings", []))

    if tracer.final_scan_result:
        summary_panel = Panel(
            Text.assemble(
                Text("Code audit summary", style="bold #60a5fa"),
                "\n\n",
                tracer.final_scan_result,
            ),
            title="[bold white]STRIX CODE",
            title_align="left",
            border_style="#60a5fa",
            padding=(1, 2),
        )
        console.print(summary_panel)
        console.print()

    _display_completion(run_name, finding_count)


def main() -> None:
    if sys.platform == "win32":
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

    args = _parse_arguments()
    _validate_environment()

    try:
        asyncio.run(_run_audit(args))
    except KeyboardInterrupt:
        pass
    except Exception as e:
        Console().print(f"[bold red]Fatal error:[/] {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
