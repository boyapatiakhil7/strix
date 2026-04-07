#!/usr/bin/env python3
"""
strix-identity — Entra ID / Azure AD identity security audit CLI.

Usage:
    strix-identity
    strix-identity --instruction "Focus on guest access and privileged roles"
    strix-identity --tenant-id <guid> --non-interactive

Credentials are read from environment variables:
    AZURE_TENANT_ID      Azure AD tenant GUID
    AZURE_CLIENT_ID      App registration client ID
    AZURE_CLIENT_SECRET  App registration client secret
"""

import argparse
import asyncio
import logging
import os
import sys
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from strix.config import Config, apply_saved_config, save_current_config
from strix.telemetry.tracer import get_global_tracer

# Apply saved config first (may set STRIX_SANDBOX_MODE=true from user's saved settings).
apply_saved_config()

# Override AFTER apply_saved_config so the correct value is seen by @register_tool
# decorators when strix.tools.entra is first imported below.
# Entra tools are sandbox_execution=False (Graph API calls — no Docker needed).
os.environ["STRIX_SANDBOX_MODE"] = "false"

from strix.interface.identity_cli import run_identity_cli  # noqa: E402
from strix.interface.utils import generate_run_name, build_final_stats_text  # noqa: E402
from strix.agents.EntraAuditAgent.entra_audit_agent import EntraAuditAgent  # noqa: E402


def _patch_agent_for_identity() -> None:
    """
    Patch strix.agents.StrixAgent → EntraAuditAgent so that sub-agents
    spawned by create_agent() also use filtered tools and the identity system prompt.
    create_agent() does a runtime `from strix.agents import StrixAgent`,
    so patching the module attribute is sufficient.
    """
    import strix.agents as _agents_module
    _agents_module.StrixAgent = EntraAuditAgent  # type: ignore[attr-defined]


logging.getLogger().setLevel(logging.ERROR)


def get_version() -> str:
    try:
        from importlib.metadata import version
        return version("strix-agent")
    except Exception:  # noqa: BLE001
        return "unknown"


def validate_azure_credentials() -> str:
    """Check that all three Azure env vars are set. Returns tenant_id."""
    console = Console()

    tenant_id = os.getenv("AZURE_TENANT_ID", "")
    client_id = os.getenv("AZURE_CLIENT_ID", "")
    client_secret = os.getenv("AZURE_CLIENT_SECRET", "")

    missing = []
    if not tenant_id:
        missing.append("AZURE_TENANT_ID")
    if not client_id:
        missing.append("AZURE_CLIENT_ID")
    if not client_secret:
        missing.append("AZURE_CLIENT_SECRET")

    if not missing:
        return tenant_id

    error_text = Text()
    error_text.append("MISSING AZURE CREDENTIALS", style="bold red")
    error_text.append("\n\n")
    for var in missing:
        error_text.append(f"• {var}", style="bold yellow")
        error_text.append(" is not set\n")
    error_text.append("\nSet these environment variables before running:\n\n", style="dim")
    error_text.append("  export AZURE_TENANT_ID='your-tenant-id'\n", style="dim white")
    error_text.append("  export AZURE_CLIENT_ID='your-client-id'\n", style="dim white")
    error_text.append("  export AZURE_CLIENT_SECRET='your-client-secret'\n", style="dim white")
    error_text.append(
        "\nThe app registration needs these API permissions (application type, admin-consented):\n",
        style="dim",
    )
    error_text.append(
        "  Directory.Read.All, AuditLog.Read.All, Policy.Read.All,\n"
        "  RoleManagement.Read.Directory, Application.Read.All, User.Read.All\n",
        style="dim white",
    )

    console.print("\n")
    console.print(
        Panel(
            error_text,
            title="[bold white]STRIX IDENTITY",
            title_align="left",
            border_style="red",
            padding=(1, 2),
        )
    )
    console.print()
    sys.exit(1)


def validate_llm_environment() -> None:
    """Ensure STRIX_LLM is configured."""
    console = Console()
    strix_llm = Config.get("strix_llm")
    if strix_llm:
        return

    error_text = Text()
    error_text.append("MISSING LLM CONFIGURATION", style="bold red")
    error_text.append("\n\nSTRIX_LLM is not set.\n\n")
    error_text.append("export STRIX_LLM='anthropic/claude-sonnet-4-5'\n", style="dim white")
    error_text.append("export LLM_API_KEY='your-api-key'\n", style="dim white")

    console.print("\n")
    console.print(
        Panel(
            error_text,
            title="[bold white]STRIX IDENTITY",
            title_align="left",
            border_style="red",
            padding=(1, 2),
        )
    )
    console.print()
    sys.exit(1)


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="strix-identity",
        description="Strix Identity — Entra ID / Azure AD identity security audit",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic audit using env vars
  strix-identity

  # With custom focus instruction
  strix-identity --instruction "Focus on guest access and stale privileged accounts"

  # Override tenant ID
  strix-identity --tenant-id xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx

  # Non-interactive (CI/CD mode)
  strix-identity --non-interactive
        """,
    )

    parser.add_argument(
        "-v", "--version",
        action="version",
        version=f"strix-identity {get_version()}",
    )

    parser.add_argument(
        "--tenant-id",
        type=str,
        default=None,
        help="Azure tenant ID. Overrides AZURE_TENANT_ID environment variable.",
    )

    parser.add_argument(
        "--instruction",
        type=str,
        default=None,
        help=(
            "Custom audit instructions, e.g. "
            "'Focus on privileged roles and conditional access gaps'"
        ),
    )

    parser.add_argument(
        "--instruction-file",
        type=str,
        default=None,
        help="Path to a file containing detailed audit instructions.",
    )

    parser.add_argument(
        "-n", "--non-interactive",
        action="store_true",
        help="Run in non-interactive mode (no TUI, exits on completion).",
    )

    args = parser.parse_args()

    if args.instruction and args.instruction_file:
        parser.error("Cannot use both --instruction and --instruction-file.")

    if args.instruction_file:
        instruction_path = Path(args.instruction_file)
        try:
            args.instruction = instruction_path.read_text(encoding="utf-8").strip()
            if not args.instruction:
                parser.error(f"Instruction file '{instruction_path}' is empty")
        except OSError as e:
            parser.error(f"Failed to read instruction file '{instruction_path}': {e}")

    return args


def display_completion(args: argparse.Namespace, results_path: Path) -> None:
    console = Console()
    tracer = get_global_tracer()

    scan_completed = False
    if tracer and tracer.scan_results:
        scan_completed = tracer.scan_results.get("scan_completed", False)

    completion_text = Text()
    if scan_completed:
        completion_text.append("Identity audit completed", style="bold #22c55e")
    else:
        completion_text.append("SESSION ENDED", style="bold #eab308")

    tenant_text = Text()
    tenant_text.append("Tenant", style="dim")
    tenant_text.append("  ")
    tenant_text.append(args.tenant_id or os.getenv("AZURE_TENANT_ID", "unknown"), style="bold white")

    stats_text = build_final_stats_text(tracer)

    results_text = Text()
    results_text.append("\n")
    results_text.append("Output", style="dim")
    results_text.append("  ")
    results_text.append(str(results_path), style="#60a5fa")

    panel_parts: list[Any] = [completion_text, "\n\n", tenant_text]
    if stats_text.plain:
        panel_parts.extend(["\n", stats_text])
    panel_parts.extend(["\n", results_text])

    console.print("\n")
    console.print(
        Panel(
            Text.assemble(*panel_parts),
            title="[bold white]STRIX IDENTITY",
            title_align="left",
            border_style="#22c55e" if scan_completed else "#eab308",
            padding=(1, 2),
        )
    )
    console.print()


def main() -> None:
    if sys.platform == "win32":
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

    args = parse_arguments()

    validate_llm_environment()
    tenant_id = validate_azure_credentials()

    # --tenant-id overrides env var
    if args.tenant_id:
        os.environ["AZURE_TENANT_ID"] = args.tenant_id
    else:
        args.tenant_id = tenant_id

    save_current_config()

    # Patch StrixAgent → EntraAuditAgent so sub-agents spawned by create_agent()
    # also get filtered tools and the identity system prompt
    _patch_agent_for_identity()

    # Generate a unique run name: tenant prefix + timestamp
    from datetime import datetime
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    args.run_name = f"identity-audit-{args.tenant_id[:8]}-{ts}"

    try:
        asyncio.run(run_identity_cli(args))
    except KeyboardInterrupt:
        pass

    results_path = Path("strix_runs") / args.run_name
    display_completion(args, results_path)

    if args.non_interactive:
        tracer = get_global_tracer()
        if tracer and tracer.vulnerability_reports:
            sys.exit(2)


if __name__ == "__main__":
    main()
