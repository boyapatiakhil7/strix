"""
CLI runner for the Entra ID identity security audit.
Analogous to cli.py but for identity audits — no Docker, no targets, Azure env vars only.
"""

import atexit
import signal
import sys
import threading
import time
from typing import Any

from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.text import Text

from strix.agents.EntraAuditAgent.entra_audit_agent import EntraAuditAgent
from strix.llm.config import LLMConfig
from strix.telemetry.tracer import Tracer, set_global_tracer

from .utils import build_live_stats_text, format_vulnerability_report


async def run_identity_cli(args: Any) -> None:
    console = Console()

    # --- Startup panel ---
    start_text = Text()
    start_text.append("Identity security audit initiated", style="bold #22c55e")

    tenant_text = Text()
    tenant_text.append("Tenant", style="dim")
    tenant_text.append("  ")
    tenant_text.append(args.tenant_id or "from AZURE_TENANT_ID", style="bold white")

    results_text = Text()
    results_text.append("Output", style="dim")
    results_text.append("  ")
    results_text.append(f"strix_runs/{args.run_name}", style="#60a5fa")

    note_text = Text()
    note_text.append("\n\n", style="dim")
    note_text.append("Identity findings will be displayed in real-time.", style="dim")

    startup_panel = Panel(
        Text.assemble(start_text, "\n\n", tenant_text, "\n", results_text, note_text),
        title="[bold white]STRIX IDENTITY",
        title_align="left",
        border_style="#22c55e",
        padding=(1, 2),
    )

    console.print("\n")
    console.print(startup_panel)
    console.print()

    # --- Audit config ---
    audit_config = {
        "run_name": args.run_name,
        "tenant_id": args.tenant_id,
        "user_instructions": args.instruction or "",
    }

    llm_config = LLMConfig(scan_mode="deep")
    agent_config = {
        "llm_config": llm_config,
        "max_iterations": 300,
    }

    # --- Tracer ---
    tracer = Tracer(args.run_name)
    tracer.set_scan_config(audit_config)

    def display_finding(report: dict[str, Any]) -> None:
        report_id = report.get("id", "unknown")
        finding_text = format_vulnerability_report(report)
        finding_panel = Panel(
            finding_text,
            title=f"[bold red]{report_id.upper()}",
            title_align="left",
            border_style="red",
            padding=(1, 2),
        )
        console.print(finding_panel)
        console.print()

    tracer.vulnerability_found_callback = display_finding

    def cleanup_on_exit() -> None:
        tracer.cleanup()

    def signal_handler(_signum: int, _frame: Any) -> None:
        tracer.cleanup()
        sys.exit(1)

    atexit.register(cleanup_on_exit)
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    if hasattr(signal, "SIGHUP"):
        signal.signal(signal.SIGHUP, signal_handler)

    set_global_tracer(tracer)

    # --- Live status ---
    def create_live_status() -> Panel:
        status_text = Text()
        status_text.append("Identity audit in progress", style="bold #22c55e")
        status_text.append("\n\n")
        stats_text = build_live_stats_text(tracer, agent_config)
        if stats_text:
            status_text.append(stats_text)
        return Panel(
            status_text,
            title="[bold white]STRIX IDENTITY",
            title_align="left",
            border_style="#22c55e",
            padding=(1, 2),
        )

    try:
        console.print()
        with Live(
            create_live_status(), console=console, refresh_per_second=2, transient=False
        ) as live:
            stop_updates = threading.Event()

            def update_status() -> None:
                while not stop_updates.is_set():
                    try:
                        live.update(create_live_status())
                        time.sleep(2)
                    except Exception:  # noqa: BLE001
                        break

            update_thread = threading.Thread(target=update_status, daemon=True)
            update_thread.start()

            try:
                agent = EntraAuditAgent(agent_config)
                result = await agent.execute_audit(audit_config)

                if isinstance(result, dict) and not result.get("success", True):
                    error_msg = result.get("error", "Unknown error")
                    console.print()
                    console.print(f"[bold red]Identity audit failed:[/] {error_msg}")
                    console.print()
                    sys.exit(1)
            finally:
                stop_updates.set()
                update_thread.join(timeout=1)

    except Exception as e:
        console.print(f"[bold red]Error during identity audit:[/] {e}")
        raise

    # --- Final report panel ---
    if tracer.final_scan_result:
        console.print()
        final_panel = Panel(
            Text.assemble(
                Text("Identity audit summary", style="bold #60a5fa"),
                "\n\n",
                tracer.final_scan_result,
            ),
            title="[bold white]STRIX IDENTITY",
            title_align="left",
            border_style="#60a5fa",
            padding=(1, 2),
        )
        console.print(final_panel)
        console.print()
