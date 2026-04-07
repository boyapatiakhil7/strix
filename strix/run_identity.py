"""
Entry point wrapper for strix-identity CLI.

This module lives OUTSIDE strix.interface so that importing it does NOT trigger
strix/interface/__init__.py (which runs `from .main import main` and imports all
pentest tools with STRIX_SANDBOX_MODE=true before we can override it).

By setting STRIX_SANDBOX_MODE=false here — before any strix.interface or strix.tools
import — the @register_tool decorators on Entra tools will see the correct value.
"""

import os

# Must be before any strix.tools import.  strix.interface.__init__ triggers
# strix.interface.main which imports strix.tools, so this must come first.
os.environ["STRIX_SANDBOX_MODE"] = "false"


def main() -> None:
    from strix.interface.identity_main import main as _main

    _main()
