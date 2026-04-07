"""
Tests: Entra ID tools register correctly and are discoverable via the tool registry.

These tests require NO Azure credentials and NO network access.
They only verify that the @register_tool decorators fired and the tool names
are present in the registry.
"""

import importlib
import sys

import pytest

from strix.tools.registry import clear_registry


def _reload_tools() -> object:
    """Wipe registry + module cache, then re-import strix.tools."""
    clear_registry()
    for name in list(sys.modules):
        if name == "strix.tools" or name.startswith("strix.tools."):
            sys.modules.pop(name, None)
    return importlib.import_module("strix.tools")


@pytest.fixture(autouse=True)
def _patch_config(monkeypatch: pytest.MonkeyPatch) -> None:
    """Prevent Config.load() from touching the filesystem during import."""
    from strix.config import Config

    monkeypatch.setattr(Config, "load", classmethod(lambda _cls: {"env": {}}))
    monkeypatch.setenv("STRIX_SANDBOX_MODE", "false")
    monkeypatch.setenv("STRIX_DISABLE_BROWSER", "true")
    monkeypatch.delenv("PERPLEXITY_API_KEY", raising=False)


# ---------------------------------------------------------------------------
# Graph tools
# ---------------------------------------------------------------------------

EXPECTED_GRAPH_TOOLS = {
    "entra_get_tenant_info",
    "entra_list_stale_users",
    "entra_list_stale_service_principals",
    "entra_list_privileged_role_assignments",
    "entra_list_app_permissions",
    "entra_list_guests",
    "entra_list_conditional_access_policies",
    "entra_list_role_assignments_per_user",
}

EXPECTED_REPORTING_TOOLS = {
    "create_identity_finding",
}

ALL_ENTRA_TOOLS = EXPECTED_GRAPH_TOOLS | EXPECTED_REPORTING_TOOLS


@pytest.mark.parametrize("tool_name", sorted(ALL_ENTRA_TOOLS))
def test_entra_tool_is_registered(tool_name: str) -> None:
    tools = _reload_tools()
    names = set(tools.get_tool_names())  # type: ignore[attr-defined]
    assert tool_name in names, (
        f"Tool '{tool_name}' was not found in the registry. "
        f"Registered tools: {sorted(names)}"
    )


def test_all_nine_entra_tools_are_registered() -> None:
    tools = _reload_tools()
    names = set(tools.get_tool_names())  # type: ignore[attr-defined]
    missing = ALL_ENTRA_TOOLS - names
    assert not missing, f"Missing Entra tools from registry: {sorted(missing)}"


def test_entra_tools_are_non_sandbox() -> None:
    """All Entra tools must run locally (sandbox_execution=False)."""
    from strix.tools.registry import tools as _tools_list

    _reload_tools()

    # tools is a list[dict], not a dict — build a lookup by name
    tools_by_name = {t["name"]: t for t in _tools_list}

    for tool_name in ALL_ENTRA_TOOLS:
        tool_meta = tools_by_name.get(tool_name)
        assert tool_meta is not None, f"'{tool_name}' not found in registry"
        assert tool_meta.get("sandbox_execution") is False, (
            f"'{tool_name}' must have sandbox_execution=False "
            "(it calls Microsoft Graph externally, not via Docker tool server)"
        )
