"""
Tests: entra_auth.py — token caching and credential validation.

No network calls. MSAL is mocked throughout.
"""

import time
from typing import Any
from unittest.mock import MagicMock, patch

import pytest


# ---------------------------------------------------------------------------
# _get_credentials
# ---------------------------------------------------------------------------


def test_get_credentials_raises_when_env_vars_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("AZURE_CLIENT_ID", raising=False)
    monkeypatch.delenv("AZURE_CLIENT_SECRET", raising=False)
    monkeypatch.delenv("AZURE_TENANT_ID", raising=False)

    from strix.tools.entra import entra_auth

    with pytest.raises(RuntimeError, match="Missing required environment variables"):
        entra_auth._get_credentials()


def test_get_credentials_raises_on_partial_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AZURE_CLIENT_ID", "my-client-id")
    monkeypatch.delenv("AZURE_CLIENT_SECRET", raising=False)
    monkeypatch.delenv("AZURE_TENANT_ID", raising=False)

    from strix.tools.entra import entra_auth

    with pytest.raises(RuntimeError, match="AZURE_CLIENT_SECRET"):
        entra_auth._get_credentials()


def test_get_credentials_returns_tuple_when_all_set(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AZURE_CLIENT_ID", "cid")
    monkeypatch.setenv("AZURE_CLIENT_SECRET", "csecret")
    monkeypatch.setenv("AZURE_TENANT_ID", "tid")

    from strix.tools.entra import entra_auth

    client_id, client_secret, tenant_id = entra_auth._get_credentials()
    assert client_id == "cid"
    assert client_secret == "csecret"
    assert tenant_id == "tid"


# ---------------------------------------------------------------------------
# get_graph_token — MSAL mocked
# ---------------------------------------------------------------------------


def _mock_msal_app(token_result: dict[str, Any]) -> MagicMock:
    mock_app = MagicMock()
    mock_app.acquire_token_for_client.return_value = token_result
    mock_confidential_class = MagicMock(return_value=mock_app)
    return mock_confidential_class


def test_get_graph_token_returns_token(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AZURE_CLIENT_ID", "cid")
    monkeypatch.setenv("AZURE_CLIENT_SECRET", "csecret")
    monkeypatch.setenv("AZURE_TENANT_ID", "tid")

    import strix.tools.entra.entra_auth as auth

    auth._token_cache.clear()

    mock_msal_class = _mock_msal_app({"access_token": "tok123", "expires_in": 3600})

    with patch.dict("sys.modules", {"msal": MagicMock(ConfidentialClientApplication=mock_msal_class)}):
        token = auth.get_graph_token()

    assert token == "tok123"


def test_get_graph_token_uses_cache_on_second_call(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AZURE_CLIENT_ID", "cid")
    monkeypatch.setenv("AZURE_CLIENT_SECRET", "csecret")
    monkeypatch.setenv("AZURE_TENANT_ID", "tid")

    import strix.tools.entra.entra_auth as auth

    auth._token_cache.clear()
    # Pre-seed the cache with a fresh token
    auth._token_cache["tid"] = {
        "access_token": "cached_token",
        "expires_at": time.time() + 3600,  # expires in 1 hour
    }

    mock_msal_class = _mock_msal_app({"access_token": "new_token", "expires_in": 3600})

    with patch.dict("sys.modules", {"msal": MagicMock(ConfidentialClientApplication=mock_msal_class)}):
        token = auth.get_graph_token()

    # Should return cached token, not call MSAL
    assert token == "cached_token"
    mock_msal_class.assert_not_called()


def test_get_graph_token_refreshes_when_near_expiry(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AZURE_CLIENT_ID", "cid")
    monkeypatch.setenv("AZURE_CLIENT_SECRET", "csecret")
    monkeypatch.setenv("AZURE_TENANT_ID", "tid")

    import strix.tools.entra.entra_auth as auth

    auth._token_cache.clear()
    # Pre-seed cache with a token expiring in 30 seconds (< 60s threshold)
    auth._token_cache["tid"] = {
        "access_token": "stale_token",
        "expires_at": time.time() + 30,
    }

    mock_msal_class = _mock_msal_app({"access_token": "fresh_token", "expires_in": 3600})

    with patch.dict("sys.modules", {"msal": MagicMock(ConfidentialClientApplication=mock_msal_class)}):
        token = auth.get_graph_token()

    assert token == "fresh_token"


def test_get_graph_token_raises_on_msal_error(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AZURE_CLIENT_ID", "cid")
    monkeypatch.setenv("AZURE_CLIENT_SECRET", "csecret")
    monkeypatch.setenv("AZURE_TENANT_ID", "tid")

    import strix.tools.entra.entra_auth as auth

    auth._token_cache.clear()

    mock_msal_class = _mock_msal_app(
        {"error": "invalid_client", "error_description": "Bad credentials"}
    )

    with patch.dict("sys.modules", {"msal": MagicMock(ConfidentialClientApplication=mock_msal_class)}):
        with pytest.raises(RuntimeError, match="Failed to acquire Microsoft Graph token"):
            auth.get_graph_token()


def test_get_graph_token_raises_when_msal_not_installed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AZURE_CLIENT_ID", "cid")
    monkeypatch.setenv("AZURE_CLIENT_SECRET", "csecret")
    monkeypatch.setenv("AZURE_TENANT_ID", "tid")

    import strix.tools.entra.entra_auth as auth

    auth._token_cache.clear()

    # Simulate msal not being installed
    with patch("builtins.__import__", side_effect=lambda name, *a, **kw: (_ for _ in ()).throw(ImportError("No module named 'msal'")) if name == "msal" else __import__(name, *a, **kw)):
        with pytest.raises(RuntimeError, match="msal package is required"):
            auth.get_graph_token()
