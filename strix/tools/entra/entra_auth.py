"""
Microsoft Graph API authentication helpers.

Not registered as tools — imported and used by entra_graph_actions.py.
Handles MSAL token acquisition, caching, pagination, and throttling.
"""

import logging
import os
import time
from typing import Any


logger = logging.getLogger(__name__)

# Module-level token cache: { tenant_id: { "access_token": str, "expires_at": float } }
_token_cache: dict[str, dict[str, Any]] = {}


def _get_credentials() -> tuple[str, str, str]:
    """Read Azure credentials from environment variables."""
    client_id = os.getenv("AZURE_CLIENT_ID", "")
    client_secret = os.getenv("AZURE_CLIENT_SECRET", "")
    tenant_id = os.getenv("AZURE_TENANT_ID", "")

    missing = []
    if not client_id:
        missing.append("AZURE_CLIENT_ID")
    if not client_secret:
        missing.append("AZURE_CLIENT_SECRET")
    if not tenant_id:
        missing.append("AZURE_TENANT_ID")

    if missing:
        raise RuntimeError(
            f"Missing required environment variables: {', '.join(missing)}. "
            "Set AZURE_CLIENT_ID, AZURE_CLIENT_SECRET, and AZURE_TENANT_ID "
            "before running an identity audit."
        )

    return client_id, client_secret, tenant_id


def get_graph_token() -> str:
    """
    Acquire a Microsoft Graph API access token using client credentials flow.

    Uses MSAL ConfidentialClientApplication with scope
    https://graph.microsoft.com/.default. Caches the token per tenant_id
    and re-acquires only when within 60 seconds of expiry.

    Returns:
        Bearer token string.

    Raises:
        RuntimeError: if env vars are missing or token acquisition fails.
    """
    try:
        import msal
    except ImportError as e:
        raise RuntimeError(
            "msal package is required for Entra ID tools. "
            "Install it with: pip install msal"
        ) from e

    client_id, client_secret, tenant_id = _get_credentials()

    # Check cache
    cached = _token_cache.get(tenant_id)
    if cached and cached.get("expires_at", 0) > time.time() + 60:
        return str(cached["access_token"])

    authority = f"https://login.microsoftonline.com/{tenant_id}"
    scope = ["https://graph.microsoft.com/.default"]

    app = msal.ConfidentialClientApplication(
        client_id=client_id,
        client_credential=client_secret,
        authority=authority,
    )

    result = app.acquire_token_for_client(scopes=scope)

    if "access_token" not in result:
        error = result.get("error", "unknown_error")
        description = result.get("error_description", "No description provided")
        raise RuntimeError(
            f"Failed to acquire Microsoft Graph token: {error} — {description}"
        )

    expires_in = result.get("expires_in", 3600)
    _token_cache[tenant_id] = {
        "access_token": result["access_token"],
        "expires_at": time.time() + expires_in,
    }

    return str(result["access_token"])


def graph_get(path: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
    """
    Perform a GET request against Microsoft Graph API v1.0.

    Handles 429 Retry-After throttling with up to 3 retries.
    Raises GraphAPIError on unrecoverable HTTP errors.

    Args:
        path: Graph API path, e.g. "users" or "identity/conditionalAccess/policies"
        params: OData query parameters ($select, $filter, $top, $expand, etc.)

    Returns:
        Parsed JSON response dict.
    """
    import httpx

    token = get_graph_token()
    base_url = "https://graph.microsoft.com/v1.0"
    url = f"{base_url}/{path.lstrip('/')}"

    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }

    max_retries = 3
    for attempt in range(max_retries):
        try:
            with httpx.Client(timeout=30) as client:
                response = client.get(url, headers=headers, params=params or {})

                if response.status_code == 429:
                    retry_after = int(response.headers.get("Retry-After", "10"))
                    logger.warning(
                        f"Graph API throttled on {path}. "
                        f"Retrying after {retry_after}s (attempt {attempt + 1}/{max_retries})"
                    )
                    time.sleep(retry_after)
                    continue

                if response.status_code == 401:
                    # Token may have expired mid-run — clear cache and retry once
                    _token_cache.clear()
                    if attempt < max_retries - 1:
                        token = get_graph_token()
                        headers["Authorization"] = f"Bearer {token}"
                        continue
                    raise RuntimeError(
                        f"Authentication failed for Graph API path: {path}. "
                        "Check that AZURE_CLIENT_ID, AZURE_CLIENT_SECRET, and "
                        "AZURE_TENANT_ID are correct and the app has required permissions."
                    )

                if response.status_code == 403:
                    raise RuntimeError(
                        f"Permission denied for Graph API path: {path}. "
                        "Ensure the service principal has the required API permissions: "
                        "Directory.Read.All, AuditLog.Read.All, Policy.Read.All, "
                        "RoleManagement.Read.Directory, Application.Read.All"
                    )

                response.raise_for_status()
                return dict(response.json())

        except httpx.TimeoutException:
            if attempt == max_retries - 1:
                raise RuntimeError(f"Graph API request timed out for path: {path}") from None
            time.sleep(2 ** attempt)

        except httpx.RequestError as e:
            if attempt == max_retries - 1:
                raise RuntimeError(f"Graph API request failed for path: {path} — {e}") from e
            time.sleep(2 ** attempt)

    raise RuntimeError(f"Graph API request failed after {max_retries} attempts for path: {path}")


def graph_get_beta(path: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
    """
    Same as graph_get but targets the /beta endpoint.
    Used for endpoints not yet in v1.0 (e.g. servicePrincipalSignInActivities).
    """
    import httpx

    token = get_graph_token()
    base_url = "https://graph.microsoft.com/beta"
    url = f"{base_url}/{path.lstrip('/')}"

    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }

    max_retries = 3
    for attempt in range(max_retries):
        try:
            with httpx.Client(timeout=30) as client:
                response = client.get(url, headers=headers, params=params or {})

                if response.status_code == 429:
                    retry_after = int(response.headers.get("Retry-After", "10"))
                    time.sleep(retry_after)
                    continue

                if response.status_code in (401, 403):
                    raise RuntimeError(
                        f"Auth/permission error for beta Graph path: {path} "
                        f"(HTTP {response.status_code})"
                    )

                response.raise_for_status()
                return dict(response.json())

        except httpx.TimeoutException:
            if attempt == max_retries - 1:
                raise RuntimeError(
                    f"Beta Graph API request timed out for path: {path}"
                ) from None
            time.sleep(2 ** attempt)

        except httpx.RequestError as e:
            if attempt == max_retries - 1:
                raise RuntimeError(
                    f"Beta Graph API request failed for path: {path} — {e}"
                ) from e
            time.sleep(2 ** attempt)

    raise RuntimeError(
        f"Beta Graph API request failed after {max_retries} attempts for: {path}"
    )


def graph_get_all_pages(
    path: str,
    params: dict[str, Any] | None = None,
    beta: bool = False,
) -> list[dict[str, Any]]:
    """
    Paginate through all pages of a Graph API response following @odata.nextLink.

    Args:
        path: Graph API path.
        params: OData query parameters.
        beta: If True, uses the /beta endpoint.

    Returns:
        Flat list of all items from the 'value' array across all pages.
    """
    import httpx

    token = get_graph_token()
    base_url = (
        "https://graph.microsoft.com/beta"
        if beta
        else "https://graph.microsoft.com/v1.0"
    )

    url = f"{base_url}/{path.lstrip('/')}"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }

    all_items: list[dict[str, Any]] = []
    current_params = params or {}

    while url:
        try:
            with httpx.Client(timeout=30) as client:
                response = client.get(url, headers=headers, params=current_params)

                if response.status_code == 429:
                    retry_after = int(response.headers.get("Retry-After", "10"))
                    logger.warning(f"Throttled during pagination of {path}. Waiting {retry_after}s")
                    time.sleep(retry_after)
                    continue

                response.raise_for_status()
                data = response.json()

        except httpx.RequestError as e:
            logger.error(f"Pagination request failed for {url}: {e}")
            break

        items = data.get("value", [])
        all_items.extend(items)

        # Follow nextLink — clear params since they're embedded in the link
        url = data.get("@odata.nextLink", "")
        current_params = {}

    return all_items
