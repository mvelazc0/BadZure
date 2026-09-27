"""
azure_rest.py: a small REST client for the telemetry hub's own Azure calls
(Phase 4 of dev-docs/redesign/telemetry-implementation-plan.md).

Everything BadZure needs to talk to Azure directly (not through Terraform) goes
through here: bring-your-own workspace verification, the Activity Log slot and
duplicate check, and the Entra diagnostic setting. It uses the same credential
Terraform uses: a client-credentials service principal secret when
ARM_CLIENT_ID / ARM_CLIENT_SECRET / ARM_TENANT_ID are set, otherwise the Azure
CLI's cached login (`az account get-access-token`). Other auth modes (certificate
SP, managed identity) are not supported here yet, so they raise a clear error
instead of failing confusingly deep in an HTTP call.

Every collaborator (the environment, subprocess.run, requests, and even the sleep
used between a retry) is constructor-injected, so tests never shell out, never
hit the network, and never actually wait.
"""
import json
import logging
import os
import subprocess
import time
from typing import Callable, Dict, Optional

import requests

ARM = "https://management.azure.com"

# Status codes worth one retry: rate limiting and transient server errors.
_RETRYABLE_STATUSES = frozenset({429, 500, 502, 503, 504})
_MAX_RETRY_AFTER_SECONDS = 10.0


class AzureRestError(RuntimeError):
    """A non-2xx Azure response the caller didn't ask to be treated specially
    (GET's 404 and DELETE's 404 are handled by the caller instead), or a
    credential problem before any HTTP call was even made. Carries the status
    and body so callers can render a useful message; status is 0 for a
    credential-resolution failure that never reached Azure."""

    def __init__(self, status: int, body: str, message: Optional[str] = None):
        self.status = status
        self.body = body
        super().__init__(message or f"Azure REST call failed: {status} {body}")


class TokenProvider:
    """Resolves and caches an access token per resource (e.g.
    https://management.azure.com). Auth precedence mirrors Terraform's azurerm
    provider:

    1. A service-principal secret, via ARM_CLIENT_ID / ARM_CLIENT_SECRET /
       ARM_TENANT_ID: a client-credentials POST to Entra's token endpoint.
    2. Otherwise, the Azure CLI's cached login: `az account get-access-token`.

    Certificate-based SP auth (ARM_CLIENT_CERTIFICATE_PATH) and managed identity
    auth (ARM_USE_MSI) are recognized but not supported here yet; both raise
    AzureRestError with a clear message rather than silently falling through to
    a CLI call that has nothing to do with the credential the operator actually
    configured.
    """

    def __init__(self, env: Optional[Dict[str, str]] = None,
                 run: Callable = subprocess.run, http=requests):
        self.env = env if env is not None else os.environ
        self.run = run
        self.http = http
        self._cache: Dict[str, str] = {}

    def token(self, resource: str) -> str:
        if resource in self._cache:
            return self._cache[resource]

        client_id = self.env.get("ARM_CLIENT_ID")
        client_secret = self.env.get("ARM_CLIENT_SECRET")
        tenant_id = self.env.get("ARM_TENANT_ID")

        if client_id and client_secret and tenant_id:
            token = self._sp_token(client_id, client_secret, tenant_id, resource)
        elif client_id and self.env.get("ARM_CLIENT_CERTIFICATE_PATH"):
            raise AzureRestError(
                0, "",
                "Certificate-based service principal authentication is not "
                "supported for telemetry yet. Use a client secret "
                "(ARM_CLIENT_ID / ARM_CLIENT_SECRET / ARM_TENANT_ID) or `az login`."
            )
        elif str(self.env.get("ARM_USE_MSI", "")).lower() in ("1", "true"):
            raise AzureRestError(
                0, "",
                "Managed identity authentication is not supported for telemetry "
                "yet. Use a service principal secret "
                "(ARM_CLIENT_ID / ARM_CLIENT_SECRET / ARM_TENANT_ID) or `az login`."
            )
        else:
            token = self._cli_token(resource)

        self._cache[resource] = token
        return token

    def _sp_token(self, client_id: str, client_secret: str, tenant_id: str,
                  resource: str) -> str:
        url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
        data = {
            "grant_type": "client_credentials",
            "client_id": client_id,
            "client_secret": client_secret,
            "scope": f"{resource}/.default",
        }
        response = self.http.post(url, data=data, timeout=30)
        if response.status_code != 200:
            raise AzureRestError(
                response.status_code, response.text,
                f"Failed to obtain a telemetry token for {resource}: "
                f"{response.status_code} {response.text}",
            )
        try:
            token = response.json().get("access_token")
        except (ValueError, AttributeError):
            token = None
        if not token:
            raise AzureRestError(
                response.status_code, response.text,
                f"Token response for {resource} had no access_token.",
            )
        return token

    def _cli_token(self, resource: str) -> str:
        try:
            result = self.run(
                ["az", "account", "get-access-token", "--resource", resource, "-o", "json"],
                capture_output=True, text=True, timeout=30,
            )
        except FileNotFoundError:
            raise AzureRestError(
                0, "",
                "Azure CLI (`az`) not found on PATH; needed to get a telemetry "
                "token when no service principal env vars are set."
            )
        if result.returncode != 0:
            raise AzureRestError(
                0, result.stderr or result.stdout or "",
                f"`az account get-access-token --resource {resource}` failed: "
                f"{result.stderr or result.stdout}",
            )
        try:
            body = json.loads(result.stdout)
        except json.JSONDecodeError:
            raise AzureRestError(
                0, result.stdout or "",
                "Could not parse `az account get-access-token` output.",
            )
        token = body.get("accessToken")
        if not token:
            raise AzureRestError(
                0, result.stdout or "",
                "`az account get-access-token` returned no accessToken.",
            )
        return token


def _retry_after_seconds(response, cap: float) -> float:
    """Honor a Retry-After header (seconds), capped at `cap`. Falls back to 1s
    when the header is missing or not a plain integer (HTTP-date Retry-After
    values are rare on Azure's ARM endpoints and not worth parsing here)."""
    headers = getattr(response, "headers", None) or {}
    value = headers.get("Retry-After")
    try:
        seconds = float(value)
    except (TypeError, ValueError):
        seconds = 1.0
    return max(0.0, min(seconds, cap))


class AzureRest:
    """A minimal ARM REST client: GET / PUT / DELETE, each taking the caller's
    api-version explicitly (Azure has no single stable version across services).
    One retry on 429 or a 5xx, honoring Retry-After capped at 10 seconds; any
    other non-2xx raises AzureRestError. 404 is handled per verb: GET returns
    None, DELETE treats it as already-done (success)."""

    def __init__(self, tokens: TokenProvider, http=requests,
                 sleep: Callable[[float], None] = time.sleep):
        self.tokens = tokens
        self.http = http
        self.sleep = sleep

    def _headers(self, resource: str) -> Dict[str, str]:
        return {
            "Authorization": f"Bearer {self.tokens.token(resource)}",
            "Content-Type": "application/json",
        }

    def _request(self, method: str, url: str, api_version: str,
                 body: Optional[dict], resource: str):
        # Callers pass ARM resource IDs ("/subscriptions/..."); make them absolute.
        if url.startswith("/"):
            url = ARM + url
        kwargs = {
            "params": {"api-version": api_version},
            "headers": self._headers(resource),
            "timeout": 30,
        }
        if body is not None:
            kwargs["json"] = body

        response = self.http.request(method, url, **kwargs)
        if response.status_code in _RETRYABLE_STATUSES:
            wait = _retry_after_seconds(response, _MAX_RETRY_AFTER_SECONDS)
            logging.debug(
                f"azure_rest: {response.status_code} from {method} {url}, "
                f"retrying once after {wait}s")
            self.sleep(wait)
            response = self.http.request(method, url, **kwargs)
        return response

    @staticmethod
    def _json_or_empty(response) -> dict:
        text = getattr(response, "text", "") or ""
        if not text:
            return {}
        try:
            return response.json()
        except ValueError:
            return {}

    def get(self, url: str, api_version: str, resource: str = ARM) -> Optional[dict]:
        response = self._request("GET", url, api_version, None, resource)
        if response.status_code == 404:
            return None
        if not (200 <= response.status_code < 300):
            raise AzureRestError(response.status_code, response.text)
        return self._json_or_empty(response)

    def put(self, url: str, api_version: str, body: dict, resource: str = ARM) -> dict:
        response = self._request("PUT", url, api_version, body, resource)
        if not (200 <= response.status_code < 300):
            raise AzureRestError(response.status_code, response.text)
        return self._json_or_empty(response)

    def delete(self, url: str, api_version: str, resource: str = ARM) -> None:
        response = self._request("DELETE", url, api_version, None, resource)
        if response.status_code == 404:
            return
        if not (200 <= response.status_code < 300):
            raise AzureRestError(response.status_code, response.text)
