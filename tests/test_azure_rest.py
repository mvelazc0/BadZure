"""
test_azure_rest.py: offline tests for src/azure_rest.py (Phase 4 of
dev-docs/redesign/telemetry-implementation-plan.md): the small REST client the
telemetry hub uses to talk to Azure directly (never through Terraform).

Every collaborator (env, subprocess.run, requests-shaped http, even the sleep
between a retry) is a fake here: no real network call, no real `az`, no real
wait. FakeHttp/FakeRun below stand in for `requests` and `subprocess.run`.

Runs two ways:
    python tests/test_azure_rest.py
    pytest tests/test_azure_rest.py
"""
import json
import logging
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.azure_rest import ARM, AzureRest, AzureRestError, TokenProvider  # noqa: E402


# ---------------------------------------------------------------------------
# Fakes
# ---------------------------------------------------------------------------
class FakeResponse:
    def __init__(self, status_code, json_body=None, text=None, headers=None):
        self.status_code = status_code
        self._json_body = json_body
        if text is not None:
            self.text = text
        elif json_body is not None:
            self.text = json.dumps(json_body)
        else:
            self.text = ""
        self.headers = headers or {}

    def json(self):
        if self._json_body is None:
            raise ValueError("FakeResponse has no JSON body")
        return self._json_body


class FakeHttp:
    """Stands in for the `requests` module: records every call, returns
    canned responses in order (one per `request`/`post` call)."""

    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def request(self, method, url, **kwargs):
        self.calls.append(("request", method, url, kwargs))
        return self.responses.pop(0)

    def post(self, url, **kwargs):
        self.calls.append(("post", "POST", url, kwargs))
        return self.responses.pop(0)


class FakeCompletedProcess:
    def __init__(self, returncode, stdout="", stderr=""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


class FakeRun:
    def __init__(self, result):
        self.result = result
        self.calls = []

    def __call__(self, cmd, **kwargs):
        self.calls.append(cmd)
        return self.result


class FakeTokens:
    """A canned TokenProvider stand-in for the AzureRest (GET/PUT/DELETE/retry)
    tests, which have nothing to do with credential resolution."""

    def __init__(self, token="tok-abc"):
        self._token = token
        self.calls = []

    def token(self, resource):
        self.calls.append(resource)
        return self._token


def _recording_sleep():
    calls = []

    def sleep(seconds):
        calls.append(seconds)

    sleep.calls = calls
    return sleep


# ---------------------------------------------------------------------------
# TokenProvider: auth mode selection
# ---------------------------------------------------------------------------
def test_sp_env_vars_use_client_credentials():
    env = {"ARM_CLIENT_ID": "cid", "ARM_CLIENT_SECRET": "csecret", "ARM_TENANT_ID": "tid"}
    http = FakeHttp([FakeResponse(200, {"access_token": "sp-token"})])
    run = FakeRun(FakeCompletedProcess(0))
    tp = TokenProvider(env=env, run=run, http=http)

    token = tp.token(ARM)

    assert token == "sp-token"
    assert run.calls == []  # subprocess never invoked
    assert len(http.calls) == 1
    kind, method, url, kwargs = http.calls[0]
    assert url == "https://login.microsoftonline.com/tid/oauth2/v2.0/token"
    assert kwargs["data"]["grant_type"] == "client_credentials"
    assert kwargs["data"]["client_id"] == "cid"
    assert kwargs["data"]["client_secret"] == "csecret"
    assert kwargs["data"]["scope"] == f"{ARM}/.default"
    print("ok: SP env vars use a client-credentials POST, no subprocess call")


def test_no_sp_env_uses_az_cli():
    env = {}
    http = FakeHttp([])
    run = FakeRun(FakeCompletedProcess(0, stdout=json.dumps({"accessToken": "cli-token"})))
    tp = TokenProvider(env=env, run=run, http=http)

    token = tp.token(ARM)

    assert token == "cli-token"
    assert http.calls == []
    assert len(run.calls) == 1
    cmd = run.calls[0]
    assert cmd[:3] == ["az", "account", "get-access-token"]
    assert "--resource" in cmd and ARM in cmd
    print("ok: no SP env vars falls back to `az account get-access-token`")


def test_token_cached_per_resource():
    env = {}
    run = FakeRun(FakeCompletedProcess(0, stdout=json.dumps({"accessToken": "cli-token"})))
    tp = TokenProvider(env=env, run=run, http=FakeHttp([]))

    first = tp.token(ARM)
    second = tp.token(ARM)

    assert first == second == "cli-token"
    assert len(run.calls) == 1   # cached: only one subprocess call for two token() calls
    print("ok: token is cached per resource")


def test_cli_token_nonzero_exit_raises():
    env = {}
    run = FakeRun(FakeCompletedProcess(1, stderr="not logged in"))
    tp = TokenProvider(env=env, run=run, http=FakeHttp([]))

    try:
        tp.token(ARM)
    except AzureRestError as e:
        assert "not logged in" in str(e) or "not logged in" in e.body
    else:
        raise AssertionError("expected AzureRestError")
    print("ok: a failing `az account get-access-token` raises AzureRestError")


def test_certificate_sp_not_supported():
    env = {"ARM_CLIENT_ID": "cid", "ARM_CLIENT_CERTIFICATE_PATH": "/tmp/cert.pem"}
    tp = TokenProvider(env=env, run=FakeRun(FakeCompletedProcess(0)), http=FakeHttp([]))

    try:
        tp.token(ARM)
    except AzureRestError as e:
        assert "certificate" in str(e).lower()
    else:
        raise AssertionError("expected AzureRestError for certificate SP auth")
    print("ok: certificate SP auth gives a clear 'not supported yet' error")


def test_managed_identity_not_supported():
    env = {"ARM_USE_MSI": "true"}
    tp = TokenProvider(env=env, run=FakeRun(FakeCompletedProcess(0)), http=FakeHttp([]))

    try:
        tp.token(ARM)
    except AzureRestError as e:
        assert "managed identity" in str(e).lower()
    else:
        raise AssertionError("expected AzureRestError for managed identity auth")
    print("ok: managed identity auth gives a clear 'not supported yet' error")


# ---------------------------------------------------------------------------
# AzureRest: GET / PUT / DELETE and retry
# ---------------------------------------------------------------------------
def test_get_returns_none_on_404():
    http = FakeHttp([FakeResponse(404)])
    rest = AzureRest(FakeTokens(), http=http, sleep=_recording_sleep())
    assert rest.get("https://example/x", "2022-01-01") is None
    print("ok: GET returns None on 404")


def test_get_raises_on_403_with_status():
    http = FakeHttp([FakeResponse(403, text="Forbidden")])
    rest = AzureRest(FakeTokens(), http=http, sleep=_recording_sleep())
    try:
        rest.get("https://example/x", "2022-01-01")
    except AzureRestError as e:
        assert e.status == 403
        assert "Forbidden" in e.body
    else:
        raise AssertionError("expected AzureRestError")
    print("ok: GET raises AzureRestError with status/body on 403")


def test_put_returns_body_on_success():
    http = FakeHttp([FakeResponse(200, {"id": "abc"})])
    rest = AzureRest(FakeTokens(), http=http, sleep=_recording_sleep())
    result = rest.put("https://example/x", "2022-01-01", {"properties": {}})
    assert result == {"id": "abc"}
    print("ok: PUT returns the response body on 2xx")


def test_delete_treats_404_as_success():
    http = FakeHttp([FakeResponse(404)])
    rest = AzureRest(FakeTokens(), http=http, sleep=_recording_sleep())
    rest.delete("https://example/x", "2022-01-01")  # must not raise
    print("ok: DELETE treats 404 as success")


def test_delete_raises_on_other_error():
    # 400 is not retryable, so exactly one call is expected.
    http = FakeHttp([FakeResponse(400, text="boom")])
    rest = AzureRest(FakeTokens(), http=http, sleep=_recording_sleep())
    try:
        rest.delete("https://example/x", "2022-01-01")
    except AzureRestError as e:
        assert e.status == 400
    else:
        raise AssertionError("expected AzureRestError")
    print("ok: DELETE raises on a non-retryable, non-404 error")


def test_retry_on_429_honors_retry_after_capped():
    http = FakeHttp([
        FakeResponse(429, headers={"Retry-After": "50"}),
        FakeResponse(200, {"ok": True}),
    ])
    sleep = _recording_sleep()
    rest = AzureRest(FakeTokens(), http=http, sleep=sleep)

    result = rest.get("https://example/x", "2022-01-01")

    assert result == {"ok": True}
    assert sleep.calls == [10.0]   # capped at 10s even though Retry-After said 50
    assert len(http.calls) == 2    # exactly one retry
    print("ok: one retry on 429, Retry-After capped at 10s")


def test_retry_on_5xx_then_success():
    http = FakeHttp([FakeResponse(503), FakeResponse(200, {"ok": True})])
    sleep = _recording_sleep()
    rest = AzureRest(FakeTokens(), http=http, sleep=sleep)

    result = rest.get("https://example/x", "2022-01-01")

    assert result == {"ok": True}
    assert len(sleep.calls) == 1
    print("ok: one retry on a 5xx")


def test_no_retry_on_immediate_success():
    http = FakeHttp([FakeResponse(200, {"ok": True})])
    sleep = _recording_sleep()
    rest = AzureRest(FakeTokens(), http=http, sleep=sleep)

    rest.get("https://example/x", "2022-01-01")

    assert sleep.calls == []
    assert len(http.calls) == 1
    print("ok: no retry, no sleep, on immediate success")


def test_only_one_retry_even_if_second_call_also_fails():
    http = FakeHttp([FakeResponse(429, headers={"Retry-After": "1"}),
                     FakeResponse(429, headers={"Retry-After": "1"})])
    sleep = _recording_sleep()
    rest = AzureRest(FakeTokens(), http=http, sleep=sleep)

    try:
        rest.get("https://example/x", "2022-01-01")
    except AzureRestError as e:
        assert e.status == 429
    else:
        raise AssertionError("expected AzureRestError")
    assert len(sleep.calls) == 1   # only one retry attempted, not a loop
    print("ok: exactly one retry, then the error surfaces")


# ---------------------------------------------------------------------------
# Self-run support
# ---------------------------------------------------------------------------
def test_resource_id_urls_are_made_absolute():
    """Callers pass ARM resource IDs; the request must go to management.azure.com."""
    http = FakeHttp([FakeResponse(200, {"id": "x"})])
    rest = AzureRest(FakeTokens(), http=http, sleep=_recording_sleep())
    rest.get("/subscriptions/s/resourceGroups/rg", "2021-04-01")
    assert http.calls[0][2] == f"{ARM}/subscriptions/s/resourceGroups/rg"
    print("ok: resource-ID URLs are sent to management.azure.com")


def test_cli_token_failure_is_a_credential_error():
    """A failing `az` is a credential problem (status 0), so `plan` can degrade."""
    run = FakeRun(FakeCompletedProcess(1, stderr="Please run 'az login'"))
    tp = TokenProvider(env={}, run=run, http=FakeHttp([]))
    try:
        tp.token(ARM)
    except AzureRestError as e:
        assert e.status == 0
    else:
        raise AssertionError("expected AzureRestError")
    print("ok: az token failure carries status 0")


def _run_all():
    tests = [(k, v) for k, v in sorted(globals().items())
             if k.startswith("test_") and callable(v)]
    failures = 0
    for name, t in tests:
        try:
            t()
        except AssertionError as e:
            failures += 1
            print(f"FAIL {name}: {e}")
    print(f"\n{len(tests) - failures}/{len(tests)} azure_rest tests passed.")
    if failures:
        sys.exit(1)


if __name__ == "__main__":
    logging.disable(logging.CRITICAL)
    _run_all()
