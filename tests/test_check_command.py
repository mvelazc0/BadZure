"""
test_check_command.py — offline test of the `badzure check` command (Phase 0 of the
agentic-badzure work). Drives CheckCommand.execute directly (it returns an exit code)
against the live chained fixtures, asserting reachability verdicts WITHOUT any Azure.

Exit-code contract: 0 = all paths reachable (or none), 1 = at least one unreachable,
2 = config/compile error.

Runs two ways:
    python tests/test_check_command.py
    pytest tests/test_check_command.py
"""
import os
import sys
import json

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.cli import CheckCommand  # noqa: E402
from src.entity_generator import EntityGenerator  # noqa: E402

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_CHAINED = os.path.join(_REPO, "examples", "chained")
_DATA = os.path.join(_REPO, "entity_data")


def _cmd():
    # Absolute entity_data dir so the command runs regardless of cwd.
    cmd = CheckCommand()
    cmd.generator = EntityGenerator(data_dir=_DATA)
    return cmd


def _fixture(name):
    return os.path.join(_CHAINED, name)


# ---------------------------------------------------------------------------
# Reachable / unreachable / baseline-only verdicts
# ---------------------------------------------------------------------------
def test_reachable_chain_exits_zero():
    code = _cmd().execute(_fixture("chained_apex.yml"))
    assert code == 0


def test_unreachable_chain_exits_one():
    code = _cmd().execute(_fixture("chained_unreachable.yml"))
    assert code == 1


def test_baseline_only_exits_zero():
    code = _cmd().execute(_fixture("chained_org_baseline.yml"))
    assert code == 0


# ---------------------------------------------------------------------------
# Config / compile errors -> exit 2
# ---------------------------------------------------------------------------
def test_missing_file_exits_two():
    code = _cmd().execute(os.path.join(_CHAINED, "does_not_exist.yml"))
    assert code == 2


def test_legacy_config_exits_two(tmp_path):
    p = tmp_path / "legacy.yml"
    p.write_text("mode: random\ntenant:\n  domain: contoso.com\n")
    code = _cmd().execute(str(p))
    assert code == 2


def test_empty_declarative_config_exits_two(tmp_path):
    # A dict that is neither baseline nor attack_paths -> ScenarioConfigError -> 2.
    p = tmp_path / "empty.yml"
    p.write_text("tenant:\n  domain: contoso.com\n")
    code = _cmd().execute(str(p))
    assert code == 2


# ---------------------------------------------------------------------------
# --json verdict shape (the Gatekeeper subagent's machine contract)
# ---------------------------------------------------------------------------
def test_json_output_reachable(capsys):
    code = _cmd().execute(_fixture("chained_apex.yml"), json_output=True)
    out = capsys.readouterr().out
    payload = json.loads(out)
    assert code == 0
    assert payload["ok"] is True
    assert payload["summary"]["total"] == payload["summary"]["reachable"]
    assert payload["summary"]["unreachable"] == 0
    path = payload["paths"][0]
    assert path["status"] == "reached"
    assert path["reachable"] is True
    assert len(path["steps"]) > 0
    assert "capability" in path["objective"]
    # The narrative description is surfaced so the crew can read it out (apex authors one).
    assert path["objective"].get("description")
    assert path["objective"].get("name")


def test_json_output_unreachable(capsys):
    code = _cmd().execute(_fixture("chained_unreachable.yml"), json_output=True)
    out = capsys.readouterr().out
    payload = json.loads(out)
    assert code == 1
    assert payload["ok"] is False
    assert payload["summary"]["unreachable"] >= 1
    assert any(not p["reachable"] for p in payload["paths"])
    # An unreachable path carries a human-readable reason for the Adversary to repair.
    bad = next(p for p in payload["paths"] if not p["reachable"])
    assert bad["reason"]


def test_json_error_is_structured(capsys, tmp_path):
    p = tmp_path / "legacy.yml"
    p.write_text("mode: random\n")
    code = _cmd().execute(str(p), json_output=True)
    out = capsys.readouterr().out
    payload = json.loads(out)
    assert code == 2
    assert payload["ok"] is False
    assert "error" in payload


# ---------------------------------------------------------------------------
# Structural PREFLIGHT: check runs the builder validation, so a config that would
# crash `terraform apply` is caught offline (exit 2) — the Adversary's self-repair
# loop + the Gatekeeper see it here, not mid-apply.
# ---------------------------------------------------------------------------
def test_certificate_secret_mismatch_preflight_exits_two(capsys, tmp_path):
    """The exact production bug: an app_secret data_inject bound to a CERTIFICATE
    credential. It is reachability-valid but crashes apply (generic.tf:404). The
    preflight must reject it with a clear password-vs-certificate message."""
    import glob
    ga = "62e90394-69f5-4237-9190-012177145e10"
    cfg = tmp_path / "bug.yml"
    cfg.write_text(
        "schema: graph\n"
        "attack_paths:\n"
        "  bug:\n"
        "    objective: {name: Secret theft, impact: high}\n"
        "    initial_access: {method: compromised_identity, principal_ref: alice}\n"
        "    identities:\n"
        "      users: [{ref: alice}]\n"
        "      applications: [{ref: bugcertapp}]\n"
        "    resources:\n"
        "      key_vaults: [{ref: kv01}]\n"
        "    assignments:\n"
        "      - {id: a1, type: azure_rbac, principal_ref: alice,\n"
        "         role: Key Vault Secrets User, scope_ref: kv01}\n"
        f"      - {{id: a2, type: entra_role, principal_ref: bugcertapp, role: {ga}}}\n"
        "    credentials:\n"
        "      - {ref: c1, app_ref: bugcertapp, type: certificate}\n"
        "    data_injects:\n"
        "      - {id: d1, material: app_secret, credential_ref: c1,\n"
        "         location: key_vault_secret, location_ref: kv01, name: s}\n"
    )
    try:
        code = _cmd().execute(str(cfg), json_output=True)
        out = capsys.readouterr().out
        payload = json.loads(out)
        assert code == 2
        assert payload["ok"] is False
        assert "password" in payload["error"] and "certificate" in payload["error"]
    finally:
        # The loader auto-minted a cert for the certificate credential; clean it up.
        tf = os.path.join(_REPO, "terraform")
        for f in (glob.glob(os.path.join(tf, "bugcertapp-*.pem"))
                  + glob.glob(os.path.join(tf, "bugcertapp-*.key"))
                  + glob.glob(os.path.join(tf, "bugcertapp-*.pfx"))):
            os.remove(f)


# ---------------------------------------------------------------------------
# Self-run support: `python tests/test_check_command.py`
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import logging
    logging.disable(logging.CRITICAL)

    class _Cap:
        """Minimal capsys stand-in for the self-run path."""
        def readouterr(self):
            import io
            return type("R", (), {"out": _Cap._buf.getvalue(), "err": ""})()
        _buf = None

    failures = 0
    # Plain (no-capsys) tests.
    for fn in (test_reachable_chain_exits_zero, test_unreachable_chain_exits_one,
               test_baseline_only_exits_zero, test_missing_file_exits_two):
        try:
            fn()
            print(f"PASS {fn.__name__}")
        except AssertionError as e:
            failures += 1
            print(f"FAIL {fn.__name__}: {e}")

    # tmp_path / capsys tests via a quick tempdir + stdout capture.
    import tempfile
    import io
    import contextlib
    from pathlib import Path

    def _run_capture(callable_):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            cap = type("C", (), {"readouterr": lambda self: type(
                "R", (), {"out": buf.getvalue(), "err": ""})()})()
            callable_(cap)
        return

    with tempfile.TemporaryDirectory() as d:
        tp = Path(d)
        for fn in (test_legacy_config_exits_two, test_empty_declarative_config_exits_two):
            try:
                fn(tp)
                print(f"PASS {fn.__name__}")
            except AssertionError as e:
                failures += 1
                print(f"FAIL {fn.__name__}: {e}")

        for fn in (test_json_output_reachable, test_json_output_unreachable):
            try:
                buf = io.StringIO()
                with contextlib.redirect_stdout(buf):
                    cap = type("C", (), {"readouterr": lambda self, b=buf: type(
                        "R", (), {"out": b.getvalue(), "err": ""})()})()
                    fn(cap)
                print(f"PASS {fn.__name__}")
            except AssertionError as e:
                failures += 1
                print(f"FAIL {fn.__name__}: {e}")
        try:
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                cap = type("C", (), {"readouterr": lambda self, b=buf: type(
                    "R", (), {"out": b.getvalue(), "err": ""})()})()
                test_json_error_is_structured(cap, tp)
            print("PASS test_json_error_is_structured")
        except AssertionError as e:
            failures += 1
            print(f"FAIL test_json_error_is_structured: {e}")

    print(f"\n{'ALL PASSED' if failures == 0 else str(failures) + ' FAILED'}")
    sys.exit(1 if failures else 0)
