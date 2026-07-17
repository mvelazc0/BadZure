"""
test_build_reachability_gate.py — offline test of build's code-enforced reachability gate.

`badzure build` proves for ITSELF that every attack path is reachable (the same deterministic
verdict `check` reports) and REFUSES to deploy otherwise — it never trusts an upstream agent's
claim. This gate runs before any network/Azure call, so it is fully offline-testable: we assert
the gate's decision without ever reaching Terraform.

Runs two ways:
    python tests/test_build_reachability_gate.py
    pytest tests/test_build_reachability_gate.py
"""
import logging
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.cli import BuildCommand  # noqa: E402

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_CHAINED = os.path.join(_REPO, "examples", "chained")
_REACHABLE = os.path.join(_CHAINED, "chained_apex.yml")
_UNREACHABLE = os.path.join(_CHAINED, "chained_unreachable.yml")


def test_gate_passes_on_reachable():
    # A reachable config clears the gate silently (returns None, no raise).
    assert BuildCommand()._reachability_gate(_REACHABLE) is None


def test_gate_refuses_unreachable():
    with pytest.raises(SystemExit) as exc:
        BuildCommand()._reachability_gate(_UNREACHABLE)
    assert exc.value.code == 1


def test_execute_aborts_before_deploy_on_unreachable(monkeypatch):
    # build.execute must hit the gate and abort with exit 1 BEFORE _build_declarative_mode
    # (i.e. before any network/Terraform). If the gate ran late, this would call out.
    called = {"deploy": False}
    monkeypatch.setattr(BuildCommand, "_build_declarative_mode",
                        lambda self, config, verbose: called.__setitem__("deploy", True))
    with pytest.raises(SystemExit) as exc:
        BuildCommand().execute(_UNREACHABLE)
    assert exc.value.code == 1
    assert called["deploy"] is False


if __name__ == "__main__":
    logging.disable(logging.CRITICAL)
    failures = 0

    try:
        test_gate_passes_on_reachable()
        print("PASS test_gate_passes_on_reachable")
    except (AssertionError, SystemExit) as e:
        failures += 1
        print(f"FAIL test_gate_passes_on_reachable: {e}")

    for name in ("test_gate_refuses_unreachable",):
        try:
            with pytest.raises(SystemExit) as exc:
                BuildCommand()._reachability_gate(_UNREACHABLE)
            assert exc.value.code == 1
            print(f"PASS {name}")
        except Exception as e:  # noqa: BLE001
            failures += 1
            print(f"FAIL {name}: {e}")

    print(f"\n{'ALL PASSED' if failures == 0 else str(failures) + ' FAILED'}")
    sys.exit(1 if failures else 0)
