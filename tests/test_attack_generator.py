"""
test_attack_generator.py — offline test of the LLM attack-path generator. Drives the REAL
AttackPathGenerator with a FAKE provider (canned attack_paths JSON — no network, no API
key). Asserts:
  - a reachable chain is merged into the config and passes the reachability gate
  - the validate->retry loop re-prompts with the failing reason on an unreachable chain
    and eventually succeeds, and raises AttackGenerationError when it can't
  - JSON extraction tolerates ```json fences and an {attack_paths: ...} envelope

Runs two ways:
    python tests/test_attack_generator.py
    pytest tests/test_attack_generator.py
"""
import os
import sys
import json

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.entity_generator import EntityGenerator  # noqa: E402
from src.attack_generator import AttackPathGenerator, AttackGenerationError  # noqa: E402

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _gen():
    return EntityGenerator(data_dir=os.path.join(_REPO, "entity_data"))


class _FakeProvider:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def generate(self, system, user):
        self.calls.append({"system": system, "user": user})
        return self.responses.pop(0)


_BASE = {"tenant": {"tenant_id": None, "domain": None, "subscription_id": None}}

# A known-reachable chain (the docs/attack-paths/chained.md worked example):
# victim holds Key Vault Contributor -> loots the planted secret -> becomes billing-app,
# which holds Global Administrator.
_GOOD = {
    "kv_to_ga": {
        "objective": {"name": "GA via Key Vault", "capability": "entra_role",
                      "role": "Global Administrator", "impact": "critical",
                      "description": "A help-desk user reads a planted secret and becomes a GA app."},
        "initial_access": {"method": "compromised_identity", "principal_ref": "victim"},
        "identities": {"users": [{"ref": "victim"}], "applications": [{"ref": "billing-app"}]},
        "resources": {"key_vaults": [{"ref": "kvtest01"}]},
        "assignments": [
            {"id": "a1", "type": "azure_rbac", "principal_ref": "victim",
             "role": "Key Vault Contributor", "scope_ref": "kvtest01"},
            {"id": "a2", "type": "entra_role", "principal_ref": "billing-app",
             "role": "Global Administrator"},
        ],
        "credentials": [{"ref": "app_secret", "app_ref": "billing-app", "type": "password"}],
        "data_injects": [{"id": "d1", "material": "app_secret", "credential_ref": "app_secret",
                          "location": "key_vault_secret", "location_ref": "kvtest01",
                          "name": "client-secret-billing-app"}],
    }
}

# Same objective but the loot is missing, so nothing controls billing-app -> UNREACHABLE.
_BLOCKED = {
    "kv_to_ga": {
        "objective": {"name": "GA via Key Vault", "capability": "entra_role",
                      "role": "Global Administrator", "impact": "critical"},
        "initial_access": {"method": "compromised_identity", "principal_ref": "victim"},
        "identities": {"users": [{"ref": "victim"}], "applications": [{"ref": "billing-app"}]},
        "resources": {"key_vaults": [{"ref": "kvtest01"}]},
        "assignments": [
            {"id": "a1", "type": "azure_rbac", "principal_ref": "victim",
             "role": "Key Vault Contributor", "scope_ref": "kvtest01"},
            {"id": "a2", "type": "entra_role", "principal_ref": "billing-app",
             "role": "Global Administrator"},
        ],
    }
}


def test_reachable_chain_merges_and_validates():
    p = _FakeProvider([json.dumps(_GOOD)])
    cfg = AttackPathGenerator(p, _gen()).generate_attack_paths(_BASE, "phish -> GA via KV")
    assert "kv_to_ga" in cfg["attack_paths"]
    assert cfg["attack_paths"]["kv_to_ga"]["objective"]["role"] == "Global Administrator"
    assert len(p.calls) == 1


def test_unreachable_then_repair():
    # First (blocked) response -> gate rejects -> retry with feedback -> good response.
    p = _FakeProvider([json.dumps(_BLOCKED), json.dumps(_GOOD)])
    cfg = AttackPathGenerator(p, _gen()).generate_attack_paths(_BASE, "phish -> GA via KV")
    assert "kv_to_ga" in cfg["attack_paths"]
    assert len(p.calls) == 2
    # The retry prompt carried the rejection reason back to the model.
    assert "REJECTED" in p.calls[1]["user"]


def test_exhausts_attempts_raises():
    p = _FakeProvider([json.dumps(_BLOCKED)] * 3)
    try:
        AttackPathGenerator(p, _gen(), max_attempts=3).generate_attack_paths(_BASE, "x")
        assert False, "expected AttackGenerationError"
    except AttackGenerationError as e:
        assert "not reachable" in str(e).lower() or "reachable" in str(e).lower()


def test_parse_tolerates_fence_and_envelope():
    fenced = "Here you go:\n```json\n" + json.dumps({"attack_paths": _GOOD}) + "\n```"
    p = _FakeProvider([fenced])
    cfg = AttackPathGenerator(p, _gen()).generate_attack_paths(_BASE, "x")
    assert "kv_to_ga" in cfg["attack_paths"]


def test_empty_response_retries_then_fails():
    p = _FakeProvider(["", "   ", "not json at all"])
    try:
        AttackPathGenerator(p, _gen(), max_attempts=3).generate_attack_paths(_BASE, "x")
        assert False, "expected AttackGenerationError"
    except AttackGenerationError:
        pass
    assert len(p.calls) == 3


if __name__ == "__main__":
    import logging
    logging.disable(logging.CRITICAL)
    failures = 0
    for fn in (test_reachable_chain_merges_and_validates, test_unreachable_then_repair,
               test_exhausts_attempts_raises, test_parse_tolerates_fence_and_envelope,
               test_empty_response_retries_then_fails):
        try:
            fn()
            print(f"PASS {fn.__name__}")
        except AssertionError as e:
            failures += 1
            print(f"FAIL {fn.__name__}: {e}")
    print(f"\n{'ALL PASSED' if failures == 0 else str(failures) + ' FAILED'}")
    sys.exit(1 if failures else 0)
