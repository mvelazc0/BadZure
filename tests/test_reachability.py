"""
test_reachability.py — offline test of the Phase-3 reachability gate (Slice 4).

Drives the real ScenarioLoader (no Azure) and asserts the gate's verdicts:
  - a 2-hop KV-secret-theft chain (loot a vault secret -> control a GA app) is
    REACHED, and the walk DERIVES ordered steps for it;
  - a 3-hop managed-identity chain (VM Contributor -> VM's MI reads a KV -> loot
    -> control a GA app) is REACHED;
  - breaking an edge (drop the RBAC hop) makes the objective unreachable and the
    loader REJECTS the config before it would ever deploy;
  - a `read_secrets` objective against a directly-reachable vault is REACHED;
  - the gate can be BYPASSED (env var) to deploy an unreachable chain anyway;
  - an objective with no machine-checkable `capability:` is UNVERIFIED (non-fatal);
  - authored `steps:` are preserved (we only derive when absent).

No live tenant: this exercises the graph walk + objective predicate only.

Runs two ways:
    python tests/test_reachability.py
    pytest tests/test_reachability.py
"""
import copy
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src import reachability  # noqa: E402
from src.entity_generator import EntityGenerator  # noqa: E402
from src.scenario_loader import ScenarioLoader  # noqa: E402

GA = "62e90394-69f5-4237-9190-012177145e10"  # Global Administrator
_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _loader():
    return ScenarioLoader(EntityGenerator(data_dir=os.path.join(_REPO, "entity_data")))


def _load(config, skip_gate=False):
    """Load a config; optionally bypass the hard gate so a BLOCKED verdict can be
    inspected without the loader raising."""
    if skip_gate:
        os.environ["BADZURE_SKIP_REACHABILITY"] = "1"
    try:
        return _loader().load(config, domain="contoso.com")
    finally:
        os.environ.pop("BADZURE_SKIP_REACHABILITY", None)


def _report(config):
    """Verdicts for every path, with the gate bypassed during load."""
    loader = _loader()
    os.environ["BADZURE_SKIP_REACHABILITY"] = "1"
    try:
        sm = loader.load(config, domain="contoso.com")
    finally:
        os.environ.pop("BADZURE_SKIP_REACHABILITY", None)
    return reachability.analyze(sm.model, sm.attack_paths, loader.resolver), sm


# ---------------------------------------------------------------------------
# Configs
# ---------------------------------------------------------------------------
# 2-hop: alice manages a vault -> loots a GA app's secret -> becomes GA.
_KV_TO_GA = {
    "schema": "graph",
    "attack_paths": {
        "kv_to_ga": {
            "objective": {"name": "GA via KV", "capability": "entra_role", "role": GA},
            "initial_access": {"method": "compromised_identity", "principal_ref": "alice"},
            "identities": {
                "users": [{"ref": "alice"}],
                "applications": [{"ref": "app_highpriv"}],
            },
            "resources": {"key_vaults": [{"ref": "kv01"}]},
            "assignments": [
                {"id": "a1", "type": "azure_rbac", "principal_ref": "alice",
                 "role": "Key Vault Contributor", "scope_ref": "kv01"},
                {"id": "a2", "type": "entra_role", "principal_ref": "app_highpriv",
                 "role": GA},
            ],
            "credentials": [
                {"ref": "app_secret", "app_ref": "app_highpriv", "type": "password"},
            ],
            "data_injects": [
                {"id": "d1", "material": "app_secret", "credential_ref": "app_secret",
                 "location": "key_vault_secret", "location_ref": "kv01", "name": "sp-secret"},
            ],
        }
    },
}

# 3-hop: alice runs the VM -> the VM's MI reads a vault -> loot -> become GA.
_MI_TO_GA = {
    "schema": "graph",
    "attack_paths": {
        "mi_to_ga": {
            "objective": {"name": "GA via MI", "capability": "entra_role", "role": GA},
            "initial_access": {"method": "phishing", "principal_ref": "alice"},
            "identities": {
                "users": [{"ref": "alice"}],
                "applications": [{"ref": "automation"}],
            },
            "resources": {
                "virtual_machines": [{"ref": "vm01"}],
                "key_vaults": [{"ref": "kv01"}],
            },
            "assignments": [
                {"id": "a1", "type": "azure_rbac", "principal_ref": "alice",
                 "role": "Virtual Machine Contributor", "scope_ref": "vm01"},
                {"id": "a2", "type": "azure_rbac", "principal_ref": "vm01",
                 "principal_type": "managed_identity", "mi_source": "vm",
                 "role": "Key Vault Secrets User", "scope_ref": "kv01"},
                {"id": "a3", "type": "entra_role", "principal_ref": "automation",
                 "role": GA},
            ],
            "credentials": [
                {"ref": "automation_secret", "app_ref": "automation", "type": "password"},
            ],
            "data_injects": [
                {"id": "d1", "material": "app_secret", "credential_ref": "automation_secret",
                 "location": "key_vault_secret", "location_ref": "kv01", "name": "prod-sp"},
            ],
        }
    },
}


# cert-loot: alice reads a storage blob holding a GA app's certificate. The loot
# only confers control of the app if a `type: certificate` credential is REGISTERED
# on it (the pair that emits azuread_application_certificate). Dummy file paths keep
# the test hermetic — reachability never reads them (only build_tfvars would).
_CERT_TO_GA = {
    "schema": "graph",
    "attack_paths": {
        "cert_to_ga": {
            "objective": {"name": "GA via cert", "capability": "entra_role", "role": GA},
            "initial_access": {"method": "compromised_identity", "principal_ref": "alice"},
            "identities": {
                "users": [{"ref": "alice"}],
                "applications": [{"ref": "app_highpriv"}],
            },
            "resources": {"storage_accounts": [{"ref": "st01"}]},
            "assignments": [
                {"id": "a1", "type": "azure_rbac", "principal_ref": "alice",
                 "role": "Storage Blob Data Reader", "scope_ref": "st01"},
                {"id": "a2", "type": "entra_role", "principal_ref": "app_highpriv",
                 "role": GA},
            ],
            "credentials": [
                {"ref": "app_cert", "app_ref": "app_highpriv", "type": "certificate",
                 "certificate_path": "terraform/dummy.pfx"},
            ],
            "data_injects": [
                {"id": "d1", "material": "app_certificate", "source_ref": "app_highpriv",
                 "location": "storage_blob", "location_ref": "st01",
                 "name": "app.pfx", "file_path": "terraform/dummy.pfx"},
            ],
        }
    },
}


def _status(config, path_name):
    report, _ = _report(config)
    return next(v for v in report.verdicts if v.name == path_name)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------
def test_two_hop_chain_reached_and_steps_derived():
    sm = _load(_KV_TO_GA)                       # does NOT raise -> objective reachable
    v = _status(_KV_TO_GA, "kv_to_ga")
    assert v.status == reachability.REACHED, v.reason
    assert v.terminal_node == "app_highpriv"
    overlay = sm.attack_paths[0]
    assert overlay.steps, "steps should be derived when none are authored"
    assert overlay.steps[0]["source_ref"] == "alice"           # initial access
    assert any(s.get("action") == "credential_loot" for s in overlay.steps)
    assert overlay.steps[-1]["gains"] == [GA]                  # final objective hop
    print("ok: 2-hop chain reached + steps derived")


def test_three_hop_managed_identity_reached():
    _load(_MI_TO_GA)                            # does not raise
    v = _status(_MI_TO_GA, "mi_to_ga")
    assert v.status == reachability.REACHED, v.reason
    assert v.terminal_node == "automation"
    # The VM-control hop and the loot hop must both appear.
    _, sm = _report(_MI_TO_GA)
    actions = [s.get("action") for s in sm.attack_paths[0].steps]
    assert "resource_control" in actions and "credential_loot" in actions, actions
    print("ok: 3-hop managed-identity chain reached")


def test_broken_chain_rejected():
    broken = copy.deepcopy(_MI_TO_GA)
    # Drop the VM-control hop: now alice can never reach the VM's MI -> the vault
    # -> the GA app. Objective becomes unreachable.
    broken["attack_paths"]["mi_to_ga"]["assignments"] = [
        a for a in broken["attack_paths"]["mi_to_ga"]["assignments"] if a["id"] != "a1"
    ]
    raised = False
    try:
        _load(broken)
    except reachability.ReachabilityError as e:
        raised = True
        assert "mi_to_ga" in str(e)
    assert raised, "loader must reject an unreachable objective"
    assert _status(broken, "mi_to_ga").status == reachability.BLOCKED
    print("ok: broken chain rejected by the gate")


def test_read_secrets_objective_reached():
    cfg = {
        "schema": "graph",
        "attack_paths": {
            "loot_kv": {
                "objective": {"name": "KV secrets", "capability": "read_secrets",
                              "target_ref": "kv01"},
                "initial_access": {"principal_ref": "alice"},
                "identities": {"users": [{"ref": "alice"}]},
                "resources": {"key_vaults": [{"ref": "kv01"}]},
                "assignments": [
                    {"id": "a1", "type": "azure_rbac", "principal_ref": "alice",
                     "role": "Key Vault Secrets User", "scope_ref": "kv01"},
                ],
            }
        },
    }
    _load(cfg)
    assert _status(cfg, "loot_kv").status == reachability.REACHED
    print("ok: read_secrets objective reached")


def test_bypass_deploys_unreachable_chain():
    broken = copy.deepcopy(_MI_TO_GA)
    broken["attack_paths"]["mi_to_ga"]["assignments"] = [
        a for a in broken["attack_paths"]["mi_to_ga"]["assignments"] if a["id"] != "a1"
    ]
    sm = _load(broken, skip_gate=True)          # bypass -> no raise
    assert sm.model is not None
    print("ok: bypass env var deploys an unreachable chain")


def test_objective_without_capability_is_unverified():
    cfg = {
        "schema": "graph",
        "attack_paths": {
            "vague": {
                "objective": {"name": "something bad"},   # no capability
                "initial_access": {"principal_ref": "alice"},
                "identities": {"users": [{"ref": "alice"}]},
                "assignments": [
                    {"id": "a1", "type": "entra_role", "principal_ref": "alice",
                     "role": GA},
                ],
            }
        },
    }
    _load(cfg)                                  # does not raise
    assert _status(cfg, "vague").status == reachability.UNVERIFIED
    print("ok: objective without capability is unverified (non-fatal)")


def test_certificate_loot_reached_when_credential_registered():
    _load(_CERT_TO_GA)                          # does not raise -> objective reachable
    v = _status(_CERT_TO_GA, "cert_to_ga")
    assert v.status == reachability.REACHED, v.reason
    assert v.terminal_node == "app_highpriv"
    print("ok: cert loot reached when the credential is registered")


def test_certificate_loot_blocked_without_registered_credential():
    # Drop the paired certificate credential: the planted .pfx now registers on no app
    # (no azuread_application_certificate), so looting it authenticates as nothing and
    # the hop is not traversable. This is exactly the generated.yml bug — the gate must
    # report the path unreachable instead of deploying a silently-broken cert-auth hop.
    broken = copy.deepcopy(_CERT_TO_GA)
    broken["attack_paths"]["cert_to_ga"]["credentials"] = []
    raised = False
    try:
        _load(broken)
    except reachability.ReachabilityError as e:
        raised = True
        assert "cert_to_ga" in str(e)
    assert raised, "loader must reject a cert loot with no registered credential"
    assert _status(broken, "cert_to_ga").status == reachability.BLOCKED
    print("ok: cert loot blocked when no credential registers the cert")


def test_blocked_verdict_carries_diagnostics():
    # A BLOCKED path must explain WHY, so the operator / self-repair loop can fix it
    # without re-deriving the walk: the frontier the attacker actually reached, and the
    # orphaned planted credential that loots to nothing.
    broken = copy.deepcopy(_CERT_TO_GA)
    broken["attack_paths"]["cert_to_ga"]["credentials"] = []
    v = _status(broken, "cert_to_ga")
    assert v.status == reachability.BLOCKED
    diag = v.diagnostics or {}
    assert diag.get("reached") == ["alice"], "frontier should be the seed alone"
    dead_ends = diag.get("dead_ends") or []
    assert any("app_highpriv" in d and "no certificate is registered" in d
               for d in dead_ends), dead_ends
    print("ok: blocked verdict carries dead-end diagnostics")


def test_blocked_verdict_reports_uncontrolled_edge_toward_target():
    # control_principal objective whose target is owned by an app that is never
    # controlled -> the blocked-edge diagnostic should name that ownership hop.
    cfg = copy.deepcopy(_CERT_TO_GA)
    path = cfg["attack_paths"]["cert_to_ga"]
    path["objective"] = {"name": "own the app", "capability": "control_principal",
                         "target_ref": "app_victim"}
    path["identities"]["applications"].append({"ref": "app_victim"})
    path["assignments"].append(
        {"id": "a3", "type": "app_ownership",
         "principal_ref": "app_highpriv", "app_ref": "app_victim"})
    path["credentials"] = []  # orphan the cert -> app_highpriv never controlled
    v = _status(cfg, "cert_to_ga")
    assert v.status == reachability.BLOCKED
    blocked = (v.diagnostics or {}).get("blocked_edges") or []
    assert any("app_highpriv" in b and "app_victim" in b for b in blocked), blocked
    print("ok: blocked verdict reports uncontrolled edge toward target")


def test_reached_verdict_has_no_diagnostics():
    v = _status(_KV_TO_GA, "kv_to_ga")
    assert v.status == reachability.REACHED
    assert v.diagnostics is None, "diagnostics are only computed for blocked paths"
    print("ok: reached verdict carries no diagnostics")


def test_authored_steps_preserved():
    cfg = copy.deepcopy(_KV_TO_GA)
    cfg["attack_paths"]["kv_to_ga"]["steps"] = [
        {"name": "hand-written", "source_ref": "alice", "action": "phishing"},
    ]
    sm = _load(cfg)
    assert sm.attack_paths[0].steps == [
        {"name": "hand-written", "source_ref": "alice", "action": "phishing"},
    ], "authored steps must not be overwritten by derived ones"
    print("ok: authored steps preserved")


def _run_all():
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for t in tests:
        t()
    print(f"\nAll {len(tests)} reachability tests passed.")


if __name__ == "__main__":
    _run_all()
