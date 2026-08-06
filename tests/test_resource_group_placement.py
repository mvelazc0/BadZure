"""
test_resource_group_placement.py — offline tests for flexible resource-group
placement of declarative (chained) resources.

Behavior under test (no Azure):
  - Resources declare their parent RGs under `resources.resource_groups`.
  - A resource may pin a `resource_group:` (must reference a declared RG).
  - A resource that OMITS `resource_group:` is distributed RANDOMLY across the
    declared RG pool (no `badzure-default-rg` is created when RGs are declared).
  - When NO RGs are declared at all, a single `badzure-default-rg` is synthesized
    as the fallback parent (backward compatible).
  - Pinning a `resource_group:` that isn't declared fails with a clear error.

Runs two ways:
    python tests/test_resource_group_placement.py
    pytest tests/test_resource_group_placement.py
"""
import os
import random
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest  # noqa: E402

from src.entity_generator import EntityGenerator  # noqa: E402
from src.scenario_loader import (  # noqa: E402
    ScenarioLoader, ScenarioConfigError, _DEFAULT_RG,
)
from src.terraform_builder import build_tfvars  # noqa: E402

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _loader():
    return ScenarioLoader(EntityGenerator(data_dir=os.path.join(_REPO, "entity_data")))


def _load(config):
    return _loader().load(config, domain="contoso.com")


def _base_path(resources):
    """A minimal single-path graph config whose objective is just to reach the KV
    (so the reachability gate stays trivially satisfiable)."""
    return {
        "schema": "graph",
        "attack_paths": {
            "p1": {
                "objective": {"name": "GA via key vault", "capability": "entra_role",
                              "role": "Global Administrator", "impact": "critical"},
                "initial_access": {"method": "compromised_identity",
                                   "principal_ref": "alice"},
                "identities": {"users": [{"ref": "alice"}],
                               "applications": [{"ref": "app1"}]},
                "resources": resources,
                "assignments": [
                    {"id": "a1", "type": "azure_rbac", "principal_ref": "alice",
                     "role": "Key Vault Contributor", "scope_ref": "kv1"},
                    {"id": "a2", "type": "entra_role", "principal_ref": "app1",
                     "role": "Global Administrator"},
                ],
                "credentials": [
                    {"ref": "s1", "app_ref": "app1", "type": "password"},
                ],
                "data_injects": [
                    {"id": "d1", "material": "app_secret", "credential_ref": "s1",
                     "location": "key_vault_secret", "location_ref": "kv1",
                     "name": "client-secret"},
                ],
            }
        },
    }


def test_pinned_resource_group_is_honored():
    cfg = _base_path({
        "resource_groups": [{"ref": "rg-a", "location": "West US"},
                            {"ref": "rg-b", "location": "East US"}],
        "key_vaults": [{"ref": "kv1", "resource_group": "rg-b"}],
    })
    m = _load(cfg).model
    assert m.key_vaults["kv1"]["resource_group_name"] == "rg-b"
    # the KV inherits the pinned RG's location
    assert m.key_vaults["kv1"]["location"] == "East US"
    # no default RG synthesized when RGs are declared
    assert _DEFAULT_RG not in m.resource_groups


def test_omitted_resource_group_is_distributed_across_declared_pool():
    cfg = _base_path({
        "resource_groups": [{"ref": "rg-a", "location": "West US"},
                            {"ref": "rg-b", "location": "East US"}],
        "key_vaults": [{"ref": "kv1"}],  # no resource_group -> random pick
    })
    m = _load(cfg).model
    assert m.key_vaults["kv1"]["resource_group_name"] in {"rg-a", "rg-b"}
    # never the synthesized default when real RGs exist
    assert m.key_vaults["kv1"]["resource_group_name"] != _DEFAULT_RG
    assert _DEFAULT_RG not in m.resource_groups


def test_distribution_uses_both_declared_groups():
    """With many unparented resources and a fixed seed, both declared RGs get used."""
    random.seed(1234)
    storage = [{"ref": f"st{i:02d}"} for i in range(12)]
    cfg = _base_path({
        "resource_groups": [{"ref": "rg-a", "location": "West US"},
                            {"ref": "rg-b", "location": "East US"}],
        "key_vaults": [{"ref": "kv1"}],
        "storage_accounts": storage,
    })
    m = _load(cfg).model
    used = {sa["resource_group_name"] for sa in m.storage_accounts.values()}
    assert used == {"rg-a", "rg-b"}, f"expected both RGs used, got {used}"

    # the full pipeline emits valid tfvars: both RGs present and every resource
    # references a declared RG.
    out = build_tfvars(m)
    assert set(out["resource_groups"]) == {"rg-a", "rg-b"}
    for sa in out["storage_accounts"].values():
        assert sa["resource_group_name"] in out["resource_groups"]


def test_default_rg_synthesized_when_none_declared():
    cfg = _base_path({
        "key_vaults": [{"ref": "kv1"}],  # no RGs declared at all
    })
    m = _load(cfg).model
    assert _DEFAULT_RG in m.resource_groups
    assert m.key_vaults["kv1"]["resource_group_name"] == _DEFAULT_RG


def test_pinning_undeclared_resource_group_raises():
    cfg = _base_path({
        "resource_groups": [{"ref": "rg-a", "location": "West US"}],
        "key_vaults": [{"ref": "kv1", "resource_group": "rg-missing"}],
    })
    with pytest.raises(ScenarioConfigError) as exc:
        _load(cfg)
    assert "rg-missing" in str(exc.value)


if __name__ == "__main__":
    import subprocess
    raise SystemExit(subprocess.call(
        [sys.executable, "-m", "pytest", __file__, "-v"]))
