"""
test_initial_access_vectors.py — offline tests for the exposed-host initial-access
foothold (slice 1: exposed_rdp / exposed_ssh).

An InitialAccessVector lands the attacker on a compute resource (code execution on
the host) instead of seeding the walk with a compromised identity. It is NOT a
generic.tf family: the builder projects it onto the target VM spec (an
`expose_to_internet` flag + optional weak admin password the existing NSG reads) and
exposes the VM ref via foothold_vm_refs. Both authoring tiers reach it:

  - ATOMIC: `initial_access: exposed_rdp` on a ManagedIdentityAbuse path. The foothold
    VM is the managed-identity source; the existing MI chain continues from it.
  - CHAINED: an `initial_access: { vector: exposed_rdp, target_ref: vm }` block on a
    hand-authored graph, seeding the walk at the host.

Drives the real ScenarioLoader / TerraformBuilder / reachability gate (no Azure).

Runs two ways:
    python tests/test_initial_access_vectors.py
    pytest tests/test_initial_access_vectors.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest  # noqa: E402

from src.entity_generator import EntityGenerator  # noqa: E402
from src.scenario_loader import ScenarioLoader, ScenarioConfigError  # noqa: E402
from src.terraform_builder import build_tfvars, TerraformBuilder, LabValidationError  # noqa: E402
from src.primitives import (  # noqa: E402
    DeploymentModel, InitialAccessVector, AzureRbacAssignment, ATTACK_PATH,
)
from src.constants import WEAK_FOOTHOLD_PASSWORD  # noqa: E402
from src import reachability, scenario_validator  # noqa: E402
from src.scenario_loader import ScenarioConfigError as _Cfg  # noqa: E402

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _loader():
    return ScenarioLoader(EntityGenerator(data_dir=os.path.join(_REPO, "entity_data")))


def _load(config):
    return _loader().load(config, domain="contoso.com")


_BASELINE = {
    "identities": {"users": 4, "groups": 1, "applications": 4},
    "resources": {"key_vaults": 1, "virtual_machines": 1},
}


def _atomic_config(**knobs):
    path = {
        "privilege_escalation": "ManagedIdentityAbuse",
        "initial_access": "exposed_rdp",
        "source_type": "vm",
        "target_resource_type": "key_vault",
        "method": "APIPermission",
        "api_type": "graph",
        "app_role": "06b708a9-e830-4db3-a914-8e69da51d44f",
    }
    path.update(knobs)
    return {"baseline": _BASELINE, "attack_paths": {"p": path}}


# ---------------------------------------------------------------------------
# ATOMIC: exposed_rdp -> ManagedIdentityAbuse
# ---------------------------------------------------------------------------
def test_atomic_foothold_compiles_and_reaches():
    scenario = _load(_atomic_config())
    ov = scenario.attack_paths[0]
    prims = scenario.model.primitives

    iav = [p for p in prims if isinstance(p, InitialAccessVector)]
    assert len(iav) == 1
    vec = iav[0]
    assert vec.method == "exposed_rdp"
    assert vec.target_type == "virtual_machine"
    assert vec.grants == "code_execution"

    # The reachability seed is the foothold VM (not a compromised identity), and the
    # path reaches its objective through the VM's managed identity.
    assert ov.initial_access.get("principal_ref") == vec.target_ref
    assert ov.initial_access.get("method") == "exposed_rdp"
    assert ov.reachability["status"] == reachability.REACHED

    # No compromised user/SP credential, and no source-Contributor RBAC grant — the
    # foothold IS host control, so those steps are skipped.
    creds = ov.credentials
    assert creds.get("initial_access") == "exposed_rdp"
    assert creds.get("foothold_resource") == vec.target_ref
    assert "user_principal_name" not in creds and "service_principal_name" not in creds
    assert not any(isinstance(p, AzureRbacAssignment) and p.key.endswith("_src_contrib")
                   for p in prims)


def test_atomic_foothold_builds_and_projects_vm_flags():
    scenario = _load(_atomic_config(expose_to_internet=True, credential="weak"))
    out = build_tfvars(scenario.model)
    vm_ref = [p for p in scenario.model.primitives
              if isinstance(p, InitialAccessVector)][0].target_ref

    assert out["foothold_vm_refs"] == [vm_ref]
    assert out["virtual_machines"][vm_ref]["expose_to_internet"] is True
    assert out["virtual_machines"][vm_ref]["admin_password"] == WEAK_FOOTHOLD_PASSWORD
    # Foothold VMs are the only VMs given a public IP (operator reaches them via RDP/SSH).
    assert out["virtual_machines"][vm_ref]["assign_public_ip"] is True

    # The InitialAccessVector is NOT emitted as a generic.tf family.
    assert not any("initial_access" in fam for fam in out)


def test_atomic_foothold_os_matches_vector():
    # RDP implies Windows, SSH implies Linux. Baseline VMs are always generated Linux,
    # so the builder must coerce the foothold host's OS to match the open port.
    for vector, expect_os in (("exposed_rdp", "Windows"), ("exposed_ssh", "Linux")):
        scenario = _load(_atomic_config(initial_access=vector))
        out = build_tfvars(scenario.model)
        vm_ref = out["foothold_vm_refs"][0]
        assert out["virtual_machines"][vm_ref]["os_type"] == expect_os, vector


def test_two_mi_paths_pick_distinct_sources():
    # Two random ManagedIdentityAbuse paths must take DIFFERENT source VMs — sharing
    # one grants the same MI the same roles on the same target -> identical Azure role
    # assignments -> 409 on apply. With enough VMs the loader always separates them.
    cfg = {
        "baseline": {"identities": {"users": 3, "applications": 4},
                     "resources": {"key_vaults": 1, "virtual_machines": 5}},
        "attack_paths": {
            "rdp": {"privilege_escalation": "ManagedIdentityAbuse",
                    "initial_access": "exposed_rdp", "source_type": "vm",
                    "target_resource_type": "key_vault", "method": "APIPermission",
                    "api_type": "graph", "app_role": "06b708a9-e830-4db3-a914-8e69da51d44f"},
            "ssh": {"privilege_escalation": "ManagedIdentityAbuse",
                    "initial_access": "exposed_ssh", "source_type": "vm",
                    "target_resource_type": "key_vault", "method": "APIPermission",
                    "api_type": "graph", "app_role": "06b708a9-e830-4db3-a914-8e69da51d44f"},
        },
    }
    for _ in range(10):  # selection is random; assert it never collides
        scenario = _load(cfg)
        sources = [ov.summary.get("source_name") for ov in scenario.attack_paths]
        assert len(set(sources)) == len(sources), sources
        build_tfvars(scenario.model)  # builds without duplicate-key errors


def test_mi_paths_exhausting_sources_fails_clearly():
    # More MI paths than baseline source VMs -> a clear loader error, not a mid-apply 409.
    cfg = {
        "baseline": {"identities": {"users": 3, "applications": 4},
                     "resources": {"key_vaults": 1, "virtual_machines": 1}},
        "attack_paths": {
            "p1": {"privilege_escalation": "ManagedIdentityAbuse", "source_type": "vm",
                   "target_resource_type": "key_vault", "method": "APIPermission",
                   "api_type": "graph", "app_role": "06b708a9-e830-4db3-a914-8e69da51d44f"},
            "p2": {"privilege_escalation": "ManagedIdentityAbuse", "source_type": "vm",
                   "target_resource_type": "key_vault", "method": "APIPermission",
                   "api_type": "graph", "app_role": "06b708a9-e830-4db3-a914-8e69da51d44f"},
        },
    }
    with pytest.raises(ScenarioConfigError, match="not enough distinct 'vm'"):
        _load(cfg)


def test_atomic_foothold_defaults_are_safe():
    # Default knobs: NSG stays operator-IP (expose_to_internet false) and the strong
    # generated password is kept (credential known).
    scenario = _load(_atomic_config())
    out = build_tfvars(scenario.model)
    vm_ref = out["foothold_vm_refs"][0]
    vm = out["virtual_machines"][vm_ref]
    assert vm["expose_to_internet"] is False
    assert vm["admin_password"] != WEAK_FOOTHOLD_PASSWORD


def test_baseline_vm_gets_no_public_ip():
    # A VM that is NOT an exposed-host foothold (pure baseline noise) must not be
    # flagged assign_public_ip — baseline VMs stay private (no public IP allocated).
    cfg = {
        "baseline": {"identities": {"users": 2, "applications": 2},
                     "resources": {"key_vaults": 1, "virtual_machines": 2}},
        "attack_paths": {
            "p": {"privilege_escalation": "ManagedIdentityAbuse",
                  "initial_access": "exposed_rdp", "source_type": "vm",
                  "target_resource_type": "key_vault", "method": "APIPermission",
                  "api_type": "graph",
                  "app_role": "06b708a9-e830-4db3-a914-8e69da51d44f"},
        },
    }
    scenario = _load(cfg)
    out = build_tfvars(scenario.model)
    foothold = set(out["foothold_vm_refs"])
    assert foothold, "expected one exposed-host foothold VM"
    for vm_ref, vm in out["virtual_machines"].items():
        if vm_ref in foothold:
            assert vm["assign_public_ip"] is True, vm_ref
        else:
            # baseline VM: no public IP (flag absent -> TF optional default false)
            assert vm.get("assign_public_ip", False) is False, vm_ref


# ---------------------------------------------------------------------------
# CHAINED: initial_access vector block
# ---------------------------------------------------------------------------
def _chained_config(**ia):
    block = {"vector": "exposed_rdp", "target_ref": "vm_foothold"}
    block.update(ia)
    return {
        "attack_paths": {
            "chain": {
                "objective": {"capability": "read_secrets", "target_ref": "kv1",
                              "name": "KV via foothold"},
                "initial_access": block,
                "identities": {"applications": [{"ref": "app_hp"}]},
                "resources": {
                    "virtual_machines": [{"ref": "vm_foothold", "os_type": "Windows"}],
                    "key_vaults": [{"ref": "kv1"}],
                },
                "assignments": [
                    {"id": "a1", "type": "azure_rbac", "principal_ref": "vm_foothold",
                     "principal_type": "managed_identity", "mi_source_type": "vm",
                     "role": "Key Vault Secrets User", "scope_ref": "kv1"},
                ],
                "credentials": [{"ref": "c", "app_ref": "app_hp", "type": "password"}],
                "data_injects": [
                    {"id": "d1", "material": "app_secret", "credential_ref": "c",
                     "location": "key_vault_secret", "location_ref": "kv1", "name": "s"},
                ],
            }
        }
    }


def test_chained_foothold_compiles_and_reaches():
    scenario = _load(_chained_config(credential="weak"))
    ov = scenario.attack_paths[0]
    iav = [p for p in scenario.model.primitives if isinstance(p, InitialAccessVector)]
    assert len(iav) == 1 and iav[0].target_ref == "vm_foothold"
    # Seed normalized to the host so the walk starts there.
    assert ov.initial_access.get("principal_ref") == "vm_foothold"
    assert ov.reachability["status"] == reachability.REACHED

    out = build_tfvars(scenario.model)
    assert out["foothold_vm_refs"] == ["vm_foothold"]
    assert out["virtual_machines"]["vm_foothold"]["admin_password"] == WEAK_FOOTHOLD_PASSWORD


# ---------------------------------------------------------------------------
# Builder: InitialAccessVector ref-validation + skip
# ---------------------------------------------------------------------------
def _model_with_vector(target_ref="vm1", target_type="virtual_machine", method="exposed_rdp"):
    m = DeploymentModel(virtual_machines={"vm1": {"name": "vm1", "os_type": "Linux",
                                                  "admin_username": "u", "admin_password": "p"}})
    m.primitives.append(InitialAccessVector(
        "v", ATTACK_PATH, method=method, target_ref=target_ref,
        target_type=target_type, grants="code_execution"))
    return m


def test_builder_rejects_unknown_vm_ref():
    with pytest.raises(LabValidationError):
        build_tfvars(_model_with_vector(target_ref="nope"))


def test_builder_rejects_non_vm_target_type():
    with pytest.raises(LabValidationError):
        build_tfvars(_model_with_vector(target_type="storage_account"))


def test_builder_rejects_unimplemented_method():
    with pytest.raises(LabValidationError):
        build_tfvars(_model_with_vector(method="vulnerable_web_app"))


# ---------------------------------------------------------------------------
# Validator: foothold rejection paths
# ---------------------------------------------------------------------------
def test_validator_rejects_foothold_on_non_mi_technique():
    cfg = {"baseline": _BASELINE,
           "attack_paths": {"p": {"privilege_escalation": "KeyVaultSecretTheft",
                                  "initial_access": "exposed_rdp"}}}
    with pytest.raises(_Cfg, match="only supported with ManagedIdentityAbuse"):
        scenario_validator.validate(cfg)


def test_validator_rejects_foothold_with_non_vm_source():
    with pytest.raises(_Cfg, match="requires source_type 'vm'"):
        scenario_validator.validate(_atomic_config(source_type="logic_app"))


def test_validator_rejects_chained_vector_without_target():
    cfg = _chained_config()
    cfg["attack_paths"]["chain"]["initial_access"] = {"vector": "exposed_rdp"}
    with pytest.raises(_Cfg, match="needs a `target_ref`"):
        scenario_validator.validate(cfg)


def test_validator_rejects_unknown_vector():
    cfg = _chained_config(vector="exposed_telnet")
    with pytest.raises(_Cfg, match="vector 'exposed_telnet' is invalid"):
        scenario_validator.validate(cfg)


def test_validator_accepts_valid_atomic_foothold():
    scenario_validator.validate(_atomic_config())  # no raise


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-q"]))
