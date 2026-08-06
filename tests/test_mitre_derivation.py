"""
test_mitre_derivation.py — the reachability walk derives MITRE ATT&CK IDs from the
traversal itself, so every atomic technique and every chained path is mapped without
an author writing `mitre:` by hand.

Asserts:
  - the per-primitive / per-vector mapping in reachability is stable (a change to an
    ID is a deliberate edit, caught here);
  - every technique in VALID_TECHNIQUES yields at least one ATT&CK ID on its steps;
  - ManagedIdentityAbuse surfaces T1528 (steal the compute host's MI token) while a
    direct KeyVault theft does not;
  - author-supplied `mitre:` augments (unions with) the derived IDs rather than
    replacing them.

No live tenant: this exercises the offline step derivation only.

Runs two ways:
    python tests/test_mitre_derivation.py
    pytest tests/test_mitre_derivation.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src import reachability  # noqa: E402
from src.constants import VALID_TECHNIQUES  # noqa: E402
from src.entity_generator import EntityGenerator  # noqa: E402
from src.primitives import (  # noqa: E402
    AppOwnership, EntraRoleAssignment, GroupOwnership, GroupMembership,
    AzureRbacAssignment, DataInject,
)
from src.scenario_loader import ScenarioLoader  # noqa: E402

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# One committed atomic example per technique.
_TECHNIQUE_EXAMPLE = {
    "ApplicationOwnershipAbuse": "atomic_app_ownership_user_role.yml",
    "ApplicationAdministratorAbuse": "atomic_app_admin_user_role.yml",
    "CloudAppAdministratorAbuse": "atomic_cloud_app_admin_user.yml",
    "ManagedIdentityAbuse": "atomic_mi_abuse_vm_user.yml",
    "KeyVaultSecretTheft": "atomic_kv_theft_user.yml",
    "StorageCertificateTheft": "atomic_storage_theft_user.yml",
    "CosmosDBSecretTheft": "atomic_cosmos_theft_user.yml",
}


def _loader():
    return ScenarioLoader(EntityGenerator(data_dir=os.path.join(_REPO, "entity_data")))


def _ids_for(example_file):
    import yaml
    path = os.path.join(_REPO, "examples", "atomic", example_file)
    with open(path) as fh:
        config = yaml.safe_load(fh)
    loader = _loader()
    os.environ["BADZURE_SKIP_REACHABILITY"] = "1"
    try:
        sm = loader.load(config, domain="contoso.com")
    finally:
        os.environ.pop("BADZURE_SKIP_REACHABILITY", None)
    ids = []
    for overlay in sm.attack_paths:
        for step in overlay.steps or []:
            for mid in step.get("mitre") or []:
                if mid not in ids:
                    ids.append(mid)
    return ids


def test_hop_mapping_is_stable():
    class _P:  # minimal stand-ins carrying only the fields the mapping reads
        pass

    def rbac(scope_resource_type):
        p = AzureRbacAssignment.__new__(AzureRbacAssignment)
        p.scope_resource_type = scope_resource_type
        p.mi_source_type = None
        return p

    def inject(location_type):
        p = DataInject.__new__(DataInject)
        p.location_type = location_type
        return p

    def own(cls):
        return cls.__new__(cls)

    assert reachability._mitre_for_hop(own(AppOwnership)) == ["T1098.001"]
    assert reachability._mitre_for_hop(own(EntraRoleAssignment)) == ["T1098.001"]
    assert reachability._mitre_for_hop(own(GroupOwnership)) == ["T1098.003"]
    assert reachability._mitre_for_hop(own(GroupMembership)) == ["T1098.003"]
    assert reachability._mitre_for_hop(rbac("key_vault")) == ["T1078.004"]
    assert reachability._mitre_for_hop(rbac("virtual_machine")) == ["T1078.004", "T1528"]
    assert reachability._mitre_for_hop(rbac("function_app")) == ["T1078.004", "T1528"]
    assert reachability._mitre_for_hop(inject("key_vault_secret")) == ["T1555.006"]
    assert reachability._mitre_for_hop(inject("key_vault_certificate")) == ["T1555.006"]
    assert reachability._mitre_for_hop(inject("storage_blob")) == ["T1552.001"]
    assert reachability._mitre_for_hop(inject("cosmos_document")) == ["T1552"]
    print("ok: per-hop ATT&CK mapping stable")


def test_initial_access_mapping_is_stable():
    m = reachability._INITIAL_ACCESS_MITRE
    assert m["compromised_identity"] == ["T1078.004"]
    assert m["compromised_credential"] == ["T1078.004"]
    assert m["exposed_rdp"] == ["T1133", "T1110.001"]
    assert m["exposed_ssh"] == ["T1133", "T1110.001"]
    assert m["vulnerable_web_app"] == ["T1190"]
    print("ok: initial-access ATT&CK mapping stable")


def test_every_technique_yields_ids():
    for technique in VALID_TECHNIQUES:
        example = _TECHNIQUE_EXAMPLE[technique]
        ids = _ids_for(example)
        assert ids, f"{technique} derived no ATT&CK IDs"
        assert "T1078.004" in ids, f"{technique} missing the valid-account entry ID"
    print(f"ok: all {len(VALID_TECHNIQUES)} techniques map to ATT&CK IDs")


def test_managed_identity_abuse_surfaces_token_theft():
    mi = _ids_for(_TECHNIQUE_EXAMPLE["ManagedIdentityAbuse"])
    kv = _ids_for(_TECHNIQUE_EXAMPLE["KeyVaultSecretTheft"])
    assert "T1528" in mi, "MI abuse should surface Steal Application Access Token"
    assert "T1528" not in kv, "direct KV theft controls no compute host, so no T1528"
    print("ok: T1528 fires for MI abuse, not for direct KV theft")


def test_merge_unions_author_and_derived():
    assert reachability._merge_mitre(["T1078.004"], "T1078.004") == ["T1078.004"]
    assert reachability._merge_mitre(["T1133"], ["T1110.001"]) == ["T1133", "T1110.001"]
    assert reachability._merge_mitre(None, None) is None
    assert reachability._merge_mitre([], "") is None
    print("ok: _merge_mitre unions and de-dupes, empty -> None")


def _run_all():
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for t in tests:
        t()
    print(f"\nAll {len(tests)} MITRE-derivation tests passed.")


if __name__ == "__main__":
    _run_all()
