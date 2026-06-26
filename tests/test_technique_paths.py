"""
test_technique_paths.py — offline test of the Tier-1 `technique:` sugar in the
declarative loader (legacy-mode-retirement Stage 1).

A `technique:` path is the on-ramp authoring tier: instead of a hand-authored
assignment graph, the operator names a technique + a few knobs and the loader fires
the SAME macro library the legacy mode used, then synthesizes a first-class graph
overlay (objective + initial_access) so the path validates and renders identically
to an explicit one.

This drives the real ScenarioLoader (no Azure) and asserts, for each of the 7
techniques, that a small baseline + a `technique:` path:
  - compiles to origin=attack_path primitives,
  - gets a synthesized (capability, target) objective,
  - passes the reachability gate (status reached/unverified, never blocked),
  - and produces a valid terraform.tfvars.json via build_tfvars.

Plus: an inline-entity (targeted) path, a mixed technique+explicit config, the
technique/assignments XOR rule, and the baseline-first missing-entity error.

Runs two ways:
    python tests/test_technique_paths.py
    pytest tests/test_technique_paths.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.entity_generator import EntityGenerator  # noqa: E402
from src.scenario_loader import ScenarioLoader, ScenarioConfigError  # noqa: E402
from src.terraform_builder import build_tfvars  # noqa: E402
from src import reachability  # noqa: E402

GA_ROLE = "62e90394-69f5-4237-9190-012177145e10"  # Global Administrator
_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _loader():
    return ScenarioLoader(EntityGenerator(data_dir=os.path.join(_REPO, "entity_data")))


def _load(config):
    return _loader().load(config, domain="contoso.com")


# A baseline rich enough that every technique's mode=random pick has something to
# land on (users/apps/groups + one of each resource type the techniques target).
_FULL_BASELINE = {
    "identities": {"users": 8, "groups": 3, "applications": 6},
    "resources": {
        "key_vaults": 1, "storage_accounts": 1, "cosmos_dbs": 1,
        "virtual_machines": 1, "logic_apps": 1, "app_services": 1,
    },
}

# technique -> (knobs, expected synthesized objective capability)
_TECHNIQUE_CASES = {
    "ApplicationOwnershipAbuse": (
        {"method": "AzureADRole", "entra_role": GA_ROLE}, "control_principal"),
    "ApplicationAdministratorAbuse": (
        {"method": "APIPermission", "api_type": "graph", "app_role": "random"},
        "control_principal"),
    "CloudAppAdministratorAbuse": (
        {"method": "AzureADRole", "entra_role": GA_ROLE}, "control_principal"),
    "KeyVaultSecretTheft": (
        {"method": "AzureADRole", "entra_role": "random"}, "read_secrets"),
    "StorageCertificateTheft": (
        {"method": "APIPermission", "api_type": "graph", "app_role": "random"},
        "read_storage"),
    "CosmosDBSecretTheft": (
        {"method": "AzureADRole", "entra_role": "random"}, "read_cosmos"),
    "ManagedIdentityAbuse": (
        {"source_type": "vm", "target_resource_type": "key_vault",
         "method": "AzureADRole", "entra_role": "random"}, "read_secrets"),
}


def _technique_config(technique, knobs):
    return {
        "baseline": _FULL_BASELINE,
        "attack_paths": {"path1": {"privilege_escalation": technique, **knobs}},
    }


def test_each_technique_compiles_verifies_and_builds():
    for technique, (knobs, expected_cap) in _TECHNIQUE_CASES.items():
        scenario = _load(_technique_config(technique, knobs))
        assert len(scenario.attack_paths) == 1, technique
        ov = scenario.attack_paths[0]

        # A (capability, target) objective was synthesized from the macro summary.
        assert ov.objective.get("capability") == expected_cap, technique
        assert ov.objective.get("target_ref"), f"{technique}: objective has no target"

        # The path is a reachability citizen and is NOT a dead end.
        assert ov.reachability["status"] in (reachability.REACHED,
                                             reachability.UNVERIFIED), \
            f"{technique}: {ov.reachability}"

        # initial_access seed names a real principal (the macro's compromised identity).
        seed = ov.initial_access.get("principal_ref")
        assert seed, f"{technique}: no initial_access seed"

        # attack-path primitives were emitted, and the tfvars build cleanly.
        assert any(getattr(p, "origin", None) == "attack_path"
                   for p in scenario.model.primitives), technique
        out = build_tfvars(scenario.model)
        assert out, technique


def test_technique_paths_get_recon_access():
    # Recon parity with legacy: a service-principal initial-access path gets
    # Directory.Read.All (graph) + subscription Reader.
    scenario = _load(_technique_config(
        "KeyVaultSecretTheft",
        {"initial_access": "service_principal", "method": "AzureADRole",
         "entra_role": "random"}))
    prims = scenario.model.primitives
    has_reader = any(type(p).__name__ == "AzureRbacAssignment"
                     and p.role == "Reader" and p.scope_type == "subscription"
                     for p in prims)
    has_dir_read = any(type(p).__name__ == "ApiPermission"
                       and p.key.startswith("recon_") for p in prims)
    assert has_reader, "no subscription Reader recon grant"
    assert has_dir_read, "no Directory.Read.All recon grant"


def test_managed_identity_app_service_source():
    # App Service as the ManagedIdentityAbuse source: compromised identity gets
    # Website Contributor on the app, then pivots through its MI to a key_vault.
    config = {
        "baseline": {"identities": {"users": 4, "applications": 4}},
        "attack_paths": {
            "mi_app_service": {
                "privilege_escalation": "ManagedIdentityAbuse",
                "source_type": "app_service", "target_resource_type": "key_vault",
                "credential_type": "secret", "initial_access": "user",
                "method": "AzureADRole", "entra_role": "random",
                "identities": {"applications": [{"ref": "LootedApp"}],
                               "users": [{"ref": "VictimUser"}]},
                "resources": {
                    "resource_groups": [{"ref": "asrg"}],
                    "key_vaults": [{"ref": "askv01", "resource_group": "asrg"}],
                    "app_services": [{"ref": "ops-portal", "resource_group": "asrg"}],
                },
            }
        },
    }
    scenario = _load(config)
    assert "ops-portal" in scenario.model.app_services
    assert "askv01" in scenario.model.key_vaults
    ov = scenario.attack_paths[0]
    assert ov.objective["target_ref"] == "askv01"
    assert ov.reachability["status"] == reachability.REACHED
    # Website Contributor on the app + MI grants resolved via app_service source.
    out = build_tfvars(scenario.model)
    rbac = out["attack_path_azure_rbac_assignments"].values()
    assert any(r["role"] == "Website Contributor"
               and r["scope_resource_type"] == "app_service" for r in rbac)
    assert any(r["principal_type"] == "managed_identity"
               and r["mi_source_type"] == "app_service" for r in rbac)


def test_inline_entities_run_targeted():
    # Inline identities/resources -> the macro runs in targeted mode against the
    # named entities (the scenarios2 shape: MI logic_app -> key_vault, SP access).
    config = {
        "baseline": {"identities": {"users": 4, "applications": 4}},
        "attack_paths": {
            "mi_inline": {
                "privilege_escalation": "ManagedIdentityAbuse",
                "source_type": "logic_app", "target_resource_type": "key_vault",
                "credential_type": "secret", "initial_access": "service_principal",
                "method": "APIPermission", "api_type": "exchange",
                "app_role": "dc890d15-9560-4a4c-9b7f-a736ec74ec40",
                "identities": {"applications": [{"ref": "AdminExchange"},
                                                {"ref": "InitialApp"}]},
                "resources": {
                    "resource_groups": [{"ref": "m003rg"}],
                    "key_vaults": [{"ref": "superkvz0033", "resource_group": "m003rg"}],
                    "logic_apps": [{"ref": "test-lp", "resource_group": "m003rg"}],
                },
            }
        },
    }
    scenario = _load(config)
    # The named inline entities were built into the model maps.
    assert "superkvz0033" in scenario.model.key_vaults
    assert "test-lp" in scenario.model.logic_apps
    ov = scenario.attack_paths[0]
    assert ov.objective["target_ref"] == "superkvz0033"
    assert ov.reachability["status"] == reachability.REACHED
    build_tfvars(scenario.model)


def test_group_member_assignment_creates_attack_group():
    scenario = _load(_technique_config(
        "KeyVaultSecretTheft",
        {"assignment_type": "group_member", "method": "AzureADRole",
         "entra_role": "random"}))
    # The macro minted an attack group; it must land in the model groups map.
    ov = scenario.attack_paths[0]
    group_name = ov.summary.get("group_name")
    assert group_name and group_name in scenario.model.groups
    assert scenario.model.groups[group_name].get("is_attack_path_group") is True
    assert ov.reachability["status"] == reachability.REACHED


def test_multihop_steps_show_intermediate_pivot():
    # A read_* objective must trace to the READER principal so the intermediate hops
    # show up — not collapse to compromise+achieve. ManagedIdentityAbuse is a 3-hop
    # chain (compromise -> control source -> MI reads target).
    mi = _load(_technique_config(
        "ManagedIdentityAbuse",
        {"source_type": "vm", "target_resource_type": "key_vault",
         "method": "AzureADRole", "entra_role": "random"}))
    steps = mi.attack_paths[0].steps
    actions = [s.get("action") for s in steps]
    assert actions[0] == "compromised_identity"
    assert "resource_control" in actions, f"MI pivot hop missing: {actions}"
    assert actions[-1] == "read_secrets"

    # group_member must show the group-inheritance hop.
    gm = _load(_technique_config(
        "KeyVaultSecretTheft",
        {"assignment_type": "group_member", "method": "AzureADRole",
         "entra_role": "random"}))
    gm_actions = [s.get("action") for s in gm.attack_paths[0].steps]
    assert "group_membership_inheritance" in gm_actions, gm_actions

    # No double-arrow: a hop's name must not embed "->" (the formatter adds the arrow
    # from target_ref).
    for ov in (mi.attack_paths[0], gm.attack_paths[0]):
        for s in ov.steps:
            if s.get("target_ref"):
                assert "->" not in s["name"], f"double-arrow in step name: {s['name']}"


def test_mixed_technique_and_explicit_paths():
    # A Tier-1 technique path and a Tier-2 explicit path side by side (the
    # on-ramp-then-graduate story) compile together.
    config = {
        "baseline": {"identities": {"users": 6, "applications": 4},
                     "resources": {"key_vaults": 1}},
        "attack_paths": {
            "sugar": {"privilege_escalation": "KeyVaultSecretTheft", "method": "AzureADRole",
                      "entra_role": "random"},
            "explicit": {
                "objective": {"name": "GA via owned app", "impact": "critical",
                              "capability": "control_principal", "target_ref": "app_hp"},
                "initial_access": {"method": "compromised_identity",
                                   "principal_ref": "carol"},
                "identities": {"users": [{"ref": "carol"}],
                               "applications": [{"ref": "app_hp"}]},
                "assignments": [
                    {"id": "a1", "type": "app_ownership", "principal_ref": "carol",
                     "app_ref": "app_hp"},
                    {"id": "a2", "type": "entra_role", "principal_ref": "app_hp",
                     "role": GA_ROLE},
                ],
            },
        },
    }
    scenario = _load(config)
    assert {ov.name for ov in scenario.attack_paths} == {"sugar", "explicit"}
    for ov in scenario.attack_paths:
        assert ov.reachability["status"] in (reachability.REACHED,
                                             reachability.UNVERIFIED), ov.name
    build_tfvars(scenario.model)


def test_technique_xor_assignments_is_rejected():
    config = {
        "baseline": {"identities": {"users": 3, "applications": 2},
                     "resources": {"key_vaults": 1}},
        "attack_paths": {
            "bad": {
                "privilege_escalation": "KeyVaultSecretTheft",
                "assignments": [{"id": "a1", "type": "entra_role",
                                 "principal_ref": "x", "role": "random"}],
            }
        },
    }
    try:
        _load(config)
        assert False, "expected XOR error for technique + assignments"
    except ScenarioConfigError as e:
        assert "mutually exclusive" in str(e)


def test_unknown_technique_is_rejected():
    config = {
        "baseline": {"identities": {"users": 3, "applications": 2}},
        "attack_paths": {"bad": {"privilege_escalation": "NotARealTechnique"}},
    }
    try:
        _load(config)
        assert False, "expected error for unknown technique"
    except ScenarioConfigError as e:
        assert "unknown privilege_escalation" in str(e)


def test_missing_baseline_entity_errors_clearly():
    # mode=random KeyVaultSecretTheft with no key_vault in the baseline.
    config = {
        "baseline": {"identities": {"users": 3, "applications": 2}},
        "attack_paths": {"kv": {"privilege_escalation": "KeyVaultSecretTheft",
                                "method": "AzureADRole", "entra_role": "random"}},
    }
    try:
        _load(config)
        assert False, "expected baseline-first error for missing key_vault"
    except ScenarioConfigError as e:
        assert "key_vault" in str(e) and "baseline" in str(e)


def test_group_access_named_in_output():
    # A group-based path renders a dedicated "Group-Based Access" line naming the
    # group + the identity's relationship (member/owner).
    import logging
    from src.output_formatter import OutputFormatter

    scenario = _load(_technique_config(
        "KeyVaultSecretTheft",
        {"assignment_type": "group_owner", "method": "AzureADRole",
         "entra_role": "random"}))
    records = []
    handler = logging.Handler()
    handler.emit = lambda r: records.append(r.getMessage())
    logger = logging.getLogger()
    logger.addHandler(handler)
    prev_level = logger.level
    logger.setLevel(logging.INFO)
    try:
        OutputFormatter().format_declarative_paths(
            scenario.attack_paths,
            {ov.name: ov.credentials for ov in scenario.attack_paths}, "contoso.com")
    finally:
        logger.removeHandler(handler)
        logger.setLevel(prev_level)

    out = "\n".join(records)
    group_name = scenario.attack_paths[0].summary["group_name"]
    assert "Group-Based Access" in out
    assert group_name in out
    assert "OWNER" in out


def _render(scenario):
    """Capture the lines format_declarative_paths logs for a scenario."""
    import logging
    from src.output_formatter import OutputFormatter
    records = []
    handler = logging.Handler()
    handler.emit = lambda r: records.append(r.getMessage())
    logger = logging.getLogger()
    logger.addHandler(handler)
    prev = logger.level
    logger.setLevel(logging.INFO)
    try:
        OutputFormatter().format_declarative_paths(
            scenario.attack_paths,
            {ov.name: ov.credentials for ov in scenario.attack_paths}, "contoso.com")
    finally:
        logger.removeHandler(handler)
        logger.setLevel(prev)
    return "\n".join(records)


def test_payoff_names_looted_app_and_resolved_privilege():
    # Entra-role payoff: the looted app + the role NAME (resolved, not the GUID).
    entra = _load(_technique_config(
        "StorageCertificateTheft",
        {"method": "AzureADRole", "entra_role": GA_ROLE}))
    out = _render(entra)
    app = entra.attack_paths[0].summary["app_name"]
    assert "Looted Application:" in out
    assert app in out
    assert "Global Administrator" in out          # resolved name
    assert GA_ROLE not in out                      # not the raw GUID
    assert "Storage Blob Data Reader" in out       # resource-access role named

    # API-permission payoff: the permission NAME (resolved).
    api = _load(_technique_config(
        "KeyVaultSecretTheft",
        {"method": "APIPermission", "api_type": "graph",
         "app_role": "9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8"}))  # RoleManagement.ReadWrite.Directory
    out_api = _render(api)
    assert "RoleManagement.ReadWrite.Directory" in out_api
    assert "Microsoft Graph" in out_api


def test_sp_resource_theft_principal_differs_from_looted_app():
    # Regression: for service_principal initial access, the compromised SP must NOT be
    # the looted app — otherwise the attacker already IS the privileged app (no
    # escalation). With exactly 2 apps the two picks must always be the distinct apps.
    cases = [
        ("KeyVaultSecretTheft", {"key_vaults": 1}),
        ("StorageCertificateTheft", {"storage_accounts": 1}),
        ("CosmosDBSecretTheft", {"cosmos_dbs": 1}),
    ]
    for technique, resources in cases:
        for _ in range(8):  # random pick — exercise it a few times
            scenario = _load({
                "baseline": {"identities": {"applications": 2}, "resources": resources},
                "attack_paths": {"p": {
                    "privilege_escalation": technique, "initial_access": "service_principal",
                    "method": "AzureADRole", "entra_role": "random"}},
            })
            summary = scenario.attack_paths[0].summary
            assert summary["principal_name"] != summary["app_name"], \
                f"{technique}: looted app == initial-access SP ({summary['app_name']})"


def test_enabled_false_parks_a_path():
    # enabled: false -> the path is defined but NOT deployed (no entities, no edges),
    # and a parked path may even be half-broken without blocking the build.
    cfg = {
        "tenant": {"tenant_id": None},
        "baseline": {"identities": {"users": 4, "applications": 4},
                     "resources": {"key_vaults": 1}},
        "attack_paths": {
            "active": {"privilege_escalation": "KeyVaultSecretTheft",
                       "method": "AzureADRole", "entra_role": "random"},
            "parked": {"enabled": False,
                       "privilege_escalation": "NotARealTechnique"},  # broken but parked
            "explicit_on": {"enabled": True,
                            "privilege_escalation": "ApplicationOwnershipAbuse",
                            "method": "AzureADRole", "entra_role": "random"},
        },
    }
    scenario = _load(cfg)                       # must NOT raise on the broken parked path
    names = {ov.name for ov in scenario.attack_paths}
    assert names == {"active", "explicit_on"}, names   # parked skipped; enabled:true kept


def _main():
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    failed = 0
    for t in tests:
        try:
            t()
            print(f"PASS  {t.__name__}")
        except AssertionError as e:
            failed += 1
            print(f"FAIL  {t.__name__}: {e}")
        except Exception as e:  # noqa: BLE001
            failed += 1
            print(f"ERROR {t.__name__}: {type(e).__name__}: {e}")
    print(f"\n{len(tests) - failed}/{len(tests)} passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(_main())
