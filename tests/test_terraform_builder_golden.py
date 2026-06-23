"""
test_terraform_builder_golden.py — the repo's first offline test.

The golden oracle is terraform/fixture_full.tfvars.json: a hand-written,
apply-verified tfvars exercising every generic building block variant. We
construct a DeploymentModel that mirrors it (entities loaded as passthrough; the
~50 building blocks hand-authored INDEPENDENTLY here, with BARE credential_refs
so the test exercises the builder's origin-prefixing), run the Terraform builder,
and assert it reproduces the fixture's 18 generic variables + 12 entity maps.

Comparison is "Terraform-equivalent," not byte-identical: each entry is
canonicalized to the optional(...) defaults generic.tf would fill in, so the
hand-written fixture's inconsistent inclusion of default-valued optionals
(api_type:"graph", pfx_password:"") doesn't matter — an omitted optional and an
explicit-default optional are the same object after Terraform's type coercion.

Runs two ways:
    python tests/test_terraform_builder_golden.py   # self-contained, no pytest
    pytest tests/test_terraform_builder_golden.py
"""
import copy
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.primitives import (  # noqa: E402
    DeploymentModel, RANDOM, ATTACK_PATH, optional_defaults,
    EntraRoleAssignment, AzureRbacAssignment, ApiPermission, AppCredential,
    DataInject, GroupMembership, AuMembership, GroupOwnership, AppOwnership,
)
from src.primitive_handlers import FAMILY_TO_CLASS, GENERIC_FAMILIES  # noqa: E402
from src.terraform_builder import build_tfvars  # noqa: E402

FIXTURE_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "terraform", "fixture_full.tfvars.json",
)


def _load_fixture():
    with open(FIXTURE_PATH) as f:
        return json.load(f)


def _build_model(fixture):
    """Mirror fixture_full as a DeploymentModel.

    Entities are loaded straight from the fixture (pure passthrough), EXCEPT
    is_attack_path_group is stripped from every group so the builder must
    DERIVE it (proving derivation, not transcription). Building blocks are
    authored independently below with bare credential_refs.
    """
    groups = copy.deepcopy(fixture["groups"])
    for g in groups.values():
        g.pop("is_attack_path_group", None)

    R, A = RANDOM, ATTACK_PATH
    primitives = [
        # ---- entra_role ----
        EntraRoleAssignment("noise_helpdesk", R, "bob", "user",
                            "729827e3-9c14-49f7-bb1b-9608f156bbb8"),
        EntraRoleAssignment("noise_dirread_sp", R, "app_recon", "service_principal",
                            "88d8e3e3-8f55-4a1e-953a-9b9898b8876b"),
        EntraRoleAssignment("ap_app_ga", A, "app_highpriv", "service_principal",
                            "62e90394-69f5-4237-9190-012177145e10"),
        EntraRoleAssignment("ap_user_appadmin_scoped", A, "alice", "user",
                            "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3",
                            scope_app_ref="app_highpriv"),
        EntraRoleAssignment("ap_group_cloudapp", A, "g_ap_role", "group",
                            "158c047a-c907-4556-b7ef-446551a6b5f7"),

        # ---- azure_rbac (control plane) ----
        AzureRbacAssignment("noise_sub_reader", R, "bob", "user", "Reader",
                            "subscription"),
        AzureRbacAssignment("noise_rg_reader_group", R, "g_finance", "group", "Reader",
                            "resource_group", scope_ref="rg_main"),
        AzureRbacAssignment("noise_owned_group_kv", R, "g_owned", "group",
                            "Key Vault Reader", "resource",
                            scope_resource_type="key_vault", scope_ref="kv_fixture"),
        AzureRbacAssignment("ap_kv_contrib_user", A, "alice", "user",
                            "Key Vault Contributor", "resource",
                            scope_resource_type="key_vault", scope_ref="kv_fixture"),
        AzureRbacAssignment("ap_sa_reader_sp", A, "app_recon", "service_principal",
                            "Storage Blob Data Reader", "resource",
                            scope_resource_type="storage_account", scope_ref="sa_fixture"),
        AzureRbacAssignment("ap_vm_linux_contrib", A, "alice", "user",
                            "Virtual Machine Contributor", "resource",
                            scope_resource_type="virtual_machine", scope_ref="vm_linux"),
        AzureRbacAssignment("ap_vm_win_contrib", A, "bob", "user",
                            "Virtual Machine Contributor", "resource",
                            scope_resource_type="virtual_machine", scope_ref="vm_win"),
        AzureRbacAssignment("ap_la_contrib", A, "alice", "user",
                            "Logic App Contributor", "resource",
                            scope_resource_type="logic_app", scope_ref="la_fixture"),
        AzureRbacAssignment("ap_aa_contrib", A, "alice", "user",
                            "Automation Contributor", "resource",
                            scope_resource_type="automation_account", scope_ref="aa_fixture"),
        AzureRbacAssignment("ap_fa_contrib", A, "alice", "user",
                            "Website Contributor", "resource",
                            scope_resource_type="function_app", scope_ref="fa_linux"),
        # ---- azure_rbac (managed identity) ----
        AzureRbacAssignment("ap_mi_vmlinux_kv", A, "vm_linux", "managed_identity",
                            "Key Vault Secrets User", "resource", mi_source_type="vm",
                            scope_resource_type="key_vault", scope_ref="kv_fixture"),
        AzureRbacAssignment("ap_mi_vmwin_sa", A, "vm_win", "managed_identity",
                            "Storage Blob Data Reader", "resource", mi_source_type="vm",
                            scope_resource_type="storage_account", scope_ref="sa_fixture"),
        AzureRbacAssignment("ap_mi_la_kv", A, "la_fixture", "managed_identity",
                            "Key Vault Reader", "resource", mi_source_type="logic_app",
                            scope_resource_type="key_vault", scope_ref="kv_fixture"),
        AzureRbacAssignment("ap_mi_aa_sa", A, "aa_fixture", "managed_identity",
                            "Storage Account Contributor", "resource",
                            mi_source_type="automation_account",
                            scope_resource_type="storage_account", scope_ref="sa_fixture"),
        AzureRbacAssignment("ap_mi_fa_kv", A, "fa_linux", "managed_identity",
                            "Key Vault Secrets User", "resource",
                            mi_source_type="function_app",
                            scope_resource_type="key_vault", scope_ref="kv_fixture"),
        # ---- azure_rbac (Cosmos data plane) ----
        AzureRbacAssignment("ap_cosmos_dataplane_user", A, "alice", "user",
                            "00000000-0000-0000-0000-000000000002", "resource",
                            scope_resource_type="cosmos_db", scope_ref="cosmos_fixture",
                            data_plane="cosmos_sql"),
        AzureRbacAssignment("ap_cosmos_dataplane_mi", A, "vm_linux", "managed_identity",
                            "00000000-0000-0000-0000-000000000002", "resource",
                            mi_source_type="vm",
                            scope_resource_type="cosmos_db", scope_ref="cosmos_fixture",
                            data_plane="cosmos_sql"),

        # ---- api_permission ----
        ApiPermission("noise_dirread", R, "app_recon",
                      "7ab1d382-f21e-4acd-a863-ba3e13f7da61", api_type="graph"),
        ApiPermission("ap_graph_rolemgmt", A, "app_highpriv",
                      "9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8", api_type="graph"),
        ApiPermission("ap_graph_apprw", A, "app_highpriv",
                      "1bfefb4e-e0b5-418b-a88f-73c46d2cc8e9", api_type="graph"),
        ApiPermission("ap_exchange_fullaccess", A, "app_highpriv",
                      "dc890d15-9560-4a4c-9b7f-a736ec74ec40", api_type="exchange"),

        # ---- app_credential ----
        AppCredential("noise_recon_secret", R, "app_recon", "password"),
        AppCredential("automation_secret", A, "app_automation", "password"),
        AppCredential("highpriv_secret", A, "app_highpriv", "password"),
        AppCredential("storagecert_cred", A, "app_storagecert", "certificate",
                      certificate_path="fx_storagecert.pem"),
        AppCredential("kvcert_cred", A, "app_kvcert", "certificate",
                      certificate_path="fx_kvcert.pem"),

        # ---- data_inject (credential_ref is BARE here; builder prefixes it) ----
        DataInject("kv_planted_secret", A, "app_secret", "key_vault_secret",
                   "kv_fixture", "automation-prod-secret",
                   credential_ref="automation_secret"),
        DataInject("kv_planted_appid", A, "app_client_id", "key_vault_secret",
                   "kv_fixture", "automation-client-id", source_ref="app_automation"),
        DataInject("kv_planted_cert", A, "app_certificate", "key_vault_certificate",
                   "kv_fixture", "kvcert-imported", file_path="fx_kvcert.pfx"),
        DataInject("blob_planted_pat", A, "literal", "storage_blob",
                   "sa_fixture", "devops-pat.txt",
                   literal_value="ghp_FAKEFULLPAT1234567890"),
        DataInject("blob_planted_cert", A, "app_certificate", "storage_blob",
                   "sa_fixture", "storagecert-public.pem",
                   file_path="fx_storagecert.pem"),
        DataInject("blob_planted_key", A, "app_certificate", "storage_blob",
                   "sa_fixture", "storagecert-private.key",
                   file_path="fx_storagecert.key"),
        DataInject("blob_planted_appid", A, "app_client_id", "storage_blob",
                   "sa_fixture", "storagecert-app-id.txt", source_ref="app_storagecert"),

        # ---- group_membership ----
        GroupMembership("bob_in_engineering", R, "bob", "user", "g_engineering"),
        GroupMembership("recon_in_finance", R, "app_recon", "service_principal",
                        "g_finance"),
        GroupMembership("finance_in_engineering", R, "g_finance", "group",
                        "g_engineering"),
        GroupMembership("alice_in_ap_role", A, "alice", "user", "g_ap_role"),

        # ---- au_membership ----
        AuMembership("bob_in_corp_au", R, "bob", "user", "au_corp"),
        AuMembership("eng_group_in_eng_au", R, "g_engineering", "group", "au_eng"),
        AuMembership("alice_in_corp_au", A, "alice", "user", "au_corp"),

        # ---- app_ownership ----
        AppOwnership("recon_owns_automation", R, "app_recon", "service_principal",
                     "app_automation"),
        AppOwnership("alice_owns_highpriv", A, "alice", "user", "app_highpriv"),

        # ---- group_ownership ----
        GroupOwnership("recon_owns_finance", R, "app_recon", "service_principal",
                       "g_finance"),
        GroupOwnership("dave_owns_ap_role", A, "dave", "user", "g_ap_role"),
    ]

    return DeploymentModel(
        tenant_id=fixture["tenant_id"],
        domain=fixture["domain"],
        subscription_id=fixture["subscription_id"],
        public_ip=fixture["public_ip"],
        azure_config_dir=fixture["azure_config_dir"],
        users=copy.deepcopy(fixture["users"]),
        groups=groups,
        applications=copy.deepcopy(fixture["applications"]),
        administrative_units=copy.deepcopy(fixture["administrative_units"]),
        resource_groups=copy.deepcopy(fixture["resource_groups"]),
        key_vaults=copy.deepcopy(fixture["key_vaults"]),
        storage_accounts=copy.deepcopy(fixture["storage_accounts"]),
        virtual_machines=copy.deepcopy(fixture["virtual_machines"]),
        logic_apps=copy.deepcopy(fixture["logic_apps"]),
        automation_accounts=copy.deepcopy(fixture["automation_accounts"]),
        function_apps=copy.deepcopy(fixture["function_apps"]),
        cosmos_dbs=copy.deepcopy(fixture["cosmos_dbs"]),
        primitives=primitives,
    )


def _canon_entry(entry, cls):
    """Fill optional(...) defaults so omitted == explicit-default (TF coercion)."""
    out = optional_defaults(cls)
    out.update(entry)
    return out


def _canon_family(fam_map, cls):
    return {k: _canon_entry(v, cls) for k, v in fam_map.items()}


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------
def test_generic_families_match_fixture():
    fixture = _load_fixture()
    out = build_tfvars(_build_model(fixture))

    for family in GENERIC_FAMILIES:
        cls = FAMILY_TO_CLASS[family]
        got = _canon_family(out.get(family, {}), cls)
        want = _canon_family(fixture.get(family, {}), cls)
        assert got == want, (
            f"family '{family}' mismatch:\n"
            f"  only-in-builder:  {set(got) - set(want)}\n"
            f"  only-in-fixture:  {set(want) - set(got)}\n"
            f"  got={got}\n  want={want}"
        )


def test_entity_maps_passthrough_and_keying():
    """Entity maps survive with SYMBOLIC keys (not re-keyed by UPN/display_name),
    and is_attack_path_group is re-derived onto g_ap_role."""
    fixture = _load_fixture()
    out = build_tfvars(_build_model(fixture))

    for attr in DeploymentModel.ENTITY_MAPS:
        assert out[attr] == fixture[attr], f"entity map '{attr}' mismatch"

    # symbolic keying: user is keyed "alice", with UPN nested inside
    assert "alice" in out["users"]
    assert out["users"]["alice"]["user_principal_name"] == "alice.full"


def test_is_attack_path_group_is_derived_not_authored():
    """g_ap_role (Entra-role target) -> flagged; g_owned (only RBAC) -> NOT."""
    fixture = _load_fixture()
    out = build_tfvars(_build_model(fixture))
    assert out["groups"]["g_ap_role"].get("is_attack_path_group") is True
    assert "is_attack_path_group" not in out["groups"]["g_owned"]


def test_credential_ref_is_origin_prefixed():
    """Bare credential_ref 'automation_secret' (an attack_path credential) becomes
    'ap:automation_secret' to match g_inject_value's merged-map indexing."""
    fixture = _load_fixture()
    out = build_tfvars(_build_model(fixture))
    injected = out["attack_path_data_injects"]["kv_planted_secret"]
    assert injected["credential_ref"] == "ap:automation_secret"


def test_cosmos_document_inject_is_filtered_from_tf_families():
    """cosmos_document is a data-plane-only inject: the builder still ref-validates
    it but must NOT emit it into any data_injects family (the Python data-plane
    phase plants it after apply). A regular storage_blob inject still emits."""
    model = DeploymentModel(
        domain="contoso.com",
        storage_accounts={"sa01": {"name": "sa01", "resource_group_name": "rg1"}},
        cosmos_dbs={"cos01": {"name": "cos01", "resource_group_name": "rg1",
                              "database_name": "db", "container_name": "c",
                              "partition_key_path": "/id"}},
        primitives=[
            DataInject("cosdoc", ATTACK_PATH, material="literal",
                       location_type="cosmos_document", location_ref="cos01",
                       name="seed", literal_value="{}"),
            DataInject("blob", ATTACK_PATH, material="literal",
                       location_type="storage_blob", location_ref="sa01",
                       name="loot.txt", literal_value="x"),
        ],
    )
    out = build_tfvars(model)  # validate() still runs over the cosmos inject
    injects = out.get("attack_path_data_injects", {})
    assert "cosdoc" not in injects        # cosmos_document filtered out
    assert "blob" in injects              # storage_blob still emitted


def test_cosmos_dataplane_refs_scopes_to_targeted_accounts_only():
    """cosmos_dataplane_refs (which accounts' master key the output surfaces) must
    list ONLY the Cosmos accounts an inject targets — baseline accounts are out."""
    model = DeploymentModel(
        domain="contoso.com",
        cosmos_dbs={
            "looted": {"name": "looted", "resource_group_name": "rg1",
                       "database_name": "db", "container_name": "c",
                       "partition_key_path": "/id"},
            "baseline_noise": {"name": "baseline-noise", "resource_group_name": "rg1",
                               "database_name": "db", "container_name": "c",
                               "partition_key_path": "/id"},
        },
        primitives=[
            DataInject("cosdoc", ATTACK_PATH, material="literal",
                       location_type="cosmos_document", location_ref="looted",
                       name="seed", literal_value="{}"),
        ],
    )
    out = build_tfvars(model)
    assert out["cosmos_dataplane_refs"] == ["looted"]   # baseline_noise excluded


def test_cosmos_dataplane_refs_empty_without_injects():
    """No cosmos_document inject -> empty allowlist -> the output surfaces nothing."""
    model = DeploymentModel(
        domain="contoso.com",
        cosmos_dbs={"baseline_noise": {"name": "bn", "resource_group_name": "rg1",
                                       "database_name": "db", "container_name": "c",
                                       "partition_key_path": "/id"}},
        primitives=[],
    )
    assert build_tfvars(model)["cosmos_dataplane_refs"] == []


# ---------------------------------------------------------------------------
# Self-runner (no pytest required)
# ---------------------------------------------------------------------------
def _main():
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    failed = 0
    for t in tests:
        try:
            t()
            print(f"PASS  {t.__name__}")
        except AssertionError as e:
            failed += 1
            print(f"FAIL  {t.__name__}\n{e}")
        except Exception as e:  # noqa: BLE001
            failed += 1
            print(f"ERROR {t.__name__}: {type(e).__name__}: {e}")
    print(f"\n{len(tests) - failed}/{len(tests)} passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(_main())
