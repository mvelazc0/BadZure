"""
test_assignment_dedup.py — the builder collapses semantically-duplicate relationship
assignments (same principal/role/scope) so they can't reach `terraform apply` and 409
with RoleAssignmentExists. Duplicates can come from an LLM/agent authoring the same edge
twice or from baseline noise colliding with itself.

Runs two ways:
    python tests/test_assignment_dedup.py
    pytest tests/test_assignment_dedup.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.primitives import (  # noqa: E402
    DeploymentModel, RANDOM, ATTACK_PATH,
    AzureRbacAssignment, EntraRoleAssignment, GroupMembership, AppCredential, DataInject,
)
from src.terraform_builder import build_tfvars, dedupe_assignments  # noqa: E402


def _model(**kw):
    defaults = dict(
        users={"alice": {"user_principal_name": "alice", "display_name": "Alice",
                         "mail_nickname": "alice", "password": "x"}},
        groups={"g1": {"display_name": "G1"}},
        applications={"app1": {"display_name": "App1"}},
        resource_groups={"rg1": {"name": "rg1", "location": "West US 2"}},
        key_vaults={"kv1": {"name": "kv1", "location": "West US 2",
                            "resource_group_name": "rg1", "sku_name": "standard"}},
        primitives=[],
    )
    defaults.update(kw)
    return DeploymentModel(**defaults)


def _rbac(key, origin=RANDOM):
    return AzureRbacAssignment(key, origin, "alice", "user", "Key Vault Secrets User",
                               "resource", scope_resource_type="key_vault", scope_ref="kv1")


def test_duplicate_azure_rbac_collapsed_in_tfvars():
    # Two identical RBAC assignments (different keys) -> only ONE Terraform resource.
    m = _model(primitives=[_rbac("r0"), _rbac("r1")])
    tf = build_tfvars(m)
    assert len(tf["random_azure_rbac_assignments"]) == 1


def test_duplicate_collapsed_across_origins():
    # Same principal/role/scope, different ORIGIN -> still the same Azure resource -> 409.
    # They must collapse to a single emitted assignment total.
    m = _model(primitives=[_rbac("r0", RANDOM), _rbac("r1", ATTACK_PATH)])
    tf = build_tfvars(m)
    total = len(tf.get("random_azure_rbac_assignments", {})) + len(tf.get("attack_path_azure_rbac_assignments", {}))
    assert total == 1


def test_distinct_assignments_preserved():
    # Different role -> distinct resource -> both kept.
    a = _rbac("r0")
    b = AzureRbacAssignment("r1", RANDOM, "alice", "user", "Key Vault Reader",
                            "resource", scope_resource_type="key_vault", scope_ref="kv1")
    m = _model(primitives=[a, b])
    tf = build_tfvars(m)
    assert len(tf["random_azure_rbac_assignments"]) == 2


def test_duplicate_entra_role_and_membership_collapsed():
    out, removed = dedupe_assignments([
        EntraRoleAssignment("e0", RANDOM, "alice", "user", "role-guid"),
        EntraRoleAssignment("e1", RANDOM, "alice", "user", "role-guid"),
        GroupMembership("m0", RANDOM, "alice", "user", "g1"),
        GroupMembership("m1", RANDOM, "alice", "user", "g1"),
        GroupMembership("m2", RANDOM, "alice", "user", "g1"),
    ])
    assert removed == 3
    assert len(out) == 2


def test_credentials_and_injects_not_deduped():
    # Two credentials with identical content but distinct keys must BOTH survive — a
    # data_inject binds to one by key; collapsing them would break the reference.
    out, removed = dedupe_assignments([
        AppCredential("c0", RANDOM, "app1", "password"),
        AppCredential("c1", RANDOM, "app1", "password"),
    ])
    assert removed == 0
    assert len(out) == 2


if __name__ == "__main__":
    import logging
    logging.disable(logging.CRITICAL)
    failures = 0
    for fn in (test_duplicate_azure_rbac_collapsed_in_tfvars,
               test_duplicate_collapsed_across_origins,
               test_distinct_assignments_preserved,
               test_duplicate_entra_role_and_membership_collapsed,
               test_credentials_and_injects_not_deduped):
        try:
            fn()
            print(f"PASS {fn.__name__}")
        except AssertionError as e:
            failures += 1
            print(f"FAIL {fn.__name__}: {e}")
    print(f"\n{'ALL PASSED' if failures == 0 else str(failures) + ' FAILED'}")
    sys.exit(1 if failures else 0)
