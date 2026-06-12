"""
baseline_generator.py — the random org-baseline ("baseline") layer of a declarative lab.

A believable tenant isn't just the attack path — it's the surrounding baseline: dozens
of ordinary users, groups, apps and the low-stakes role/permission grants between
them. This module turns the declarative `baseline:` section's COUNTS into that
baseline: random entities and random assignments, all tagged `origin=random`. The
attack paths (origin=attack_path) are layered on top by the scenario loader; the
builder deploys both origins from one model.

Two deliberate contrasts with the attack-path layer keep signal distinct from the
baseline:
  - Baseline role/permission grants use the LOW-privileged catalogs (ENTRA_ROLES, the
    general GRAPH_API_PERMISSIONS). Attack paths use the high-privileged resolver.
    A defender hunting the escalation shouldn't trip over baseline noise.
  - Baseline generation is COUNT-driven (`entra_roles: 10`), not the legacy
    percentage-of-users heuristic — the declarative schema asks for an explicit
    amount, which is also how an LLM reasons about "add ~10 stray grants".

This is the Phase-3 analog of assignment_manager.create_random_assignments, but it
emits generic primitives instead of legacy dicts, and is driven by explicit counts.

Entities are generated here; assignments are generated in a SEPARATE call so the
loader can run them AFTER attack-path compilation and pass the groups an attack path
uses (so random members don't dilute an intended group-based chain — the same
exclusion the legacy random mode applies to attack-path groups).
"""
import logging
import random
from typing import Dict, List, Optional, Set, Tuple

from src.entity_generator import EntityGenerator
from src.primitives import (
    RANDOM, Primitive,
    EntraRoleAssignment, ApiPermission, GroupMembership, AuMembership,
)
from src.constants import ENTRA_ROLES, GRAPH_API_PERMISSIONS

# Resource kinds that need a parent resource group (everything except RGs).
_RG_DEPENDENT = (
    "key_vaults", "storage_accounts", "virtual_machines", "logic_apps",
    "automation_accounts", "function_apps", "cosmos_dbs",
)


def _count(value) -> int:
    """A baseline kind is either an integer COUNT or an explicit LIST of specs.
    This helper extracts the count form; explicit lists (built by the loader's
    targeted path) read as 0 here so the two forms can coexist in one baseline."""
    return value if isinstance(value, int) else 0


class BaselineGenerator:
    """Generates the random org-baseline entities and noise assignments."""

    def __init__(self, entity_generator: Optional[EntityGenerator] = None):
        self.generator = entity_generator or EntityGenerator()

    # -- entities -------------------------------------------------------------
    def generate_entities(self, baseline_config: Dict) -> Dict[str, Dict]:
        """COUNT-driven baseline entities: integer counts under
        baseline.identities / baseline.resources -> symbolic entity maps (same
        shape the attack-path layer and the builder expect).

        Kinds given as an explicit LIST of specs (the named, declarative form) are
        ignored here and built by the scenario loader's targeted path instead — so
        a baseline may mix counts (some kinds) and explicit specs (others). Only the
        count kinds are produced here; the loader merges the explicit ones in."""
        identities = baseline_config.get("identities") or {}
        resources = baseline_config.get("resources") or {}
        gen = self.generator

        rg_count = _count(resources.get("resource_groups"))
        if rg_count == 0 and any(_count(resources.get(k)) for k in _RG_DEPENDENT):
            # Count resources were requested with no resource group to hold them —
            # give them one rather than silently dropping them (EntityGenerator
            # would warn-and-skip otherwise). Explicit resources get their RG via
            # the loader's default-RG synthesis.
            rg_count = 1
            logging.info("baseline: synthesizing 1 resource group for baseline resources")
        resource_groups = gen.generate_resource_groups(rg_count)

        return {
            "users": gen.generate_users(_count(identities.get("users"))),
            "groups": gen.generate_groups(_count(identities.get("groups"))),
            "applications": gen.generate_applications(_count(identities.get("applications"))),
            "administrative_units": gen.generate_administrative_units(
                _count(identities.get("administrative_units"))),
            "resource_groups": resource_groups,
            "key_vaults": gen.generate_key_vaults(
                _count(resources.get("key_vaults")), resource_groups),
            "storage_accounts": gen.generate_storage_accounts(
                _count(resources.get("storage_accounts")), resource_groups),
            "virtual_machines": gen.generate_virtual_machines(
                _count(resources.get("virtual_machines")), resource_groups),
            "logic_apps": gen.generate_logic_apps(
                _count(resources.get("logic_apps")), resource_groups),
            "automation_accounts": gen.generate_automation_accounts(
                _count(resources.get("automation_accounts")), resource_groups),
            "function_apps": gen.generate_function_apps(
                _count(resources.get("function_apps")), resource_groups),
            "cosmos_dbs": gen.generate_cosmos_dbs(
                _count(resources.get("cosmos_dbs")), resource_groups),
        }

    # -- noise assignments ----------------------------------------------------
    def generate_noise(self, baseline_config: Dict, entities: Dict[str, Dict],
                       excluded_groups: Optional[Set[str]] = None) -> List[Primitive]:
        """Counts under baseline.assignments -> origin=random assignment primitives,
        sampled over the baseline entities only. `excluded_groups` are groups an
        attack path relies on; random group memberships avoid them."""
        acfg = baseline_config.get("assignments")
        if not isinstance(acfg, dict):
            # A LIST under assignments is the explicit form (emitted by the loader);
            # count-driven noise only applies to the dict-of-counts form.
            return []
        excluded = excluded_groups or set()
        prims: List[Primitive] = []
        prims += self._group_memberships(acfg.get("group_memberships", 0), entities, excluded)
        prims += self._entra_roles(acfg.get("entra_roles", 0), entities)
        prims += self._api_permissions(acfg.get("api_permissions", 0), entities)
        prims += self._au_memberships(acfg.get("au_memberships", 0), entities)
        return prims

    # -- noise helpers --------------------------------------------------------
    def _group_memberships(self, n: int, entities: Dict[str, Dict],
                           excluded: Set[str]) -> List[Primitive]:
        users = list(entities.get("users", {}))
        groups = [g for g in entities.get("groups", {}) if g not in excluded]
        return [
            GroupMembership(f"baseline_grpmem_{i}", RANDOM,
                            principal_ref=u, principal_type="user", group_ref=g)
            for i, (u, g) in enumerate(self._sample_pairs(users, groups, n))
        ]

    def _entra_roles(self, n: int, entities: Dict[str, Dict]) -> List[Primitive]:
        # Roles go to users OR apps; carry the right principal_type for each.
        principals = ([(u, "user") for u in entities.get("users", {})]
                      + [(a, "service_principal") for a in entities.get("applications", {})])
        roles = list(ENTRA_ROLES.values())
        return [
            EntraRoleAssignment(f"baseline_entra_{i}", RANDOM,
                                principal_ref=p[0], principal_type=p[1], role=r)
            for i, (p, r) in enumerate(self._sample_pairs(principals, roles, n))
        ]

    def _api_permissions(self, n: int, entities: Dict[str, Dict]) -> List[Primitive]:
        apps = list(entities.get("applications", {}))
        perms = [meta["id"] for meta in GRAPH_API_PERMISSIONS.values()]
        return [
            ApiPermission(f"baseline_api_{i}", RANDOM,
                          principal_ref=a, permission_id=p, api_type="graph")
            for i, (a, p) in enumerate(self._sample_pairs(apps, perms, n))
        ]

    def _au_memberships(self, n: int, entities: Dict[str, Dict]) -> List[Primitive]:
        users = list(entities.get("users", {}))
        aus = list(entities.get("administrative_units", {}))
        return [
            AuMembership(f"baseline_aumem_{i}", RANDOM,
                         principal_ref=u, principal_type="user", au_ref=au)
            for i, (u, au) in enumerate(self._sample_pairs(users, aus, n))
        ]

    @staticmethod
    def _sample_pairs(left: List, right: List, count: int) -> List[Tuple]:
        """Up to `count` DISTINCT (left, right) pairs, randomly chosen. Distinctness
        avoids generating the same membership/grant twice (which Azure rejects as a
        duplicate). Returns fewer than `count` when the pair space is smaller."""
        if not left or not right or count <= 0:
            return []
        pairs = [(l, r) for l in left for r in right]
        return random.sample(pairs, min(count, len(pairs)))
