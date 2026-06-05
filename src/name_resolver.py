"""
name_resolver.py — friendly NAME -> GUID resolution for the declarative config.

The declarative graph config (Phase 3) lets operators write
`role: "Global Administrator"` instead of the raw role GUID. This module turns
those human-readable Entra-role and API-permission names into the GUIDs the
Terraform generic layer needs, accepting four input forms (the same contract the
legacy `_assign_app_privileges` honored, minus its GUID-only passthrough):

  - a GUID            -> returned unchanged (passthrough)
  - a name            -> looked up in the catalog
  - a list of either  -> each element resolved, order preserved, deduped
  - the string "random" -> one random pick from the high-privileged pool

Azure RBAC roles are deliberately NOT handled here: `azurerm_role_assignment`
takes a role *name* ("Key Vault Contributor") directly, so the scenario loader
passes those through verbatim.

The catalog ("our database of GUIDs and names")
------------------------------------------------
The built-in catalog comes from src/constants.py, which is NOT exhaustive —
Microsoft ships new roles and Graph/Exchange permissions regularly. Rather than
forcing a Python edit for every addition, the resolver merges an OPTIONAL
overrides file on top of the built-ins at construction time. Point at it with the
BADZURE_CATALOG_OVERRIDES env var, or drop a `catalog_overrides.json` at the repo
root. Overrides win on name collisions, so you can also correct a stale GUID.
Format (see catalog_overrides.example.json):

    {
      "entra_roles":          { "Some New Role": "<guid>" },
      "graph_permissions":    { "Some.Graph.Perm": "<guid>" },
      "exchange_permissions": { "Some.Exchange.Perm": "<guid>" }
    }
"""
import json
import logging
import os
import random
import re
from typing import Dict, List, Optional

from src.constants import (
    HIGH_PRIVILEGED_ENTRA_ROLES, PRIVILEGED_ENTRA_ROLES, ENTRA_ROLES,
    ALL_API_PERMISSIONS, ALL_HIGH_PRIVILEGED_PERMISSIONS, API_REGISTRY,
)

_GUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
_RANDOM = "random"

# Default overrides-file location (env var wins). Lives at the repo root.
_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_DEFAULT_OVERRIDES = os.path.join(_REPO_ROOT, "catalog_overrides.json")


class NameResolutionError(ValueError):
    """Raised when a role/permission name (or api_type) can't be resolved."""


def is_guid(value: str) -> bool:
    return isinstance(value, str) and bool(_GUID_RE.match(value))


class NameResolver:
    """Resolves Entra-role and API-permission names/GUIDs against the merged
    built-in + overrides catalog."""

    def __init__(self, overrides_path: Optional[str] = None,
                 load_overrides: bool = True):
        # Entra roles: merge the three built-in catalogs (high-priv, privileged,
        # general). Identical names map to identical GUIDs across them; a later
        # dict simply re-affirms the value.
        self.entra_roles: Dict[str, str] = {}
        for catalog in (ENTRA_ROLES, PRIVILEGED_ENTRA_ROLES, HIGH_PRIVILEGED_ENTRA_ROLES):
            self.entra_roles.update(catalog)

        # API permissions: name -> GUID, per api_type (graph/exchange/...).
        self.api_permissions: Dict[str, Dict[str, str]] = {
            api_type: {name: meta["id"] for name, meta in perms.items()}
            for api_type, perms in ALL_API_PERMISSIONS.items()
        }

        # High-privileged pools used by the "random" sentinel.
        self._entra_random_pool: List[str] = list(HIGH_PRIVILEGED_ENTRA_ROLES.values())
        self._perm_random_pool: Dict[str, List[str]] = {
            api_type: [meta["id"] for meta in perms.values()]
            for api_type, perms in ALL_HIGH_PRIVILEGED_PERMISSIONS.items()
        }

        if load_overrides:
            path = overrides_path or os.environ.get("BADZURE_CATALOG_OVERRIDES") \
                or _DEFAULT_OVERRIDES
            self._load_overrides(path)

        # Case-insensitive fallback indexes (built after overrides merge).
        self._entra_ci = {k.lower(): v for k, v in self.entra_roles.items()}
        self._perm_ci = {
            api_type: {k.lower(): v for k, v in perms.items()}
            for api_type, perms in self.api_permissions.items()
        }

    # -- catalog maintenance --------------------------------------------------
    def _load_overrides(self, path: str) -> None:
        if not path or not os.path.isfile(path):
            return
        try:
            with open(path, "r") as f:
                data = json.load(f)
        except (json.JSONDecodeError, OSError) as e:
            logging.warning(f"Could not read catalog overrides '{path}': {e}")
            return
        self.entra_roles.update(data.get("entra_roles", {}))
        for name, guid in data.get("graph_permissions", {}).items():
            self.api_permissions.setdefault("graph", {})[name] = guid
        for name, guid in data.get("exchange_permissions", {}).items():
            self.api_permissions.setdefault("exchange", {})[name] = guid
        n = (len(data.get("entra_roles", {})) + len(data.get("graph_permissions", {}))
             + len(data.get("exchange_permissions", {})))
        if n:
            logging.info(f"Merged {n} catalog override(s) from '{path}'")

    # -- Entra roles ----------------------------------------------------------
    def resolve_entra_role(self, value) -> List[str]:
        """Resolve an entra_role field to an ordered, de-duplicated GUID list."""
        if value == _RANDOM:
            return [random.choice(self._entra_random_pool)]
        tokens = value if isinstance(value, list) else [value]
        return _dedupe(self._resolve_entra_token(t) for t in tokens)

    def _resolve_entra_token(self, token: str) -> str:
        if is_guid(token):
            return token
        guid = self.entra_roles.get(token) or self._entra_ci.get(str(token).lower())
        if guid is None:
            raise NameResolutionError(
                f"Unknown Entra role '{token}'. Use a GUID, a known role name, or "
                f"'random'. Add new roles via catalog_overrides.json "
                f"(entra_roles)."
            )
        return guid

    # -- API permissions ------------------------------------------------------
    def resolve_api_permission(self, value, api_type: str = "graph") -> List[str]:
        """Resolve an api_permission field to an ordered, de-duplicated GUID list
        for the given api_type (graph/exchange)."""
        if api_type not in API_REGISTRY:
            raise NameResolutionError(
                f"Unknown api_type '{api_type}'. Known: {', '.join(API_REGISTRY)}."
            )
        if value == _RANDOM:
            pool = self._perm_random_pool.get(api_type)
            if not pool:
                raise NameResolutionError(
                    f"No high-privileged '{api_type}' permissions to pick from."
                )
            return [random.choice(pool)]
        tokens = value if isinstance(value, list) else [value]
        return _dedupe(self._resolve_permission_token(t, api_type) for t in tokens)

    def _resolve_permission_token(self, token: str, api_type: str) -> str:
        if is_guid(token):
            return token
        by_name = self.api_permissions.get(api_type, {})
        guid = by_name.get(token) or self._perm_ci.get(api_type, {}).get(str(token).lower())
        if guid is None:
            raise NameResolutionError(
                f"Unknown {api_type} permission '{token}'. Use a GUID, a known "
                f"permission name, or 'random'. Add new permissions via "
                f"catalog_overrides.json ({api_type}_permissions)."
            )
        return guid


def _dedupe(items) -> List[str]:
    """Order-preserving de-duplication (avoids duplicate Terraform assignments)."""
    seen, out = set(), []
    for item in items:
        if item not in seen:
            seen.add(item)
            out.append(item)
    return out
