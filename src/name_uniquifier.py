"""
name_uniquifier.py — make globally-unique Azure resource names unique AND valid.

BadZure resource refs double as real Azure names. Key vaults, storage accounts,
Cosmos DB accounts, function apps and app services must be GLOBALLY unique for a live
build, so a freshly generated (or hand-authored) config will clash on a real tenant.

`uniquify_config` rewrites those refs with a short random suffix AND every reference to
them across the whole config (assignment scope_refs, data_inject location_refs, etc.),
so the chain stays internally consistent. Other refs (users, groups, apps, resource
groups, VMs, …) are left untouched — they do not need global uniqueness. The new names
respect each type's Azure naming rules (length, character set, start character); the
suffix is always preserved and only the base is truncated.

Azure naming rules applied (Microsoft Learn, "Naming rules and restrictions for Azure
resources"):
  - key_vaults       : 3-24, alphanumerics + hyphens, start with a letter
  - storage_accounts : 3-24, LOWERCASE letters and numbers only (no hyphens)
  - cosmos_dbs       : 3-44, lowercase alphanumerics + hyphens, start with a letter
  - function_apps    : site name is 2-60, BUT capped to 24 here because main.tf DERIVES
                       the backing storage-account name from it (lowercase, strip hyphens,
                       truncate to 24 from the front); keeping the function-app name <=24
                       lowercase-alnum guarantees that derived storage name keeps the suffix
  - app_services     : 2-60, alphanumerics + hyphens (lowercased; no derived storage)

Pure/offline: returns a new config dict + the rename map; no Azure, no I/O.
"""
import copy
import random
import re
import string
from typing import Dict, Optional, Tuple

# kind -> (max_len, allow_hyphen, lowercase_only, must_start_with_letter).
_GLOBAL_KINDS = {
    "key_vaults":       (24, True,  False, True),
    "storage_accounts": (24, False, True,  False),
    "cosmos_dbs":       (44, True,  True,  True),
    "function_apps":    (24, True,  True,  False),   # 24: backing storage is derived from this
    "app_services":     (60, True,  True,  False),
}

_SUFFIX_LEN = 5


def _suffix(n: int = _SUFFIX_LEN) -> str:
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=n))


def _normalize(s: str, allow_hyphen: bool, lowercase_only: bool) -> str:
    if lowercase_only:
        s = s.lower()
    s = re.sub(r"[^0-9A-Za-z-]" if allow_hyphen else r"[^0-9A-Za-z]", "", s)
    s = re.sub(r"-{2,}", "-", s)            # collapse consecutive hyphens
    return s.strip("-")


def _make_name(old: str, suffix: str, max_len: int, allow_hyphen: bool,
               lowercase_only: bool, start_letter: bool) -> str:
    base = _normalize(old, allow_hyphen, lowercase_only)
    if start_letter and base and not base[0].isalpha():
        base = "a" + base
    joiner = "-" if allow_hyphen else ""
    tail = joiner + suffix
    keep = max(1, max_len - len(tail))
    base = base[:keep].rstrip("-")          # never let truncation leave a trailing hyphen
    if not base:
        base = "a" if start_letter else suffix[:1]
    return (base + tail)[:max_len]


def _collect(resources: Dict, rename: Dict[str, str], suffix: str) -> None:
    if not isinstance(resources, dict):
        return
    for kind, (max_len, allow_hyphen, lower, start_letter) in _GLOBAL_KINDS.items():
        for spec in resources.get(kind, []) or []:
            ref = spec.get("ref") if isinstance(spec, dict) else None
            if ref and ref not in rename:
                rename[ref] = _make_name(ref, suffix, max_len, allow_hyphen, lower,
                                         start_letter)


def _deep_replace(obj, rename: Dict[str, str]):
    if isinstance(obj, dict):
        return {k: _deep_replace(v, rename) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_deep_replace(v, rename) for v in obj]
    if isinstance(obj, str):
        return rename.get(obj, obj)   # exact-match only; substrings are untouched
    return obj


def uniquify_config(config: Dict, suffix: Optional[str] = None) -> Tuple[Dict, Dict[str, str]]:
    """Return (new_config, rename_map) with globally-unique resource names suffixed.

    A fixed `suffix` makes the transform deterministic (useful for tests / rehearsal);
    omit it to get a fresh random 5-char suffix.

    IDEMPOTENT: a config already carrying the `uniquified: true` marker is returned
    unchanged (empty rename map). This lets `build` always call uniquify without
    stacking a second suffix onto names an earlier `uniquify` (agent or CLI) already
    made unique. The marker is stamped onto every config this transform processes.
    """
    if config.get("uniquified"):
        return config, {}

    suffix = suffix or _suffix()
    rename: Dict[str, str] = {}

    baseline = config.get("baseline") or {}
    _collect(baseline.get("resources") or {}, rename, suffix)
    for path in (config.get("attack_paths") or {}).values():
        if isinstance(path, dict):
            _collect(path.get("resources") or {}, rename, suffix)

    new_config = _deep_replace(copy.deepcopy(config), rename)
    new_config["uniquified"] = True
    return new_config, rename
