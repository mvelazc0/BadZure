"""
skill_vocab.py — generate the vocabulary name-lists embedded in the agent authoring
Skills from the single source of truth (`src/vocabulary.py` / `src/constants.py`).

The `.claude/skills/badzure-*-authoring/SKILL.md` files quote role/permission NAMES so
the Org Builder / Adversary subagents are self-sufficient. Those names can drift from
code. Rather than merely *detect* drift (the old tripwire), this module *owns* each
name-list: the list lives between `<!-- BADZURE:GEN <id> -->` markers in the SKILL.md
and is rewritten from code by `sync()`. Regenerate after changing the vocabulary:

    python -m src.skill_vocab        # rewrite the SKILL.md blocks in place

`tests/test_cheatsheet_drift.py` calls `sync(check=True)` and fails if any block is
stale — so a vocabulary change that wasn't regenerated cannot merge. The block builders
also assert every advertised name still resolves (and that baseline examples are still
low-priv), so removing/renaming a role in code fails the regenerate, not the live demo.
"""
import os
import re
import textwrap
from typing import Callable, Dict, List

from src import vocabulary
from src.constants import GRAPH_API_PERMISSIONS
from src.name_resolver import NameResolver, NameResolutionError

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_SKILLS = os.path.join(_REPO, ".claude", "skills")

BASELINE_SKILL = os.path.join(_SKILLS, "badzure-baseline-authoring", "SKILL.md")
ATTACK_SKILL = os.path.join(_SKILLS, "badzure-attack-authoring", "SKILL.md")

_WIDTH = 92  # wrap the comma-lists so the SKILL.md stays readable


def _wrap(names: List[str], backtick: bool = False) -> str:
    items = [f"`{n}`" for n in names] if backtick else list(names)
    return textwrap.fill(", ".join(items), width=_WIDTH,
                         break_long_words=False, break_on_hyphens=False)


# -- validation: a name that doesn't resolve must fail the REGENERATE, not the demo ----
def _assert_roles_resolve(names: List[str], label: str) -> None:
    resolver = NameResolver()
    bad = []
    for n in names:
        try:
            resolver.resolve_entra_role(n)
        except NameResolutionError:
            bad.append(n)
    if bad:
        raise ValueError(f"{label} no longer resolve in constants.py: {bad}")


def _assert_low_priv(names: List[str]) -> None:
    low = set(vocabulary.entra_role_names())
    bad = [n for n in names if n not in low]
    if bad:
        raise ValueError(
            f"baseline Entra-role examples are no longer low-priv baseline roles "
            f"(promoted to high-priv or removed): {bad}")


def _assert_graph_perms(names: List[str]) -> None:
    bad = [n for n in names if n not in GRAPH_API_PERMISSIONS]
    if bad:
        raise ValueError(f"Graph permissions no longer in the API registry: {bad}")


# -- the generated blocks, keyed by their marker id --------------------------------
def baseline_blocks() -> Dict[str, str]:
    _assert_low_priv(vocabulary.BASELINE_ENTRA_ROLE_EXAMPLES)
    _assert_graph_perms(vocabulary.graph_permission_names())
    return {
        "azure_rbac_roles": _wrap(vocabulary.COMMON_AZURE_RBAC_ROLES),
        "graph_permissions": _wrap(vocabulary.graph_permission_names()),
        "baseline_entra_roles": _wrap(vocabulary.BASELINE_ENTRA_ROLE_EXAMPLES),
    }


def attack_blocks() -> Dict[str, str]:
    _assert_roles_resolve(vocabulary.ESCALATION_ENTRA_ROLES, "escalation Entra roles")
    return {
        "escalation_entra_roles": _wrap(vocabulary.ESCALATION_ENTRA_ROLES, backtick=True),
    }


_FILES: List = [(BASELINE_SKILL, baseline_blocks), (ATTACK_SKILL, attack_blocks)]


def _apply(text: str, block_id: str, body: str, path: str) -> str:
    pattern = re.compile(
        r"(<!-- BADZURE:GEN " + re.escape(block_id) + r" -->\n)"
        r".*?"
        r"(\n<!-- /BADZURE:GEN " + re.escape(block_id) + r" -->)",
        re.S,
    )
    if not pattern.search(text):
        raise ValueError(
            f"{os.path.basename(path)}: missing generated-block markers for "
            f"'{block_id}' (expected <!-- BADZURE:GEN {block_id} --> ... "
            f"<!-- /BADZURE:GEN {block_id} -->).")
    return pattern.sub(lambda m: m.group(1) + body + m.group(2), text)


def sync(check: bool = False) -> List[str]:
    """Rewrite (or, with check=True, only verify) every generated vocab block from
    code. Returns the repo-relative paths that were rewritten / are out of sync."""
    stale: List[str] = []
    for path, builder in _FILES:
        with open(path, "r", encoding="utf-8") as f:
            original = f.read()
        updated = original
        for block_id, body in builder().items():
            updated = _apply(updated, block_id, body, path)
        if updated != original:
            stale.append(os.path.relpath(path, _REPO))
            if not check:
                with open(path, "w", encoding="utf-8", newline="\n") as f:
                    f.write(updated)
    return stale


if __name__ == "__main__":
    changed = sync(check=False)
    if changed:
        for p in changed:
            print(f"regenerated {p}")
    else:
        print("skills already in sync")
