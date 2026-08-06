"""
docs_vocab.py — generate the vocabulary name-lists embedded in the published docs
from the single source of truth (`src/vocabulary.py` / `src/constants.py`).

`docs/reference/vocabulary.md` lists the techniques, initial-access vectors, assignment
types, resource kinds, and common role/permission names a config may use. Those lists
can drift from code. Rather than merely detect drift, this module *owns* each list: it
lives between `<!-- BADZURE:GEN <id> -->` markers in the markdown and is rewritten from
code by `sync()`. Regenerate after changing the vocabulary:

    python -m src.docs_vocab        # rewrite the vocabulary.md blocks in place

`tests/test_docs_drift.py` calls `sync(check=True)` and fails if any block is stale, so a
vocabulary change that wasn't regenerated cannot merge. Mirrors `src/skill_vocab.py`.
"""
import os
import re
from typing import Dict, List

from src import vocabulary
from src.constants import VALID_TECHNIQUES, ATOMIC_INITIAL_ACCESS_VECTORS

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
VOCAB_DOC = os.path.join(_REPO, "docs", "reference", "vocabulary.md")

# Assignment types in a stable, readable order for the docs. Asserted below to be
# exactly the set the code supports, so adding/removing a type fails the regenerate.
_ASSIGNMENT_TYPE_ORDER = [
    "entra_role", "azure_rbac", "api_permission",
    "group_membership", "group_ownership", "app_ownership", "au_membership",
]


def _code(names: List[str]) -> str:
    return ", ".join(f"`{n}`" for n in names)


def _plain(names: List[str]) -> str:
    return ", ".join(names)


def _assignment_types() -> List[str]:
    have = set(vocabulary.ASSIGNMENT_FIELDS)
    listed = set(_ASSIGNMENT_TYPE_ORDER)
    if have != listed:
        raise ValueError(
            "assignment types in docs_vocab are out of sync with "
            f"vocabulary.ASSIGNMENT_FIELDS: only in code {have - listed}, "
            f"only in docs {listed - have}")
    return _ASSIGNMENT_TYPE_ORDER


def blocks() -> Dict[str, str]:
    """The generated body for each marker id in vocabulary.md."""
    return {
        "techniques": _code(list(VALID_TECHNIQUES)),
        "initial-access-vectors": _code(list(ATOMIC_INITIAL_ACCESS_VECTORS)),
        "assignment-types": _code(_assignment_types()),
        "resource-kinds": _code(list(vocabulary.RESOURCE_KINDS)),
        "azure-rbac-roles": _plain(list(vocabulary.COMMON_AZURE_RBAC_ROLES)),
        "graph-permissions": _plain(list(vocabulary.graph_permission_names())),
    }


def _apply(text: str, block_id: str, body: str) -> str:
    pattern = re.compile(
        r"(<!-- BADZURE:GEN " + re.escape(block_id) + r" -->\n)"
        r".*?"
        r"(\n<!-- /BADZURE:GEN " + re.escape(block_id) + r" -->)",
        re.S,
    )
    if not pattern.search(text):
        raise ValueError(
            f"vocabulary.md: missing generated-block markers for '{block_id}' "
            f"(expected <!-- BADZURE:GEN {block_id} --> ... "
            f"<!-- /BADZURE:GEN {block_id} -->).")
    return pattern.sub(lambda m: m.group(1) + body + m.group(2), text)


def sync(check: bool = False) -> List[str]:
    """Rewrite (or, with check=True, only verify) every generated vocab block in the
    docs from code. Returns the repo-relative path if it was rewritten / is stale."""
    with open(VOCAB_DOC, "r", encoding="utf-8") as f:
        original = f.read()
    updated = original
    for block_id, body in blocks().items():
        updated = _apply(updated, block_id, body)
    if updated == original:
        return []
    if not check:
        with open(VOCAB_DOC, "w", encoding="utf-8", newline="\n") as f:
            f.write(updated)
    return [os.path.relpath(VOCAB_DOC, _REPO)]


if __name__ == "__main__":
    changed = sync(check=False)
    print(f"regenerated {changed[0]}" if changed else "docs vocabulary already in sync")
