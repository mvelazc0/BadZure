"""
test_cheatsheet_drift.py — drift tripwire for the agent reference cheat-sheets.

The `.claude/reference/*-cheatsheet.md` files embed a curated vocabulary of Entra-role
and Graph-permission NAMES so the Org Builder / Adversary subagents are self-sufficient.
That embedded list can silently drift from the source of truth (`src/constants.py`, via
`NameResolver`) — e.g. if a role is renamed in code, the cheat-sheet keeps the old name and
an agent authors something the resolver rejects only at runtime.

This test parses the vocabulary sections out of the cheat-sheets and asserts every name
still resolves. If it fails, the cheat-sheet and the code have diverged — fix whichever is
stale. (Azure RBAC role names are intentionally NOT checked: they have no offline catalog in
constants.py — they pass through to Terraform/azurerm, which validates them at apply time.)

Runs two ways:
    python tests/test_cheatsheet_drift.py
    pytest tests/test_cheatsheet_drift.py
"""
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.name_resolver import NameResolver, NameResolutionError  # noqa: E402

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_REF = os.path.join(_REPO, ".claude", "reference")


def _read(name: str) -> str:
    with open(os.path.join(_REF, name), "r", encoding="utf-8") as f:
        return f.read()


def _graph_permissions(baseline_text: str):
    """Dotted PascalCase tokens (e.g. User.Read.All) are exactly the Graph permission
    names; nothing else in the cheat-sheet matches this shape."""
    return sorted(set(re.findall(r"[A-Z][A-Za-z]+(?:\.[A-Za-z]+)+", baseline_text)))


def _baseline_entra_roles(baseline_text: str):
    """The 'e.g. <comma list>.' after the **Entra roles** label in the baseline sheet."""
    m = re.search(r"e\.g\.\s*(.+?)\.\s*\(Full", baseline_text, re.S)
    assert m, "baseline cheat-sheet: **Entra roles** 'e.g. …' list not found (structure changed)"
    return [r.strip() for r in m.group(1).replace("\n", " ").split(",") if r.strip()]


def _attack_entra_roles(attack_text: str):
    """Backticked role names under the attack sheet's 'Escalation-worthy Entra roles'."""
    m = re.search(r"Escalation-worthy Entra roles.*?\n(.*?)(?:\n##|\Z)", attack_text, re.S)
    assert m, "attack cheat-sheet: 'Escalation-worthy Entra roles' section not found"
    return [t.strip() for t in re.findall(r"`([^`]+)`", m.group(1))]


def test_graph_permissions_resolve():
    resolver = NameResolver()
    perms = _graph_permissions(_read("baseline-authoring-cheatsheet.md"))
    assert len(perms) >= 5, f"too few Graph permissions parsed ({len(perms)}) — parser drift?"
    bad = []
    for p in perms:
        try:
            resolver.resolve_api_permission(p, "graph")
        except NameResolutionError:
            bad.append(p)
    assert not bad, f"Graph permissions in the cheat-sheet no longer resolve: {bad}"


def test_entra_roles_resolve():
    resolver = NameResolver()
    roles = (_baseline_entra_roles(_read("baseline-authoring-cheatsheet.md"))
             + _attack_entra_roles(_read("attack-authoring-cheatsheet.md")))
    assert len(roles) >= 5, f"too few Entra roles parsed ({len(roles)}) — parser drift?"
    bad = []
    for r in roles:
        try:
            resolver.resolve_entra_role(r)
        except NameResolutionError:
            bad.append(r)
    assert not bad, f"Entra roles in the cheat-sheets no longer resolve: {bad}"


if __name__ == "__main__":
    failures = 0
    for fn in (test_graph_permissions_resolve, test_entra_roles_resolve):
        try:
            fn()
            print(f"PASS {fn.__name__}")
        except AssertionError as e:
            failures += 1
            print(f"FAIL {fn.__name__}: {e}")
    print(f"\n{'ALL PASSED' if failures == 0 else str(failures) + ' FAILED'}")
    sys.exit(1 if failures else 0)
