"""
test_cheatsheet_drift.py — drift PREVENTION for the agent authoring skills.

The `.claude/skills/badzure-*-authoring/SKILL.md` files quote Entra-role and
Graph-permission NAMES so the Org Builder / Adversary subagents are self-sufficient.
Those name-lists are no longer hand-maintained: `src/skill_vocab.py` owns them and
generates each list (between `<!-- BADZURE:GEN ... -->` markers) from the single source
of truth (`src/vocabulary.py` / `src/constants.py`). Regenerate with:

    python -m src.skill_vocab

This test enforces that contract two ways:
  - `test_skill_vocab_blocks_in_sync` — every generated block in the SKILL.md files
    matches what the code would emit right now (so a vocabulary change that wasn't
    regenerated cannot merge — drift is *prevented*, not just *detected*).
  - `test_skill_vocab_names_resolve` — every advertised name still resolves (and the
    baseline examples are still low-priv). The skill_vocab builders assert this while
    rendering, so a removed/renamed role fails the regenerate; this test surfaces it
    independently with a precise message.

(Azure RBAC role names are intentionally NOT resolve-checked: they have no offline
catalog in constants.py — they pass through to Terraform/azurerm, which validates them
at apply time. They are still kept in sync structurally by the generator.)

Runs two ways:
    python tests/test_cheatsheet_drift.py
    pytest tests/test_cheatsheet_drift.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src import skill_vocab, vocabulary  # noqa: E402
from src.name_resolver import NameResolver, NameResolutionError  # noqa: E402


def test_skill_vocab_blocks_in_sync():
    stale = skill_vocab.sync(check=True)
    assert not stale, (
        "agent SKILL.md vocabulary is out of sync with src/vocabulary.py: "
        f"{stale}. Run `python -m src.skill_vocab` to regenerate.")


def test_skill_vocab_names_resolve():
    resolver = NameResolver()
    # Building the blocks runs skill_vocab's own assertions (low-priv / resolves /
    # in-registry); do it here so a failure is attributed to this test.
    skill_vocab.baseline_blocks()
    skill_vocab.attack_blocks()

    entra = (vocabulary.BASELINE_ENTRA_ROLE_EXAMPLES
             + vocabulary.ESCALATION_ENTRA_ROLES)
    bad_roles = []
    for name in entra:
        try:
            resolver.resolve_entra_role(name)
        except NameResolutionError:
            bad_roles.append(name)
    assert not bad_roles, f"Entra roles in the skills no longer resolve: {bad_roles}"

    bad_perms = []
    for name in vocabulary.graph_permission_names():
        try:
            resolver.resolve_api_permission(name, "graph")
        except NameResolutionError:
            bad_perms.append(name)
    assert not bad_perms, f"Graph permissions in the skills no longer resolve: {bad_perms}"


if __name__ == "__main__":
    failures = 0
    for fn in (test_skill_vocab_blocks_in_sync, test_skill_vocab_names_resolve):
        try:
            fn()
            print(f"PASS {fn.__name__}")
        except AssertionError as e:
            failures += 1
            print(f"FAIL {fn.__name__}: {e}")
    print(f"\n{'ALL PASSED' if failures == 0 else str(failures) + ' FAILED'}")
    sys.exit(1 if failures else 0)
