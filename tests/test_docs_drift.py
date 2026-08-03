"""
test_docs_drift.py — drift PREVENTION for the published docs vocabulary.

`docs/reference/vocabulary.md` lists the techniques, initial-access vectors, assignment
types, resource kinds, and common role/permission names a config may use. Those lists
are owned by `src/docs_vocab.py`, which generates each one (between
`<!-- BADZURE:GEN ... -->` markers) from the single source of truth
(`src/vocabulary.py` / `src/constants.py`). Regenerate with:

    python -m src.docs_vocab

This test fails if any generated block is stale, so a vocabulary change that wasn't
regenerated cannot merge. Mirrors tests/test_cheatsheet_drift.py.

Runs two ways:
    python tests/test_docs_drift.py
    pytest tests/test_docs_drift.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src import docs_vocab  # noqa: E402


def test_docs_vocab_blocks_in_sync():
    stale = docs_vocab.sync(check=True)
    assert not stale, (
        "docs/reference/vocabulary.md is out of sync with the code vocabulary. "
        "Run `python -m src.docs_vocab` to regenerate.")
    print("ok: docs vocabulary blocks match the code")


def test_docs_vocab_every_block_present():
    # Every block builder must find its markers (raises if a marker is missing).
    bodies = docs_vocab.blocks()
    for block_id, body in bodies.items():
        assert body.strip(), f"generated block '{block_id}' is empty"
    print(f"ok: all {len(bodies)} generated blocks resolve")


def _run_all():
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for t in tests:
        t()
    print(f"\nAll {len(tests)} docs-drift tests passed.")


if __name__ == "__main__":
    _run_all()
