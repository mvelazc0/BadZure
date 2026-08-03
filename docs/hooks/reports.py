"""mkdocs hook: render the documentation lab reports at build time.

Each lab under ``docs/labs/`` is rendered to a self-contained interactive HTML
report and injected into the built site as a generated file at ``reports/<name>``.
Documentation pages embed a single panel from a report with an iframe, e.g.::

    <iframe src="/reports/atomic-gallery.report.html?embed=attack-kv_theft"></iframe>

Reports are NEVER written into ``docs/`` — entity names are randomized, so every
render differs, and writing into the watched source tree would make ``mkdocs
serve`` rebuild forever. ``File.generated`` keeps them in-memory (regenerated on
every build/reload) and out of source control.
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path

from mkdocs.structure.files import File

# Repo root is two levels up from this file (docs/hooks/reports.py).
_REPO_ROOT = Path(__file__).resolve().parents[2]
_LABS_DIR = _REPO_ROOT / "docs" / "labs"


def _ensure_src_importable():
    """Put the repo root on sys.path so `import src` resolves.

    This MUST run inside the build event, not at module import: mkdocs restores
    sys.path after loading hook modules, so a top-level insert is discarded before
    on_files runs. It also lets `mkdocs` (the console script, no cwd on sys.path)
    work the same as `python -m mkdocs`.
    """
    if str(_REPO_ROOT) not in sys.path:
        sys.path.insert(0, str(_REPO_ROOT))

log = logging.getLogger("mkdocs.hooks.reports")

# Every lab config whose report the docs embed. Nested labs (concepts/) keep their
# subdirectory in the output path so panel URLs are stable and collision-free.
_LAB_CONFIGS = [
    "intro.yml",
    "atomic-gallery.yml",
    "chained-showcase.yml",
    "blocked.yml",
    "initial-access.yml",
    "concepts/app-ownership.yml",
    "concepts/key-vault-to-app.yml",
    "concepts/group-indirection.yml",
    "concepts/managed-identity.yml",
]


def on_files(files, config):
    """Render each lab config and add its report to the site as a generated file."""
    _ensure_src_importable()
    # Imported lazily (after the path fix above) so a missing dependency surfaces
    # here, during the docs build, rather than at hook-load time.
    from src.reporting.pipeline import build_report_html_from_file

    for rel in _LAB_CONFIGS:
        source = _LABS_DIR / rel
        if not source.exists():
            log.warning("BadZure docs lab not found, skipping: %s", source)
            continue
        out_path = f"reports/{Path(rel).with_suffix('').name}.report.html"
        try:
            html = build_report_html_from_file(str(source))
        except Exception as exc:  # a bad lab must fail the build, not ship an empty page
            raise RuntimeError(f"Failed to render report for {source}: {exc}") from exc
        files.append(File.generated(config, out_path, content=html))
        log.info("Rendered BadZure lab report: %s", out_path)
    return files
