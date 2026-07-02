"""
test_graph_command.py — offline test of the `badzure graph` command + graph_builder
(Phase 2 of the agentic-badzure work). Compiles the chained fixtures (no Azure) and
asserts the three Mermaid views and the HTML render. No browser is opened.

Runs two ways:
    python tests/test_graph_command.py
    pytest tests/test_graph_command.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src import graph_builder  # noqa: E402
from src.cli import GraphCommand  # noqa: E402
from src.entity_generator import EntityGenerator  # noqa: E402
from src.scenario_loader import ScenarioLoader  # noqa: E402
from src.config_manager import ConfigManager  # noqa: E402

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_CHAINED = os.path.join(_REPO, "examples", "chained")
_DATA = os.path.join(_REPO, "entity_data")


def _model_and_overlays(fixture):
    cfg = ConfigManager().load_config(os.path.join(_CHAINED, fixture))
    scenario = ScenarioLoader(EntityGenerator(data_dir=_DATA)).load(
        cfg, domain="example.com", enforce_reachability=False)
    return scenario.model, scenario.attack_paths


def _cmd():
    cmd = GraphCommand()
    cmd.generator = EntityGenerator(data_dir=_DATA)
    return cmd


# ---------------------------------------------------------------------------
# graph_builder pure functions
# ---------------------------------------------------------------------------
def test_identity_view():
    model, _ = _model_and_overlays("chained_apex.yml")
    out = graph_builder.identity_mermaid(model)
    assert out.startswith("flowchart TD")
    assert "Organization" in out
    assert "g-engineering" in out
    assert "members" in out
    # Individual users are NEVER nodes — svc-it-admin (a user owner + AU member in
    # apex) must appear only as a count, not as its own node.
    assert "svc-it-admin" not in out
    assert "owned by 1 user" in out


def test_identity_view_scales_to_many_users():
    from src.primitives import DeploymentModel, AuMembership
    m = DeploymentModel(
        users={f"u{i}": {} for i in range(200)},
        administrative_units={"au-tier0": {}},
    )
    m.primitives = [
        AuMembership(key=f"au_{i}", origin="random", principal_ref=f"u{i}",
                     principal_type="user", au_ref="au-tier0")
        for i in range(200)
    ]
    out = graph_builder.identity_mermaid(m)
    assert "Users: 200" in out          # the count is shown (org summary + AU label)
    assert "u_u0" not in out            # but no per-user node is emitted
    # Node-bounded: only the org summary + the single AU node.
    assert out.count('["') <= 3


def test_identity_view_folds_standalone_service_principals():
    # An org with many SPs where only a couple sit on an ownership edge: the
    # connected SPs get their own node; the standalone bulk folds into a count
    # node, so the view stays legible while the SP total is still shown.
    from src.primitives import DeploymentModel, AppOwnership
    apps = {f"sp-noise-{i}": {} for i in range(20)}
    apps["sp-owner"] = {}
    apps["sp-owned"] = {}
    m = DeploymentModel(applications=apps)
    m.primitives = [
        AppOwnership(key="o1", origin="random", principal_ref="sp-owner",
                     principal_type="service_principal", app_ref="sp-owned"),
    ]
    out = graph_builder.identity_mermaid(m)
    assert "Service Principals: 22" in out          # full count in the org summary
    # the two ownership-connected SPs are drawn individually...
    assert "SP: sp-owner" in out and "SP: sp-owned" in out
    assert "sp-owner" in out and "-->|owns|" in out  # the edge is kept
    # ...the 20 standalone SPs fold into one count node, not 20 nodes.
    assert "Other Service Principals (20)" in out
    assert "sp-noise-0" not in out


def test_identity_view_collapses_all_sps_when_none_connected():
    # No ownership edges among the SPs -> none are structural -> all fold into a
    # single plain count node (no "Other" qualifier since nothing is drawn).
    from src.primitives import DeploymentModel
    m = DeploymentModel(applications={f"sp{i}": {} for i in range(25)})
    out = graph_builder.identity_mermaid(m)
    assert "Service Principals (25)" in out
    assert "Other Service Principals" not in out
    assert "SP: sp0" not in out


def test_resource_view():
    model, _ = _model_and_overlays("chained_apex.yml")
    out = graph_builder.resource_mermaid(model)
    assert out.startswith("flowchart TD")
    assert "Subscription" in out
    assert "RG: rg-data" in out
    assert "Key Vault: 2" in out          # kv-bz-vault02 + kv-bz-vault04 in rg-data
    assert "Cosmos DB" in out             # cosmos-bz-app01 in rg-data


def test_attack_view():
    _, overlays = _model_and_overlays("chained_apex.yml")
    out = graph_builder.attack_mermaid(overlays)
    assert out.startswith("flowchart LR")
    assert "apex_to_global_admin" in out
    assert "reachable" in out
    assert "subgraph" in out


def test_attack_view_unreachable():
    _, overlays = _model_and_overlays("chained_unreachable.yml")
    out = graph_builder.attack_mermaid(overlays)
    assert "UNREACHABLE" in out


def test_attack_view_empty():
    out = graph_builder.attack_mermaid([])
    assert "No attack paths" in out


def test_render_html_wraps_sections():
    html = graph_builder.render_html("T", [("Sec", "flowchart TD\n  a-->b")])
    assert "<pre class=\"mermaid\">" in html
    assert "mermaid.initialize" in html
    assert "Sec" in html


# ---------------------------------------------------------------------------
# GraphCommand end to end (no browser)
# ---------------------------------------------------------------------------
def test_command_all_views(tmp_path):
    out = tmp_path / "lab.html"
    code = _cmd().execute(os.path.join(_CHAINED, "chained_apex.yml"),
                          view="all", output=str(out), open_browser=False)
    assert code == 0
    page = out.read_text(encoding="utf-8")
    assert "Identity / Org structure" in page
    assert "Resources" in page
    assert "Attack paths" in page
    assert "flowchart" in page


def test_command_single_view(tmp_path):
    out = tmp_path / "id.html"
    code = _cmd().execute(os.path.join(_CHAINED, "chained_apex.yml"),
                          view="identity", output=str(out), open_browser=False)
    assert code == 0
    page = out.read_text(encoding="utf-8")
    assert "Identity / Org structure" in page
    assert "Resources" not in page


def test_command_baseline_only(tmp_path):
    out = tmp_path / "base.html"
    code = _cmd().execute(os.path.join(_CHAINED, "chained_org_baseline.yml"),
                          view="all", output=str(out), open_browser=False)
    assert code == 0
    page = out.read_text(encoding="utf-8")
    assert "No attack paths" in page   # baseline-only -> empty attack view


def test_command_legacy_exits_two(tmp_path):
    p = tmp_path / "legacy.yml"
    p.write_text("mode: random\n")
    code = _cmd().execute(str(p), view="all", output=str(tmp_path / "x.html"),
                          open_browser=False)
    assert code == 2


if __name__ == "__main__":
    import logging
    import tempfile
    from pathlib import Path
    logging.disable(logging.CRITICAL)

    failures = 0
    for fn in (test_identity_view, test_resource_view, test_attack_view,
               test_attack_view_unreachable, test_attack_view_empty,
               test_render_html_wraps_sections):
        try:
            fn()
            print(f"PASS {fn.__name__}")
        except AssertionError as e:
            failures += 1
            print(f"FAIL {fn.__name__}: {e}")

    with tempfile.TemporaryDirectory() as d:
        tp = Path(d)
        for fn in (test_command_all_views, test_command_single_view,
                   test_command_baseline_only, test_command_legacy_exits_two):
            try:
                fn(tp)
                print(f"PASS {fn.__name__}")
            except AssertionError as e:
                failures += 1
                print(f"FAIL {fn.__name__}: {e}")

    print(f"\n{'ALL PASSED' if failures == 0 else str(failures) + ' FAILED'}")
    sys.exit(1 if failures else 0)
