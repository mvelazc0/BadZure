"""
graph_builder.py — render a compiled BadZure DeploymentModel as Mermaid diagrams.

Three offline views, all derived from the config (no Azure):
  - identity  : org structure — administrative units, groups (+ member counts),
                service principals, and ownership/nesting edges.
  - resources : subscription -> resource groups -> resource counts per type.
  - attack    : the reachability-walked steps of each attack path.

Pure/text-only: every function returns a string (Mermaid source, or a standalone
HTML page embedding it). The CLI (`badzure graph`) compiles the model and opens the
HTML; this module never touches Azure or the browser, so it is fully unit-testable.
"""
import html
import re
from typing import Dict, List, Tuple

from src.primitives import (
    DeploymentModel, GroupMembership, GroupOwnership, AppOwnership, AuMembership,
)

# DeploymentModel attribute -> human label for the resource view.
_RESOURCE_TYPES = {
    "key_vaults": "Key Vault",
    "storage_accounts": "Storage Account",
    "virtual_machines": "Virtual Machine",
    "logic_apps": "Logic App",
    "automation_accounts": "Automation Account",
    "function_apps": "Function App",
    "app_services": "App Service",
    "cosmos_dbs": "Cosmos DB",
}

_UNPLACED = "(random placement)"


def _node_id(prefix: str, ref: str) -> str:
    """A Mermaid-safe node id derived from an entity ref."""
    return f"{prefix}_{re.sub(r'[^0-9A-Za-z]', '_', str(ref))}"


def _label(text: str) -> str:
    """Escape a string for use inside a Mermaid ["..."] label."""
    return html.escape(str(text), quote=True).replace("\n", "<br/>")


# ---------------------------------------------------------------------------
# Identity view
# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# Identity view — count-based and node-bounded so it stays legible at hundreds
# of users. Nodes are ONLY groups, administrative units and service principals;
# individual users are NEVER drawn — they appear as counts on labels.
# ---------------------------------------------------------------------------
_GROUP_NODE_CAP = 60      # above this, collapse groups to a single count node
_APP_NODE_CAP = 40        # above this, collapse SPs to a single count node


def identity_mermaid(model: DeploymentModel) -> str:
    groups = set(model.groups)
    apps = set(model.applications)

    members: Dict[str, int] = {}                 # group -> member count
    nesting: List[Tuple[str, str]] = []          # (child_group, parent_group)
    au_user_count: Dict[str, int] = {}           # au -> #user members
    au_group_members: Dict[str, List[str]] = {}  # au -> [group refs]
    group_user_owners: Dict[str, int] = {}       # group -> #user owners
    group_group_owners: List[Tuple[str, str]] = []   # (owner_group, group)
    app_user_owners: Dict[str, int] = {}         # app -> #user owners
    app_group_owners: List[Tuple[str, str]] = []     # (owner_group, app)
    app_app_owners: List[Tuple[str, str]] = []       # (owner_app, app)

    for p in model.primitives:
        if isinstance(p, GroupMembership):
            members[p.group_ref] = members.get(p.group_ref, 0) + 1
            if p.principal_type == "group":
                nesting.append((p.principal_ref, p.group_ref))
        elif isinstance(p, AuMembership):
            if p.principal_ref in groups:
                au_group_members.setdefault(p.au_ref, []).append(p.principal_ref)
            else:
                au_user_count[p.au_ref] = au_user_count.get(p.au_ref, 0) + 1
        elif isinstance(p, GroupOwnership):
            if p.principal_ref in groups:
                group_group_owners.append((p.principal_ref, p.group_ref))
            else:
                group_user_owners[p.group_ref] = group_user_owners.get(p.group_ref, 0) + 1
        elif isinstance(p, AppOwnership):
            if p.principal_ref in apps:
                app_app_owners.append((p.principal_ref, p.app_ref))
            elif p.principal_ref in groups:
                app_group_owners.append((p.principal_ref, p.app_ref))
            else:
                app_user_owners[p.app_ref] = app_user_owners.get(p.app_ref, 0) + 1

    lines: List[str] = ["flowchart TD"]
    summary = (f"Organization<br/>Users: {len(model.users)} &bull; "
               f"Groups: {len(model.groups)} &bull; "
               f"Service Principals: {len(model.applications)} &bull; "
               f"AUs: {len(model.administrative_units)}")
    lines.append(f'  org["{summary}"]')

    # Administrative units — counts only, never per-user nodes.
    for au in model.administrative_units:
        u = au_user_count.get(au, 0)
        g = len(au_group_members.get(au, []))
        lines.append(f'  {_node_id("au", au)}["AU: {_label(au)}<br/>'
                     f'Users: {u} &bull; Groups: {g}"]')
        lines.append(f'  org --> {_node_id("au", au)}')

    show_groups = len(model.groups) <= _GROUP_NODE_CAP
    if show_groups:
        nested_children = {c for c, _ in nesting}
        for g in model.groups:
            owner_note = (f"<br/>owned by {group_user_owners[g]} user(s)"
                          if group_user_owners.get(g) else "")
            lines.append(f'  {_node_id("g", g)}["{_label(g)}<br/>'
                         f'{members.get(g, 0)} members{owner_note}"]')
        for g in model.groups:
            if g not in nested_children:
                lines.append(f'  org --> {_node_id("g", g)}')
        for child, parent in nesting:
            lines.append(f'  {_node_id("g", child)} -->|member of| {_node_id("g", parent)}')
        for owner, grp in group_group_owners:
            lines.append(f'  {_node_id("g", owner)} -->|owns| {_node_id("g", grp)}')
        for au, gs in au_group_members.items():
            for g in gs:
                lines.append(f'  {_node_id("au", au)} -.->|contains| {_node_id("g", g)}')
    elif model.groups:
        lines.append(f'  groups_all["Groups ({len(model.groups)})"]')
        lines.append('  org --> groups_all')

    show_apps = bool(model.applications) and len(model.applications) <= _APP_NODE_CAP
    if show_apps:
        for app in model.applications:
            owner_note = (f"<br/>owned by {app_user_owners[app]} user(s)"
                          if app_user_owners.get(app) else "")
            lines.append(f'  {_node_id("app", app)}(["SP: {_label(app)}{owner_note}"])')
        if show_groups:
            for owner, app in app_app_owners:
                lines.append(f'  {_node_id("app", owner)} -->|owns| {_node_id("app", app)}')
            for owner, app in app_group_owners:
                lines.append(f'  {_node_id("g", owner)} -->|owns| {_node_id("app", app)}')
    elif model.applications:
        lines.append(f'  sps_all["Service Principals ({len(model.applications)})"]')
        lines.append('  org --> sps_all')

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Resource view
# ---------------------------------------------------------------------------
def resource_mermaid(model: DeploymentModel) -> str:
    # rg -> type_label -> count
    buckets: Dict[str, Dict[str, int]] = {}
    locations: Dict[str, str] = {
        rg: (info or {}).get("location", "") for rg, info in model.resource_groups.items()
    }
    for attr, type_label in _RESOURCE_TYPES.items():
        for _ref, info in getattr(model, attr).items():
            rg = (info or {}).get("resource_group_name") or _UNPLACED
            buckets.setdefault(rg, {})
            buckets[rg][type_label] = buckets[rg].get(type_label, 0) + 1

    lines: List[str] = ["flowchart TD", '  sub["Subscription"]']

    # Every declared RG, even empty ones, plus the synthetic unplaced bucket.
    rgs = list(model.resource_groups.keys())
    for rg in buckets:
        if rg not in rgs:
            rgs.append(rg)

    for rg in rgs:
        loc = locations.get(rg, "")
        loc_str = f"<br/>{_label(loc)}" if loc else ""
        lines.append(f'  {_node_id("rg", rg)}["RG: {_label(rg)}{loc_str}"]')
        lines.append(f'  sub --> {_node_id("rg", rg)}')
        for type_label, count in sorted(buckets.get(rg, {}).items()):
            tid = _node_id("rt", f"{rg}_{type_label}")
            lines.append(f'  {tid}["{_label(type_label)}: {count}"]')
            lines.append(f'  {_node_id("rg", rg)} --> {tid}')

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Attack view
# ---------------------------------------------------------------------------
def attack_mermaid(overlays: List) -> str:
    lines: List[str] = ["flowchart LR"]
    if not overlays:
        return "flowchart LR\n  none[\"No attack paths in this config\"]"

    for idx, ov in enumerate(overlays):
        reach = getattr(ov, "reachability", None) or {}
        status = reach.get("status", "")
        marker = {"reached": "reachable", "blocked": "UNREACHABLE",
                  "unverified": "unverified", "invalid": "INVALID"}.get(status, status)
        title = f"{ov.name} [{marker}]" if marker else ov.name
        lines.append(f'  subgraph p{idx}["{_label(title)}"]')
        steps = getattr(ov, "steps", None) or []
        if not steps:
            reason = reach.get("reason", "not traversable")
            lines.append(f'    p{idx}_blocked["{_label(reason)}"]')
            lines.append("  end")
            continue
        prev = None
        for sidx, step in enumerate(steps):
            nid = f"p{idx}_s{sidx}"
            name = step.get("name", "step")
            tgt = step.get("target_ref")
            label = f"{name}<br/>{tgt}" if tgt else name
            lines.append(f'    {nid}["{_label(label)}"]')
            if prev is not None:
                action = step.get("action")
                edge = f'-->|{_label(action)}|' if action else "-->"
                lines.append(f'    {prev} {edge} {nid}')
            prev = nid
        lines.append("  end")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# HTML wrapper
# ---------------------------------------------------------------------------
def render_html(title: str, sections: List[Tuple[str, str]]) -> str:
    """A standalone HTML page rendering each (heading, mermaid-source) section.
    Mermaid is loaded from a CDN and renders client-side — no server needed."""
    blocks = []
    for heading, mermaid in sections:
        blocks.append(
            f'<section><h2>{html.escape(heading)}</h2>'
            f'<pre class="mermaid">\n{html.escape(mermaid)}\n</pre></section>'
        )
    body = "\n".join(blocks)
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<title>{html.escape(title)}</title>
<style>
  body {{ font-family: -apple-system, Segoe UI, Roboto, sans-serif; margin: 2rem;
          background: #0d1117; color: #e6edf3; }}
  h1 {{ font-size: 1.4rem; }}
  h2 {{ font-size: 1.1rem; border-bottom: 1px solid #30363d; padding-bottom: .3rem;
        margin-top: 2rem; }}
  .mermaid {{ background: #161b22; border: 1px solid #30363d; border-radius: 8px;
              padding: 1rem; overflow: auto; }}
</style>
</head>
<body>
<h1>{html.escape(title)}</h1>
{body}
<script type="module">
  import mermaid from 'https://cdn.jsdelivr.net/npm/mermaid@10/dist/mermaid.esm.min.mjs';
  mermaid.initialize({{ startOnLoad: true, theme: 'dark', securityLevel: 'loose' }});
</script>
</body>
</html>
"""
