# How to Read These Graphs

Every attack path in this documentation is shown as two interactive graphs, rendered from a real BadZure lab. This page explains what the shapes, colors, and lines mean. Read it once and every other graph on the site becomes legible.

## Two graphs per path

A path is always shown as a pair:

- **Posture**: the *state that exists* in the tenant: who is a member of what, who owns what, which principal holds which role, where a secret is stored. Posture is the misconfiguration, sitting still.
- **Attack**: the *sequence of actions* an adversary takes across that state: compromise, take over, inherit, steal, authenticate, achieve. Attack is the traversal, in order.

The distinction is the core idea of a cloud attack path: no single edge is the vulnerability. A user being a group member is normal. A group holding a role is normal. The **path through them** is the exposure. Posture shows the edges; attack shows the walk.

## Nodes

Node color encodes the entity type. The same type is the same color in every graph.

| Color | Type |
|---|---|
| Blue | User |
| Teal | Group |
| Purple | Service principal (application) |
| Light purple | Managed identity |
| Cyan | Administrative unit |
| Amber / yellow | Key Vault, Storage Account |
| Green | Virtual Machine |
| Orange / pink | Function App, Logic App, App Service, Automation Account |
| Lime | Cosmos DB |
| Pink-red | Credential |
| Light purple | Entra role |
| Red | Attacker, Objective |

A node with a **thick red ring** is sensitive: the privileged target the path is reaching for, or the objective itself.

## Edges

An edge is a relationship (in posture) or an action (in attack). Its style encodes emphasis:

| Style | Meaning |
|---|---|
| **Thick red, solid** | The escalation **spine**: the edges that actually carry the attack from foothold to objective |
| Grey, dashed | **Off-spine** context: real relationships that surround the path but are not part of it |
| Blue, dashed | **Inferred**: a relationship BadZure derived rather than one that was configured (for example, "can manage," which follows from a role) |
| Grey, solid | An ordinary relationship |

Following the thick red edges from the foothold traces the path a defender needs to break.

## Interacting

- **Drag** a node to rearrange the graph.
- **Hover** a node or edge for a quick summary.
- **Fit** and **Reset** (top right) recenter the graph.
- Open the full report (linked under each figure) for the complete, tabbed experience: every panel, the inventories, and a click-to-inspect detail panel that shows all properties of a node or edge, including the MITRE ATT&CK IDs on each attack step.

## The full lab report

Render any configuration as a self-contained interactive report before deploying:

```bash
python BadZure.py report --config my-lab.yml
```

The report opens in a browser and contains an overview plus Identity, Resources, and
Assignments panels for the environment. Each attack path then gets the paired
Posture and Attack graphs described above. The generated HTML is a single shareable
file; use `--output` to name it or `--no-open` to render without opening a browser.

## Attack-step labels

In the attack graph, each edge is a numbered step with an action and, where applicable, MITRE ATT&CK technique IDs. The steps read as a sentence: *compromise* the foothold, *take over* an app via ownership, *inherit* access via a group, *control* a resource and its managed identity, *loot* a planted credential, *achieve* the objective.
