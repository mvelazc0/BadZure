# BadZure Documentation Overhaul — Plan & Progress Tracker

> **Status legend:** `[ ]` not started · `[~]` in progress · `[x]` done
> This document is the working guideline for the docs overhaul. Update the checkboxes as
> work lands so we always know what is implemented.
>
> **Status:** structure agreed · implementation not started

---

## 1. Context

The `dev` branch added a large amount of functionality that `docs/` does not describe: seven
new CLI commands, the offline reachability gate, the interactive HTML report, the agentic
authoring crew, and three new initial-access vectors. The published documentation still
describes the pre-`dev` tool.

It is not merely incomplete — it is wrong in the first place a new user looks. The
quick-start config in `docs/getting-started.md:126-131` uses the retired flat attack-path
shape and fails validation:

```
[!] Config error: Declarative config has 1 problem(s):
  - attack_path 'my_attack_path': `privilege_escalation:` must be a mapping with a
    `technique:` field (and the technique's knobs).
```

## 2. Goals

1. Every shipped feature has a page.
2. Every diagram is a live, interactive graph generated from a real,
   reachability-verified BadZure config — no mermaid anywhere.
3. The documentation teaches cloud attack paths, not just the tool.
4. Assertive and informative. No recommendations, no opinions, no hype.
5. Pages are short. The interactive graph carries the explanation that walls of mermaid and
   prose were carrying.

## 3. Non-goals

- Deploying to a real tenant to validate doc labs (`check` and `plan` cover it offline).
- Restructuring `dev-docs/` — internal design notes, not published.
- Playbook / scenario pages (detection engineering, purple team, CTF guides). The honest
  version needs telemetry research that cannot be derived from the codebase, and the
  dishonest version is the recommendation-flavored filler we are trying to avoid. Revisit
  later as a deliberate project.

---

## 4. The organizing insight

BadZure's report already emits **two paired graphs per attack path**, and they are
pedagogically distinct:

| Panel | Ontology | Shows |
|---|---|---|
| `posture-<path>` | `src/reporting/ontologies/posture.yml` | The **tenant state**: `MEMBER_OF`, `OWNS`, `HAS_ENTRA_ROLE`, `HAS_AZURE_ROLE`, `STORES`, `CREDENTIAL_FOR`, `CAN_REACH` from Internet — plus `CAN_MANAGE`, which is *derived*, not configured |
| `attack-<path>` | `src/reporting/ontologies/attack.yml` | The **adversary's action sequence**: `Attacker → COMPROMISES → EXPLOITS → STEALS_CREDENTIAL → AUTHENTICATES_AS → ACHIEVES`, with `step` ordering on every edge |

`src/reporting/style.py:7-13` gives every edge an `emphasis`:

- **spine** — red, thick: the actual escalation chain
- **offspine** — grey dashed: surrounding context
- **inferred** — blue dashed: derived relationships nobody configured

This is the lesson cloud attack paths teach: *no single edge is the vulnerability; the
traversal is.* The tooling already draws the signal path through the noise.

**Structural principle:** every attack concept is taught as the same triplet —
**state → traversal → objective** — with the posture graph and the attack graph adjacent.

`attack.yml` also defines a `BLOCKED_AT` edge carrying a `reason`, so the docs can teach why
a path *fails*, not only why it works.

---

## 5. Reader journeys

| Reader | Budget | Needs | Served by |
|---|---|---|---|
| **Evaluator** — "what is this?" | 5 min | A graph to drag before installing anything | §1 Start Here |
| **Operator** — "give me a lab" | 1 hour | install → deploy → credentials → attack → destroy | §1, §3 |
| **Author** — "build my scenario" | ongoing | Authoring guides + a reference to return to | §3, §4 |
| **Learner** — "teach me attack paths" | open | Concepts grounded in real, explorable graphs | §2 |

Today's docs serve the Operator only, and partially. The Learner is the reader the
interactive graphs unlock.

---

## 6. Target information architecture

```
1. START HERE
   Introduction              what it is + hero graph, no install required
   Installation
   Your First Lab            15-min tutorial: build → report → attack → destroy
   What's New                NEW — dev changed a lot; existing users have stale models

2. CLOUD ATTACK PATHS        the teaching section
   Attack Paths Explained    concepts, every diagram a real lab
   How to Read These Graphs  NEW — node types, edge types, spine vs off-spine,
                             posture vs attack, the red "sensitive" ring
   Anatomy of a Path         NEW — initial access → pivot → objective
   Initial Access            4 vectors, each with a graph
   Techniques                index (comparison table) + 7 templated pages
   Chaining Techniques       the long chain
   When Paths Fail           NEW — BLOCKED_AT + reason; teaches the negative space

3. BUILDING LABS             task-shaped how-to
   Lab Anatomy               NEW — a complete config, every section annotated
   Authoring by Hand
   Authoring with Claude Code
   Designing the Org Baseline
   Validating a Lab          check / plan / uniquify
   Deploying and Destroying
   Reading the Lab Report

4. REFERENCE
   CLI Commands              NEW — all 10
   Tenant & Baseline         split from configuration.md
   Atomic Reference          split
   Chained Reference         split
   Org Design Reference      NEW
   Vocabulary                roles, permissions, resource types, assignment types
   Graph Ontology            NEW — generated from ontologies/*.yml

5. PROJECT
   Talks & Demos
   Contributing
```

~26 pages, each short and single-purpose.

### 6.1 Technique pages stay separate

Seven pages, not one page with a switcher: each technique name is searched and deep-linked,
and a switcher destroys that. They are held together by a **strict template** —
graph → what makes it possible → configure it → verify it → variants — plus a
**comparison table on the Techniques index** (technique × initial access × source × target ×
objective) so scanners get the one-page view without losing the deep links.

---

## 7. Locked design decisions

| # | Decision | Rationale |
|---|---|---|
| D1 | Concept diagrams become **real mini-configs** | Every diagram comes from a deployable, `check`-verified lab. Zero drift. |
| D2 | Reports **generated at mkdocs build time**, never committed | Entity names are unseeded; committed reports churn on every regeneration. |
| D3 | Report template gets **light mode + flexible height** | Embeds must match the mkdocs theme toggle; docs control figure size. |
| D4 | Reports injected via **`File.generated`**, not written to `docs/` | Writing into `docs_dir` makes `mkdocs serve` rebuild forever — unseeded names mean every render differs byte-for-byte, so the loop never settles. Confirmed available in the installed mkdocs 1.6.1. |
| D5 | **Shared lab configs**, not one report per page | Each report inlines `cytoscape.min.js` (373 KB). One per page would add ~5 MB; a handful of shared configs add ~1 MB and the browser caches across pages. |
| D6 | **Full teaching section** (§2), not a bare catalog | The graphs are the differentiator; the teaching is what they enable. |
| D7 | Technique pages pair **posture + attack** graphs | The state-vs-traversal distinction is what makes attack paths click. Both panels already exist in every report. |
| D8 | MITRE IDs are **derived per-primitive**, not authored per technique | See §8. Chained paths inherit it free and it cannot drift from what a path actually does. |

---

## 8. MITRE ATT&CK derivation

`mitre` is already a first-class field on attack edges (`attack.yml`) and narratives
(`src/reporting/attack.py:47`), but it is populated only where an author hand-wrote it on a
chained path (`examples/chained/*.yml`). The seven atomic techniques emit nothing.

The fix is not seven hand-authored lists. `src/reachability.py:622-629` already maps
primitive type → action verb:

```python
_ACTIONS = {
    AppOwnership: "app_credential_addition",
    GroupOwnership: "group_membership_modification",
    ...
}
```

and applies it per-edge at `reachability.py:586` while deriving steps. Add a parallel
`_MITRE` map applied at the same point, plus mappings for the initial-access vectors at
`reachability.py:574`. ATT&CK IDs then come from the **actual traversal**: atomic and chained
paths both get them, and an author-supplied `mitre:` still augments the derived set.

**Implemented mapping** (in `src/reachability.py`, `_mitre_for_hop` +
`_INITIAL_ACCESS_MITRE`; adjust the table there and it flows to every report/doc):

| Primitive / vector | Condition | ATT&CK |
|---|---|---|
| `AppOwnership`, `EntraRoleAssignment` | add credentials to an app | T1098.001 Additional Cloud Credentials |
| `GroupOwnership`, `GroupMembership` | self-add to a privileged group | T1098.003 Additional Cloud Roles |
| `AzureRbacAssignment` | scope is a **compute host** (VM/logic app/automation/function/app service) | T1078.004 + **T1528** Steal Application Access Token (control the host → its MI token) |
| `AzureRbacAssignment` | any other scope (KV/storage/cosmos/sub/RG) | T1078.004 Valid Accounts: Cloud Accounts |
| `DataInject` | Key Vault secret / certificate | T1555.006 Cloud Secrets Management Stores |
| `DataInject` | storage blob | T1552.001 Unsecured Credentials: Credentials In Files |
| `DataInject` | cosmos document | T1552 Unsecured Credentials |
| `compromised_identity` / `compromised_credential` | initial access | T1078.004 |
| `exposed_rdp` / `exposed_ssh` | initial access | T1133 External Remote Services + T1110.001 Password Guessing |
| `vulnerable_web_app` | initial access | T1190 Exploit Public-Facing Application |

Two refinements from the draft, found while wiring it against real configs:
`T1528` keys on the **compute-host scope**, not on `mi_source_type` (the
`mi_source_type='vm'` assignments are the MI's *own* grants, not the theft hop); and
`exposed_rdp/ssh` map to **T1133 + T1110.001** (initial-access techniques) rather than
the draft's T1021.x (which is lateral movement). Verified: every technique in
`VALID_TECHNIQUES` yields ≥1 ID; MI abuse surfaces T1528, direct KV theft does not.

---

## 9. How the interactive graphs work

### 9.1 The mechanism already exists

`src/reporting/templates/report.html.j2:9-12` reads `?embed=<panel-key>` from the URL and
`:184-191` strips the header, tab nav, and overview, leaving only the graph canvas and detail
sidebar. Embedding is an `<iframe>` — no new rendering code, no new JS dependency.

Panel keys are stable and config-derived:
`identity`, `resources`, `assignments`, `posture-<path_name>`, `attack-<path_name>`.

Verified: `report --config examples/atomic/atomic_kv_theft_user.yml` produced 5 panels
including `attack-kv_theft_user` in a 430 KB self-contained file.

### 9.2 The build hook

`docs/hooks/reports.py`, wired via `hooks:` in `mkdocs.yml`:

```python
def on_files(files, config):
    for name, source in DOC_LABS.items():
        html = build_report_html(source)          # shared with ReportCommand
        files.append(File.generated(config, f"reports/{name}.report.html", content=html))
    return files
```

Requires factoring the render pipeline out of `src/cli.py:670-715` into a reusable
`build_report_html(config_file) -> str` that `ReportCommand.execute` also calls. Hook and CLI
stay on one code path.

### 9.3 Lab configs

| File | Serves |
|---|---|
| `docs/labs/atomic-gallery.yml` | One path per technique, stable names (`kv_theft`, `app_ownership`, …). All 7 technique pages, posture + attack panels each. |
| `docs/labs/chained-showcase.yml` | Chaining page, Anatomy of a Path, and the `identity` / `resources` / `assignments` panels for Reading the Lab Report. |
| `docs/labs/blocked.yml` | When Paths Fail — a deliberately unreachable path (see `examples/chained/chained_unreachable.yml`). |
| `docs/labs/concepts/*.yml` | 3–4 minimal configs for Attack Paths Explained: app ownership, key-vault-to-app, group indirection, cloud-app-admin. |
| `docs/labs/initial-access.yml` | One path per initial-access vector. |

### 9.4 Embed markup

```html
<iframe class="bz-graph" src="/reports/atomic-gallery.report.html?embed=attack-kv_theft"
        title="KeyVaultSecretTheft attack path"></iframe>
```

Absolute paths — mkdocs does not rewrite `src` inside raw HTML, and the site is served at the
domain root (`docs/CNAME`). `.bz-graph` styling and an "Open the full report ↗" link pattern
live in `docs/stylesheets/extra.css`.

### 9.5 Writing constraint

Entity names come from `entity_data/*.txt` with no seed, so they differ every build. Doc labs
whose entities prose names **must** be chained/explicit configs with named refs (`priya`,
`billing-sync-app`). Prose around atomic panels stays generic ("the compromised user").

---

## 10. Audit — what is wrong today

### 10.1 Broken

| Location | Problem |
|---|---|
| `docs/getting-started.md:126-131` | Attack-path config fails validation (verified) |
| `docs/index.md:60-69` | Quick start implies the same retired shape |

### 10.2 Undocumented — 7 of 10 CLI commands

Documented: `build`, `show`, `destroy`.
Missing: `check`, `plan`, `report`, `generate`, `compile-baseline`, `baseline-spec`,
`uniquify`.

### 10.3 Undocumented feature areas

| Area | Source of truth |
|---|---|
| Interactive HTML report | `src/reporting/`, `src/cli.py:660-781` |
| Agentic authoring crew | `.claude/agents/*.md`, `.claude/skills/badzure-*` |
| Org design → `compile-baseline` | `src/vocabulary.py`, `src/org_generator.py` |
| Reachability verdicts / blocked reasons | `src/reachability.py` |
| Initial-access vectors | `src/constants.py:2555-2600` |
| `uniquify` (global-name collisions) | `src/name_uniquifier.py` |

### 10.4 Structural

- `docs/configuration.md` is 668 lines doing five jobs.
- 60 mermaid blocks across 10 pages (13 in `managed-identity-abuse.md` alone).
- `docs/index.md` and `README.md` duplicate three paragraphs verbatim and drift apart.

---

## 11. Phases

### Phase 0 — Adopt the plan · `[x]`

- `[x]` Land this file at `dev-docs/documentation-overhaul-plan.md`
- `[x]` Fix `docs/getting-started.md` to the current nested shape (verified: `check` passes)
- `[x]` Fix the quick start in `docs/index.md` (cross-platform venv activation)

**Acceptance:** the config copied out of Getting Started passes `BadZure.py check`.
**Independent of every other phase — can ship immediately.**

---

### Phase 1 — Report template: light mode + height · `[x]`

- `[x]` Light palette via `prefers-color-scheme`, plus `?theme=light|dark` override
- `[x]` `src/reporting/report.py:225` — emit `"transparent"` for non-sensitive node borders
- `[x]` `html.embed-mode .graph-canvas` — fills the iframe viewport (`calc(100vh - 96px)`)
- `[x]` Graph label colors read from CSS vars at init, so they track the palette
- `[x]` Tests green (89 reporting tests); the asserted literal palette strings preserved as
  the dark `:root` defaults

**Acceptance met:** `pytest tests/` green; standalone report unchanged in dark mode.

---

### Phase 2 — MITRE derivation · `[x]`

- `[x]` `_mitre_for_hop` + `_INITIAL_ACCESS_MITRE` + `_COMPUTE_SCOPE_TYPES` in
  `src/reachability.py`, applied per-hop in `_derive_steps`
- `[x]` Initial-access vector mapping
- `[x]` Author-supplied `mitre:` augments (unioned) via `_merge_mitre`; path-level coverage
  aggregated in `src/reporting/attack.py:build_path_narrative`
- `[x]` `tests/test_mitre_derivation.py` — every technique yields ≥1 ID; T1528 for MI abuse

**Acceptance met:** `report` shows ATT&CK IDs on every attack edge (verified on MI abuse:
`["T1078.004","T1528"]`, `["T1555.006"]`).

---

### Phase 3 — Embed pipeline · `[x]`

- `[x]` `src/reporting/pipeline.py`: `build_report_html` / `build_report_html_from_file`,
  factored out of `src/cli.py` (CLI now calls it; dead helpers removed)
- `[x]` Lab configs authored and all reachability-checked: `atomic-gallery.yml` (7 paths),
  `chained-showcase.yml` (Northwind org + 6-step chain), `blocked.yml` (intentional dead-end),
  `initial-access.yml` (4 vectors), `concepts/*` (4 labs)
- `[x]` `docs/hooks/reports.py` using `File.generated` + `hooks:` in `mkdocs.yml`
- `[x]` `.bz-graph` + `.bz-graph-pair` CSS (side-by-side, stacks < 1000px)
- `[x]` `docs/javascripts/graph-theme.js` syncs `?theme=` to the mkdocs palette toggle
- `[x]` `.github/workflows/docs.yml`: installs `requirements.txt`, triggers on `src/**` +
  `examples/**`
- `[x]` Proved on the KeyVault page: paired posture/attack graphs embed and serve

**Acceptance met:** `mkdocs serve` serves all 8 reports and the embedded page (HTTP 200);
serve log shows **1 build, 0 rebuild events** — no loop. `pytest tests/` still 349 green.

---

### Phase 4 — Start Here · `[ ]`

- `[ ]` Introduction (hero graph, current feature set)
- `[ ]` Installation
- `[ ]` Your First Lab (15-min tutorial)
- `[ ]` What's New

---

### Phase 5 — Cloud Attack Paths · `[ ]`

- `[ ]` How to Read These Graphs — generated from `ontologies/*.yml` + `style.py:16-70`
- `[ ]` Attack Paths Explained — concept labs replace 9 mermaid blocks
- `[ ]` Anatomy of a Path
- `[ ]` Initial Access — 4 vectors per `src/constants.py:2555-2600`
- `[ ]` Techniques index with the comparison table
- `[ ]` 7 technique pages, strict template, posture + attack paired
- `[ ]` Chaining Techniques
- `[ ]` When Paths Fail
- `[ ]` `grep -rn mermaid docs/` returns nothing

---

### Phase 6 — Building Labs · `[ ]`

- `[ ]` Lab Anatomy
- `[ ]` Authoring by Hand
- `[ ]` Authoring with Claude Code — the crew (`org-builder`, `adversary`, `gatekeeper`), the
  two Agent Skills, `generate` / `compile-baseline` / `baseline-spec`
- `[ ]` Designing the Org Baseline
- `[ ]` Validating a Lab — `check` / `plan` / `uniquify`
- `[ ]` Deploying and Destroying
- `[ ]` Reading the Lab Report

---

### Phase 7 — Reference · `[ ]`

- `[ ]` CLI Commands — all 10, options, exit codes (`BadZure.py:86-196`, `src/cli.py`)
- `[ ]` Split `configuration.md` → Tenant & Baseline / Atomic / Chained
- `[ ]` Org Design Reference (`src/vocabulary.py`, `BaselineSpecCommand`)
- `[ ]` Vocabulary
- `[ ]` Graph Ontology
- `[ ]` `mkdocs.yml` nav + every inbound link updated

---

### Phase 8 — Drift guard & README · `[ ]`

- `[ ]` `tests/test_docs_drift.py` following `tests/test_cheatsheet_drift.py`: technique
  names, initial-access vectors, assignment types, node/edge types generated into the docs
  between `<!-- BADZURE:GEN -->` markers via `src/skill_vocab.py`
- `[ ]` Trim `README.md` to point at the docs instead of duplicating three paragraphs

---

## 12. Local development

Nothing extra to install — the venv already has mkdocs 1.6.1 and mkdocs-material.

```bash
./venv/bin/mkdocs serve       # http://127.0.0.1:8000
```

The hook renders the doc labs on startup and every rebuild, and mkdocs serves them at
`/reports/…`, so the absolute iframe paths resolve identically locally and in production.
Editing a page hot-reloads; editing a lab under `docs/labs/` re-renders its report.

To inspect a single panel outside mkdocs:

```bash
./venv/bin/python BadZure.py report --config docs/labs/atomic-gallery.yml --no-open
# then open: atomic-gallery.report.html?embed=attack-kv_theft
```

---

## 13. Verification

| Check | Command |
|---|---|
| Every doc lab reachable — no diagram shows an impossible path (except the deliberate one) | `BadZure.py check --config docs/labs/<each>.yml` |
| Tests survive the template + MITRE changes | `./venv/bin/python -m pytest tests/` |
| No broken links or nav refs | `./venv/bin/mkdocs build --strict` |
| Panels render in both site themes; no horizontal page scroll | `./venv/bin/mkdocs serve` |
| No mermaid left | `grep -rn mermaid docs/` |
| **The regression that started this** | copy the quick-start config out of Getting Started, run `check` |
