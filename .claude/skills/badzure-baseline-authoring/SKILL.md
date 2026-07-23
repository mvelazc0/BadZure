---
name: badzure-baseline-authoring
description: Authoring contract for a BadZure org-design YAML (departments + headcounts, groups, service principals, Azure resources, RBAC, Entra roles, ownerships, fake secrets) that `compile-baseline` expands into a realistic, deployable lab baseline. Use when generating or refining a BadZure organization/tenant baseline. Not for attack paths.
user-invocable: false
---

# BadZure baseline authoring

How to author a BadZure **org-design YAML** that `badzure compile-baseline` expands into a
realistic, deployable org baseline. This is the org-side equivalent of the attack-authoring skill.

The schema, rules, and a curated vocabulary are below — this skill is self-sufficient.
`compile-baseline` is the gate: it rejects any unknown role/permission name (or dangling ref)
with a clear error you then fix, so you don't need an exhaustive list to author confidently. For
the FULL authoritative role/permission lists you may optionally run
`python BadZure.py baseline-spec`, but you rarely need to.

---

## The idea
You author a COMPACT design (departments + headcounts, not individual users). A deterministic
compiler then expands it into realistically-named users, group memberships, SP grants, RBAC,
ownerships, AUs, and planted fake secrets — and validates the result. You never hand-write
hundreds of users; you give a `headcount` and the compiler generates them.

## Flow
1. Author the design as a single YAML mapping (see schema below) and save it to `design.yml`.
2. Compile + validate it (no LLM, no Azure):
   ```
   python BadZure.py compile-baseline --design design.yml -o generated.yml
   ```
3. If it exits non-zero, read the error, FIX `design.yml`, and re-run — the same self-repair
   loop the Adversary uses with `check`. Repeat until it exits 0.
4. Render the report for review:
   ```
   python BadZure.py report --config generated.yml --output generated.report.html
   ```

## Org-design schema (all top-level keys optional except `departments`)
```yaml
company: { name: "Helix Bio", industry: "biotech", size: "mid" }
departments:
  - { name: "Research", headcount: 78 }
  - { name: "IT", headcount: 12 }
groups:
  - { ref: "IT-Admins", department: "IT" }
service_principals:
  - ref: "ci-deploy"
    purpose: "CI/CD"
    api_permissions: ["User.Read.All"]
    azure_roles:
      - { role: "Contributor", scope: "rg-prod" }
    credentials:
      - { display_name: "github-actions" }
administrative_units:
  - { ref: "Research-Unit", departments: ["Research"] }
resources:
  resource_groups:
    - { ref: "rg-prod", location: "West US 2" }
  key_vaults:
    - { ref: "kvhxprod01", resource_group: "rg-prod" }
  storage_accounts:
    - { ref: "sthxprod01", resource_group: "rg-prod" }
rbac:
  - { principal: "IT-Admins", role: "Reader", scope: "rg-prod" }
entra_roles:
  - { principal: "IT-Admins", role: "Helpdesk Administrator" }
ownerships:
  - { owner: "IT", target: "ci-deploy" }
secrets:
  - { vault: "kvhxprod01", name: "db-connection-string" }
blobs:
  - { storage: "sthxprod01", name: "backup.json" }
```

## Vocabulary (the common, realistic palette)
Use these NAMES verbatim. `compile-baseline` accepts any name the resolver knows; this curated
set keeps generated orgs believable. (For the exhaustive list, `baseline-spec`.)

<!-- The name-lists below are GENERATED from src/vocabulary.py — do not hand-edit;
     run `python -m src.skill_vocab` to refresh. The tripwire test enforces sync. -->

**Azure RBAC roles** (for `rbac` and SP `azure_roles`):
<!-- BADZURE:GEN azure_rbac_roles -->
Owner, Contributor, Reader, Storage Blob Data Owner, Storage Blob Data Contributor, Storage
Blob Data Reader, Storage Account Contributor, Storage Queue Data Contributor, Key Vault
Administrator, Key Vault Secrets User, Key Vault Secrets Officer, Key Vault Reader, Key
Vault Certificates Officer, Virtual Machine Contributor, Virtual Machine Administrator
Login, Website Contributor, Web Plan Contributor, Cosmos DB Account Reader Role, DocumentDB
Account Contributor, Network Contributor, Monitoring Reader, Monitoring Contributor, User
Access Administrator
<!-- /BADZURE:GEN azure_rbac_roles -->

**Graph application permissions** (for SP `api_permissions`):
<!-- BADZURE:GEN graph_permissions -->
User.Read.All, User.ReadWrite.All, Group.Read.All, GroupMember.Read.All, Directory.Read.All,
Application.Read.All, Mail.Read, Mail.Send, Files.Read.All, Sites.Read.All, Calendars.Read,
People.Read.All, AuditLog.Read.All, Reports.Read.All
<!-- /BADZURE:GEN graph_permissions -->

**Entra roles** (for `entra_roles` — use SPARINGLY, only LOW-privileged ones; high-priv roles are
reserved for attack paths so the baseline doesn't look like the escalation a defender hunts), e.g.
<!-- BADZURE:GEN baseline_entra_roles -->
Directory Readers, Message Center Reader, Reports Reader, Service Support Administrator,
Groups Administrator, Guest Inviter, Usage Summary Reports Reader
<!-- /BADZURE:GEN baseline_entra_roles -->
(Full low-priv list: `baseline-spec`.)

## Key rules
- Do NOT enumerate users — give each department a `headcount`; the compiler names them.
- `principal` in `rbac`/`entra_roles`/`ownerships` may be a group ref, an SP ref, or a
  DEPARTMENT name (resolves to a representative user). `ownerships.owner` may NOT be a group.
- Use role/permission NAMES from the vocabulary above; use Entra roles sparingly and only
  low-privileged ones (the baseline is benign — attack paths come separately).
- `key_vault` refs: 3-24 chars, lowercase letters/digits/hyphens. `storage_account` refs:
  3-24 chars, lowercase letters/digits ONLY (no hyphens). Keep them globally unique-ish;
  `badzure uniquify` finalizes uniqueness before a live build.
- Every group and app registration should have an owner; populate a fully-wired org (memberships
  AND rbac AND entra_roles AND ownerships AND a few fake secrets/blobs) so it looks real.
- Secrets/blobs must be FAKE.

Never hand off a baseline that `compile-baseline` has not accepted (exit 0).
