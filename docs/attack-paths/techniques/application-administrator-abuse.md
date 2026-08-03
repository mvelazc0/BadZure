# ApplicationAdministratorAbuse

**Category:** Identity based

A compromised identity holds the **Application Administrator** Entra role. That role can manage credentials on *any* application in the tenant, so the attacker adds a credential to a privileged application and authenticates as it.

<div class="bz-graph-pair" markdown="0">
  <figure>
    <figcaption>Posture: the state that exists</figcaption>
    <iframe class="bz-graph" src="/reports/atomic-gallery.report.html?embed=posture-app_admin" title="ApplicationAdministratorAbuse posture" loading="lazy"></iframe>
  </figure>
  <figure>
    <figcaption>Attack: what the adversary does</figcaption>
    <iframe class="bz-graph" src="/reports/atomic-gallery.report.html?embed=attack-app_admin" title="ApplicationAdministratorAbuse attack" loading="lazy"></iframe>
  </figure>
</div>

<small class="bz-graph-caption"><a href="/reports/atomic-gallery.report.html" target="_blank" rel="noopener">Open the full lab report ↗</a></small>

## What makes it possible

Application Administrator is a directory role that grants credential management over every application registration. Unlike ownership, it is not scoped to a single app: any application with a powerful permission or role becomes a lever. The attacker adds a credential to such an application and inherits its privilege.

## Configure it

```yaml
attack_paths:
  app_admin:
    initial_access:
      vector: compromised_credential
      principal_type: user
    privilege_escalation:
      technique: ApplicationAdministratorAbuse
      assignment_type: direct
    objective:
      entra_role: 62e90394-69f5-4237-9190-012177145e10   # Global Administrator
```

## Verify it

```bash
python BadZure.py check --config your-config.yml
```

A `reachable` verdict confirms a controlled principal holds Application Administrator and can take over an application that reaches the objective.

## Variants

- **Assignment**: `assignment_type` controls whether the role is held directly or through a group.
- **Scope**: `scope: directory` (all applications, the default) or `scope: application` (the role is scoped to the target application only, a more least-privilege posture).
- **Foothold**: `principal_type: user` or `service_principal`.

Full options are in the [Atomic Reference](../../reference/atomic.md#applicationadministratorabuse).
