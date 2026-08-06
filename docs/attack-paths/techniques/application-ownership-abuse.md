# ApplicationOwnershipAbuse

**Category:** Identity based

A compromised identity owns an application registration that holds a privileged Entra role. An owner can add credentials to the application and authenticate as its service principal, inheriting the role.

<div class="bz-graph-pair" markdown="0">
  <figure>
    <figcaption>Posture: the state that exists</figcaption>
    <iframe class="bz-graph" src="/reports/atomic-gallery.report.html?embed=posture-app_ownership" title="ApplicationOwnershipAbuse posture" loading="lazy"></iframe>
  </figure>
  <figure>
    <figcaption>Attack: what the adversary does</figcaption>
    <iframe class="bz-graph" src="/reports/atomic-gallery.report.html?embed=attack-app_ownership" title="ApplicationOwnershipAbuse attack" loading="lazy"></iframe>
  </figure>
</div>

<small class="bz-graph-caption"><a href="/reports/atomic-gallery.report.html" target="_blank" rel="noopener">Open the full lab report ↗</a></small>

## What makes it possible

Application owners can manage the application's credentials. Adding a client secret or certificate to an application lets the owner authenticate as its service principal and therefore hold whatever that service principal holds. When the owned application has a high-privilege Entra role, ownership is an escalation.

## Configure it

```yaml
attack_paths:
  app_ownership:
    initial_access:
      vector: compromised_credential
      principal_type: user            # or: service_principal
    privilege_escalation:
      technique: ApplicationOwnershipAbuse
      assignment_type: direct
    objective:
      entra_role: 62e90394-69f5-4237-9190-012177145e10   # Global Administrator
```

## Verify it

```bash
python BadZure.py check --config your-config.yml
```

A `reachable` verdict confirms a controlled principal owns an application that holds the objective role.

## Variants

- **Foothold**: `principal_type: user` or `service_principal`.
- **Objective**: any `entra_role`; the owned application is granted that role.

This technique supports only `direct` assignment: Entra ID does not let security groups own applications, so group-scoped ownership falls back to direct. Full options are in the [Atomic Reference](../../reference/atomic.md#applicationownershipabuse).
