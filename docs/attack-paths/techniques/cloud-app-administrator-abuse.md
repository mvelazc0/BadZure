# CloudAppAdministratorAbuse

**Category:** Identity based

A compromised identity holds the **Cloud Application Administrator** Entra role. Like Application Administrator, it can manage credentials on applications across the tenant, but it is narrower and cannot manage applications with certain sensitive configurations.

<div class="bz-graph-pair" markdown="0">
  <figure>
    <figcaption>Posture: the state that exists</figcaption>
    <iframe class="bz-graph" src="/reports/atomic-gallery.report.html?embed=posture-cloud_app_admin" title="CloudAppAdministratorAbuse posture" loading="lazy"></iframe>
  </figure>
  <figure>
    <figcaption>Attack: what the adversary does</figcaption>
    <iframe class="bz-graph" src="/reports/atomic-gallery.report.html?embed=attack-cloud_app_admin" title="CloudAppAdministratorAbuse attack" loading="lazy"></iframe>
  </figure>
</div>

<small class="bz-graph-caption"><a href="/reports/atomic-gallery.report.html" target="_blank" rel="noopener">Open the full lab report ↗</a></small>

## What makes it possible

Cloud Application Administrator grants credential management over applications, the same lever as Application Administrator. The difference is scope: it cannot act on applications with an on-premises application proxy configuration, and it is often granted as a "safer" delegation. When any reachable application still holds a powerful permission, the narrower role is enough to escalate.

## Configure it

```yaml
attack_paths:
  cloud_app_admin:
    initial_access:
      vector: compromised_credential
      principal_type: user
    privilege_escalation:
      technique: CloudAppAdministratorAbuse
      assignment_type: direct
    objective:
      entra_role: 62e90394-69f5-4237-9190-012177145e10   # Global Administrator
```

## Verify it

```bash
python BadZure.py check --config your-config.yml
```

A `reachable` verdict confirms a controlled principal holds Cloud Application Administrator and can take over an application that reaches the objective.

## Variants

Configuration is identical to [ApplicationAdministratorAbuse](application-administrator-abuse.md), with `assignment_type`, `scope`, and `principal_type`, but uses role `158c047a-c907-4556-b7ef-446551a6b5f7`. Full options are in the [Atomic Reference](../../reference/atomic.md#cloudappadministratorabuse).
