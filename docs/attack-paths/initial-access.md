# Initial Access

Every attack path begins at a foothold. Initial access describes how the attacker first lands. It is distinct from the technique they run afterward. BadZure provides the foothold's credentials or entry, so you start post-compromise.

There are two families: a compromised **credential** (the attacker holds an identity) and a **resource foothold** (the attacker has code execution on a host). A resource foothold seeds the path at the host, and controlling the host already means controlling its managed identity, so managed-identity chains continue from there.

## Compromised credential

The attacker already holds an identity's credentials obtained through phishing, password spray, or a leak. Set `principal_type` to choose the identity.

```yaml
initial_access:
  vector: compromised_credential
  principal_type: user            # or: service_principal
```

<iframe class="bz-graph" src="/reports/initial-access.report.html?embed=attack-credential" title="Compromised credential initial access" loading="lazy"></iframe>

<small class="bz-graph-caption"><a href="/reports/initial-access.report.html" target="_blank" rel="noopener">Open the full lab report ↗</a></small>

## Exposed RDP or SSH

An internet-exposed virtual machine with RDP or SSH open, reached by brute force. BadZure opens the port to the internet and gives the VM a weak administrator credential, then lands the attacker on the host with code execution.

```yaml
initial_access:
  vector: exposed_rdp             # or: exposed_ssh
  expose_to_internet: true
  credential: weak
```

<iframe class="bz-graph" src="/reports/initial-access.report.html?embed=attack-exposed_rdp" title="Exposed RDP initial access" loading="lazy"></iframe>

<small class="bz-graph-caption"><a href="/reports/initial-access.report.html" target="_blank" rel="noopener">Open the full lab report ↗</a></small>

The seed is the VM, not an identity. From code execution on the host, the path continues through the VM's managed identity.

## Vulnerable web application

An internet-facing App Service running deployed code with a command-injection bug. Exploiting it yields code execution on the app, and the path continues through the App Service's managed identity.

```yaml
initial_access:
  vector: vulnerable_web_app
  variant: rce
```

<iframe class="bz-graph" src="/reports/initial-access.report.html?embed=attack-vulnerable_web_app" title="Vulnerable web app initial access" loading="lazy"></iframe>

<small class="bz-graph-caption"><a href="/reports/initial-access.report.html" target="_blank" rel="noopener">Open the full lab report ↗</a></small>

## Choosing a vector

| Vector | Seeds at | Continues through |
|---|---|---|
| `compromised_credential` | A user or service principal | The identity's roles, ownership, and group membership |
| `exposed_rdp` / `exposed_ssh` | A virtual machine | The VM's managed identity |
| `vulnerable_web_app` | An App Service | The App Service's managed identity |

Any technique can follow a compromised credential. The resource footholds pair naturally with [ManagedIdentityAbuse](techniques/managed-identity-abuse.md), since they land on a host with a managed identity. Options for each vector are in the [Atomic Reference](../reference/atomic.md).
