# Chained Paths and Primitives

A **chained path** is an explicit attack graph built from lower-level primitives
rather than a named technique template. You declare the participants and connect
them one relationship at a time, giving you control over every hop from initial
access to the objective.

Despite the name, a chained path does not have to be long or combine several named
techniques. It can explicitly reproduce one catalog behavior or create a multi-stage
route that moves repeatedly between identities and Azure resources. What defines it
is the explicit graph, not its length. See [Atomic vs Chained Paths](atomic-vs-chained.md)
for a side-by-side comparison.

The graph below uses four escalation mechanisms: application ownership, group
membership, control of a virtual machine and its managed identity, and Key Vault
secret theft. Together, they move from a leaked deployment secret to Global Administrator.

<iframe class="bz-graph" src="/reports/chained-showcase.report.html?embed=attack-pipeline_to_ga" title="A chained attack path" loading="lazy"></iframe>

<small class="bz-graph-caption"><a href="/reports/chained-showcase.report.html" target="_blank" rel="noopener">Open the full lab report ↗</a></small>

## How this chain works

Following the graph from its foothold to its objective, the attacker:

1. Authenticates as the compromised `deploy-agent` service principal.
2. Uses application ownership to take over `release-bot`.
3. Inherits the access of the `platform-eng` group through `release-bot`'s membership.
4. Uses the group's Virtual Machine Contributor role to control `vm-build01` and act
   as its managed identity.
5. Uses that managed identity to read the client secret of `directory-sync` from a
   Key Vault, then authenticates as the application.
6. Reaches the objective because `directory-sync` holds Global Administrator.

Each step follows a relationship declared in the YAML. When a traversable
relationship brings another principal or resource under control, the reachability
walk continues from there until a controlled principal holds the objective.

## The YAML behind the chain

The excerpt below is the `attack_paths` entry that generates the graph. Its numbered
comments correspond to the walkthrough above; tenant and baseline configuration are
omitted so the path itself remains visible.

??? example "View the annotated YAML"

    ```yaml
    attack_paths:
      pipeline_to_ga:
        objective:
          name: "Global Administrator via CI/CD pipeline"
          capability: entra_role
          role: "Global Administrator"
          impact: critical

        # 1. Start with the compromised deployment service principal.
        initial_access:
          method: compromised_identity
          principal_ref: deploy-agent

        # Every participant in this path has a stable, explicit reference.
        identities:
          applications:
            - { ref: deploy-agent }
            - { ref: release-bot }
            - { ref: directory-sync }
          groups:
            - { ref: platform-eng }
        resources:
          resource_groups:
            - { ref: rg-compute, location: East US }
          virtual_machines:
            - { ref: vm-build01, resource_group: rg-compute }
          key_vaults:
            - { ref: kv-pipeline-secrets, resource_group: rg-compute }

        assignments:
          # 2. deploy-agent owns release-bot and can act as its service principal.
          - id: own1
            type: app_ownership
            principal_ref: deploy-agent
            app_ref: release-bot

          # 3. release-bot inherits the access held by platform-eng.
          - id: mem1
            type: group_membership
            principal_ref: release-bot
            group_ref: platform-eng

          # 4. The group can control the VM and therefore its managed identity.
          - id: rbac1
            type: azure_rbac
            principal_ref: platform-eng
            role: "Virtual Machine Contributor"
            scope_ref: vm-build01

          # 5. The VM's managed identity can read secrets from the vault.
          - id: rbac2
            type: azure_rbac
            principal_ref: vm-build01
            principal_type: managed_identity
            mi_source: vm
            role: "Key Vault Secrets User"
            scope_ref: kv-pipeline-secrets

          # 6. The application reached through the stolen secret holds the objective.
          - id: role1
            type: entra_role
            principal_ref: directory-sync
            role: "Global Administrator"

        # Step 5 also requires a real application credential stored in the vault.
        credentials:
          - { ref: ga_secret, app_ref: directory-sync, type: password }
        data_injects:
          - id: d1
            material: app_secret
            credential_ref: ga_secret
            location: key_vault_secret
            location_ref: kv-pipeline-secrets
            name: client-secret-directory-sync
    ```

## The building blocks

Chained paths use the same underlying relationships that atomic technique templates
expand into. They fall into three useful groups.

### Identity relationships

- `app_ownership`: take over an application by owning it
- `group_membership`: inherit the access assigned to a group
- `group_ownership`: take control of a group and its access
- `au_membership`: place a user or group in an administrative unit

### Privilege and access assignments

- `entra_role`: a directory role held by a principal
- `azure_rbac`: an Azure role held at a subscription, resource-group, or resource scope
- `api_permission`: a Graph or Exchange permission on a service principal

Managed-identity pivots are also expressed with `azure_rbac`: one assignment gives a
principal control of a compute resource, while another gives that resource's managed
identity access to its target.

### Credentials and stored data

- `credentials` declares a client secret or certificate for an application.
- `data_injects` plants that credential in a Key Vault, Storage Account, or Cosmos DB
  for a controlled principal to discover and use.

An atomic template fixes the sequence of primitives for its supported behavior. A
chained path lets you choose their order, combine them, and repeat them as needed.

## Author one

A chained path is defined with `assignments:` instead of `privilege_escalation:`. It declares an `objective`, an `initial_access` point, the `identities` and `resources` it uses, the `assignments` that form the chain, and any `credentials` and `data_injects` it plants.

The [Atomic vs Chained](atomic-vs-chained.md#chained-paths) overview contains a
minimal configuration. See [Chained Reference](../reference/chained.md) for every
field and [Author a Chained Path](../building/authoring-chained.md) for the workflow.
The `examples/chained/` directory holds worked configurations, including a
thirty-step chain that exercises every primitive.

## Verify it

```bash
python BadZure.py check --config your-chain.yml
```

`check` derives the full step list and confirms the objective is reachable. If a hop is missing, it reports where the walk dead-ends, naming the hop that blocks the path. See the [`check` reference](../reference/commands.md#check).
