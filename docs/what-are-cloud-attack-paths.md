# What Are Cloud Attack Paths?

In the context of BadZure, a **cloud attack path** is a chain of entitlements that links identities, permissions, and cloud resources in ways that can unintentionally enable abuse. Once the right identity is compromised, an adversary can traverse that chain by abusing legitimate cloud features to reach their goal, whether that's data exfiltration, lateral movement, or full tenant compromise.

These paths don't rely on software vulnerabilities or zero-days. They emerge from everyday cloud administration: creating identities, granting permissions, provisioning resources, and configuring automation.

## How Attack Paths Emerge

Attack paths are created through the accumulation of individual configurations, each one reasonable on its own, but dangerous when connected.

### Explicit Configurations

The most straightforward attack paths come from direct, visible relationships. When a user is set as the **owner** of an application registration, that user can add credentials to the application and authenticate as its service principal. If the application holds a privileged Entra ID role or API permission, the user inherits that privilege.

``` mermaid
graph LR
    U(("User")) -->|"owner of"| APP(("Application"))
    APP -->|"has"| ROLE(("Privileged<br/>Role"))
```

Similarly, a user with **Key Vault Contributor** on an Azure Key Vault can retrieve application secrets stored inside and use them to authenticate as the service principal. If that application holds the `Mail.Read` permission, the attacker can read every mailbox in the tenant.

``` mermaid
graph LR
    U(("User")) -->|"Key Vault<br/>Contributor"| KV(("Azure<br/>Key Vault"))
    KV -->|"stores secret for"| APP(("Application<br/><small>Mail.Read</small>"))
    APP -->|"read all"| MAIL(("Tenant<br/>Mailboxes"))
```

The same pattern applies to Azure Storage. A user with **Storage Blob Data Reader** can download application certificates and private keys from a storage container, then use certificate-based authentication to impersonate the application. If that application holds `Files.Read.All`, the attacker can exfiltrate documents from every SharePoint site and OneDrive in the tenant.

``` mermaid
graph LR
    U(("User")) -->|"Blob Data<br/>Reader"| SA(("Azure Storage<br/>Account"))
    SA -->|"stores certificate for"| APP(("Application<br/><small>Files.Read.All</small>"))
    APP -->|"read all"| FILES(("SharePoint &<br/>OneDrive Files"))
```

These relationships are explicit — an administrator intentionally created them. But even explicit configurations can create unintended escalation paths when the downstream privileges of an application are broader than what the administrator intended for the user.

### Implicit Configurations

More subtle attack paths emerge from **implicit** relationships — configurations that individually follow best practices but combine into something unintended.

Consider an identity with the **Cloud Application Administrator** role. This role grants control over every application and service principal in the tenant. If any of those applications holds a powerful permission like `RoleManagement.ReadWrite.Directory`, the Cloud App Admin can add credentials to that application, authenticate as it, and use its permissions to promote themselves to Global Administrator.

``` mermaid
graph LR
    ID(("Compromised<br/>Identity")) -->|"has"| ROLE(("Cloud App<br/>Admin Role"))
    ROLE -->|"implicit control"| APP1(("App A"))
    ROLE -->|"implicit control"| APP2(("App B"))
    ROLE -->|"implicit control"| APP3(("App C<br/><small>RoleManagement<br/>.ReadWrite.Directory</small>"))
    APP3 -->|"escalate to"| GA(("Global<br/>Admin"))
```

No single configuration here is obviously wrong. The Cloud App Admin role may be legitimate. The API permission on App C may serve a valid automation use case. But together, they form a complete privilege escalation path to Global Administrator.

**Security groups** add another layer of indirection. A user who is a **member** of a group that holds a privileged role inherits that privilege — even though the role was never assigned to the user directly. If the group holds **Application Administrator** and a controlled application has `Privileged Role Administrator`, the attacker can promote themselves to Global Admin.

``` mermaid
graph LR
    U(("Compromised<br/>User")) -->|"member of"| G(("Security<br/>Group"))
    G -->|"has"| ROLE(("Application<br/>Administrator Role"))
    ROLE -->|"manage"| APP(("Application<br/><small>Privileged Role<br/>Administrator</small>"))
    APP -->|"escalate to"| GA(("Global<br/>Admin"))
```

Worse, a user who **owns** a security group can add themselves as a member at any time. If that group holds a privileged role, the owner can self-escalate by joining the group and inheriting its permissions.

``` mermaid
graph LR
    U(("Compromised<br/>User")) -->|"owner of"| G(("Security<br/>Group"))
    U -.->|"add self as member"| G
    G -->|"has"| ROLE(("Application<br/>Administrator Role"))
    ROLE -->|"manage"| APP(("Privileged<br/>Application"))
```

### Chains Across Azure and Entra ID

Attack paths become even more complex when they span both **Azure resources** and **Entra ID**. An identity with contributor access to a virtual machine can execute commands on it. If that VM has a managed identity with access to a Key Vault, the attacker can steal the managed identity token, retrieve application secrets from the vault, and authenticate as an application that holds `RoleManagement.ReadWrite.Directory` — then promote themselves to Global Administrator.

``` mermaid
graph LR
    ID(("Compromised<br/>Identity")) -->|"Contributor"| VM(("Virtual<br/>Machine"))
    VM -->|"managed identity"| MI(("Managed<br/>Identity"))
    MI -->|"Key Vault access"| KV(("Key<br/>Vault"))
    KV -->|"stores secret for"| APP(("Application<br/><small>RoleManagement<br/>.ReadWrite.Directory</small>"))
    APP -->|"escalate to"| GA(("Global<br/>Admin"))
```

The same pattern applies with different source resources and credential types. A compromised identity with contributor access to a **Logic App** can modify its workflow to extract the managed identity token, then use that token to download certificates from a **Storage Account** and authenticate as an application that holds Exchange `full_access_as_app` — giving the attacker read access to every mailbox in the organization.

``` mermaid
graph LR
    ID(("Compromised<br/>Identity")) -->|"Contributor"| LA(("Logic<br/>App"))
    LA -->|"managed identity"| MI(("Managed<br/>Identity"))
    MI -->|"Blob Data Reader"| SA(("Storage<br/>Account"))
    SA -->|"stores certificate for"| APP(("Application<br/><small>Exchange<br/>full_access_as_app</small>"))
    APP -->|"read all"| MAIL(("Tenant<br/>Mailboxes"))
```

Each link in the chain — the contributor role, the managed identity assignment, the storage access policy, the stored credential — exists for a legitimate reason. The attack path emerges from the connection between them.

## What BadZure Does About It

BadZure takes the concept of cloud attack paths and makes them **deployable**. Instead of waiting for misconfigurations to emerge organically, BadZure lets you define attack paths in YAML and provision them with Terraform into a lab environment.

This gives security teams a controlled, repeatable way to:

- **Understand** how identity abuse, credential theft, and privilege escalation work in Azure and Entra ID
- **Develop detections** by generating real telemetry from attack path traversal in a test tenant
- **Run purple team exercises** with known attack paths that can be traversed end-to-end
- **Validate controls** by testing whether logging, alerts, and response playbooks catch each step in the chain

Each attack path in BadZure represents a real-world technique — from application ownership abuse to managed identity token theft — codified as infrastructure-as-code that can be deployed, exercised, and torn down on demand.

``` mermaid
graph LR
    YAML["YAML<br/>Configuration"] -->|"BadZure"| TF["Terraform<br/>Plan"]
    TF -->|"deploy"| ENV["Azure / Entra ID<br/>Lab Environment"]
    ENV -->|"exercise"| DET["Detection &<br/>Response"]
```

To explore the specific attack paths BadZure supports, see the [Attack Paths](attack-paths/index.md) section.

## Further Reading

- [Attack Paths in Azure — How They Emerge (Andy Robbins, Specter Ops)](https://www.youtube.com/watch?v=02QXw0mxkBo)
- [Azure Attack Paths (Fabian Bader)](https://cloudbrothers.info/en/azure-attack-paths/)
- [Deploying Entra ID and Azure Attack Paths with BadZure](https://medium.com/@mvelazco/deploying-entra-id-and-azure-attack-paths-with-badzure-57a9c5bc2c06)
