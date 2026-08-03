# Author an Atomic Path

An atomic path names one of BadZure's built-in technique templates and supplies the
few choices that vary it. BadZure selects suitable entities from the baseline and
expands the template into a complete, reachable attack graph.

This guide builds the smallest form of an application-ownership path: a compromised
user owns an application that holds Global Administrator.

## Start with a complete lab

Save the following as `my-atomic-lab.yml`:

```yaml
tenant:
  # null values use the BADZURE_* variables from your environment.
  tenant_id: null
  domain: null
  subscription_id: null

baseline:
  # The selected technique needs one user and one application.
  identities:
    users: 1
    applications: 1

attack_paths:
  owned_app_to_admin:
    # Where the attacker starts.
    initial_access:
      vector: compromised_credential
      principal_type: user

    # The atomic template and its options.
    privilege_escalation:
      technique: ApplicationOwnershipAbuse
      assignment_type: direct

    # What the terminal application holds. This GUID is Global Administrator.
    objective:
      entra_role: 62e90394-69f5-4237-9190-012177145e10
```

The path reads: compromise a baseline user, use that user's ownership of an
application to add a credential, authenticate as the application's service
principal, and inherit its Global Administrator role.

## 1. Choose a technique

Set `privilege_escalation.technique` to one of BadZure's seven named templates. This
example uses `ApplicationOwnershipAbuse`:

```yaml
privilege_escalation:
  technique: ApplicationOwnershipAbuse
  assignment_type: direct
```

Each template has different options and baseline requirements. For example, a Key
Vault theft needs a Key Vault in `baseline.resources`, while managed-identity abuse
needs both a supported compute resource and, for stored-credential paths, a target
data resource. Use the [atomic technique catalog](../attack-paths/techniques/index.md)
to choose a template and see its supported variants.

An atomic attack-path entry names exactly one technique. A lab can still contain
several atomic paths by adding more named entries under `attack_paths:`.

## 2. Provide the required baseline

Atomic templates select their participants from the baseline. The example needs a
user for initial access and an application for the ownership target:

```yaml
baseline:
  identities:
    users: 1
    applications: 1
```

If the selected template cannot find the required entity or resource type, BadZure
rejects the configuration and identifies what is missing. The technique pages list
the resources required by each template.

## 3. Set initial access

`initial_access` defines the foothold BadZure gives the lab operator. Here, the
operator receives the credentials of the user selected from the baseline:

```yaml
initial_access:
  vector: compromised_credential
  principal_type: user
```

A compromised service principal is also supported. Exposed RDP, exposed SSH, and a
vulnerable web application are available for compatible managed-identity paths. See
[Initial Access](../attack-paths/initial-access.md) for the requirements and safety
controls of each vector.

## 4. Define the objective

The objective is the access the terminal principal must hold. This example uses an
Entra role:

```yaml
objective:
  entra_role: 62e90394-69f5-4237-9190-012177145e10
```

Atomic paths can also end at an API permission or an Azure role. The
[Atomic Reference](../reference/atomic.md#objective) documents each objective shape
and every per-technique option.

## 5. Check and inspect the path

Prove that the path is traversable before deploying it:

```bash
python BadZure.py check --config my-atomic-lab.yml
```

A `reachable` verdict means a controlled principal reaches the configured objective.
Then render the posture and attack graphs:

```bash
python BadZure.py report --config my-atomic-lab.yml
```

Use the report to confirm that the generated entities and traversal represent the
lab you intended. Neither command creates Azure or Entra resources.

## 6. Build and destroy the lab

Once the path looks right, deploy it:

```bash
python BadZure.py build --config my-atomic-lab.yml
```

BadZure prints the compromised user's credentials after the build. Those credentials
are the starting point for exercising the path. When finished, remove the lab:

```bash
python BadZure.py destroy
```

See [Installation](../installation.md#authenticate-to-azure) for authentication
requirements and the [`build` reference](../reference/commands.md#build) for options.

## Try a variation

After the first path works, change one dimension at a time. For example, switch to
`principal_type: service_principal` and increase `baseline.identities.applications`
to `2`. BadZure then selects one application as the compromised foothold and another
as the ownership target.

Run `check` and `report` after each change. For every available knob, see the
[Atomic Reference](../reference/atomic.md).
