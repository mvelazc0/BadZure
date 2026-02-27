# Getting Started

This guide walks you through setting up BadZure, populating your first vulnerable tenant, and tearing it down.

## Requirements

Before you begin, install the following:

- **Python 3.8+** — [python.org](https://www.python.org/downloads/)
- **Azure CLI** — [Installation guide](https://docs.microsoft.com/en-us/cli/azure/install-azure-cli)
- **Terraform** — [Installation guide](https://learn.hashicorp.com/tutorials/terraform/install-cli)

You also need an Azure subscription with an Entra ID tenant. [Creating an Azure subscription](https://learn.microsoft.com/en-us/training/modules/create-an-azure-account/1-introduction) will also provide you an Entra ID tenant.

!!! note
    BadZure uses only Entra ID Free tier features. Running it in your Azure subscription won't incur additional licensing costs, though Azure resources like Virtual Machines and Function Apps will incur standard compute charges.

## Installation

### Clone the repository

```bash
git clone https://github.com/mvelazc0/BadZure
cd BadZure
```

### Set up a virtual environment

=== "Windows"

    ```bash
    python -m venv venv
    venv\Scripts\activate
    pip install -r requirements.txt
    ```

=== "macOS / Linux"

    ```bash
    python -m venv venv
    source venv/bin/activate
    pip install -r requirements.txt
    ```

### Configure environment variables

Copy the example environment file and fill in your tenant details:

```bash
cp .env.example .env
```

Edit `.env` with your tenant ID, domain, and subscription ID. Alternatively, you can set these values directly in the YAML configuration file.

### Log in to Azure

You must be logged in as a **Global Administrator** in Entra ID and have the **Owner** RBAC role on the Azure subscription for BadZure to create and configure all resources:

```bash
az login
```

## Your First Run

### Build a vulnerable tenant

The simplest way to get started is to run `build` with the default configuration file:

```bash
python badzure.py build
```

This reads `badzure.yml`, creates the specified entities and Azure resources, and configures the attack paths defined in the file.

To use a custom configuration file:

```bash
python badzure.py build --config my-config.yml
```

!!! tip
    Start with a small configuration (5 users, 3 apps, 1-2 attack paths) for your first run. You can scale up once you're comfortable with the tool.

### View created resources

After a successful build, inspect what was created:

```bash
python badzure.py show
```

This displays all created entities, their credentials, and the configured attack paths with initial access details.

### Destroy the environment

When you're done, clean up everything:

```bash
python badzure.py destroy
```

For detailed output during teardown:

```bash
python badzure.py destroy --verbose
```

## Configuration Overview

BadZure uses a YAML file to define what to create and which attack paths to configure. The file has two main sections:

**`tenant`** — Defines your Azure tenant details and how many entities/resources to create:

```yaml
tenant:
  tenant_id: YOUR-TENANT-GUID
  domain: yourdomain.onmicrosoft.com
  subscription_id: YOUR-SUBSCRIPTION-GUID

  users: 10
  applications: 5
  groups: 3
  administrative_units: 2

  resource_groups: 1
  key_vaults: 1
  storage_accounts: 1
  virtual_machines: 1
  cosmos_dbs: 1
```

**`attack_paths`** — Defines the privilege escalation paths to configure:

```yaml
attack_paths:
  my_attack_path:
    enabled: true
    privilege_escalation: ApplicationOwnershipAbuse
    method: AzureADRole
    entra_role: 62e90394-69f5-4237-9190-012177145e10
```

See the [Configuration Guide](configuration.md) for the full reference of all options and parameters.

## What's Next?

- Browse the [Attack Paths](attack-paths/index.md) to understand the seven privilege escalation techniques BadZure supports
- Read the [Configuration Guide](configuration.md) to customize your environment
- Check out the example configurations in the `scenarios/` directory
