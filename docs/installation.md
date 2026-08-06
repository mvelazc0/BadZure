# Installation

## Requirements

- **Python 3.8+**: [python.org](https://www.python.org/downloads/)
- **Azure CLI**: [installation guide](https://docs.microsoft.com/en-us/cli/azure/install-azure-cli)
- **Terraform**: [installation guide](https://learn.hashicorp.com/tutorials/terraform/install-cli)

You also need an Azure subscription with an Entra ID tenant. [Creating an Azure subscription](https://learn.microsoft.com/en-us/training/modules/create-an-azure-account/1-introduction) provides both.

!!! note
    BadZure uses only Entra ID Free tier features, so running it adds no licensing cost. Azure resources it creates (virtual machines, function apps, and the like) incur standard compute charges until you `destroy` the lab.

Azure CLI and Terraform are required only to `build`, `show`, `destroy`, or `plan` a lab against a real tenant. Authoring, `check`, and `report` run offline with Python alone.

## Install

Clone the repository:

```bash
git clone https://github.com/mvelazc0/BadZure
cd BadZure
```

Create a virtual environment and install dependencies:

=== "macOS / Linux"

    ```bash
    python -m venv venv
    source venv/bin/activate
    pip install -r requirements.txt
    ```

=== "Windows"

    ```bash
    python -m venv venv
    venv\Scripts\activate
    pip install -r requirements.txt
    ```

## Configure the tenant

BadZure reads your tenant identifiers from environment variables or from the `tenant:` block of a configuration file. Copy the example environment file and fill it in:

```bash
cp .env.example .env
```

Set your tenant ID, domain, and subscription ID in `.env`. A config whose `tenant:` values are `null` falls back to these variables.

## Authenticate to Azure

Building a lab requires **Global Administrator** in Entra ID and the **Owner** role on the subscription you will be working on. Using a dedicated service principal is recommended.

=== "Service principal"

    ```bash
    az login --service-principal --username $APP_ID --tenant $TENANT_ID --password <path-to-cert.pem>
    ```

=== "User account"

    ```bash
    az login --tenant $TENANT_ID  --scope "https://management.core.windows.net//.default" --claims-challenge "eyJhY2Nlc3NfdG9rZW4iOnsiYWNycyI6eyJlc3NlbnRpYWwiOnRydWUsInZhbHVlcyI6WyJwMSJdfX19"
    ```
## Verify the install

Confirm the CLI runs and list the commands:

```bash
python BadZure.py --help
```

`check` and `report` need no Azure login, so you can verify the offline path immediately against a bundled example:

```bash
python BadZure.py check --config examples/atomic/atomic_kv_theft_user.yml
```

A reachable verdict confirms the install. Continue with [Your First Lab](first-lab.md).
