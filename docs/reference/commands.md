# CLI Commands

The core lab commands use `python BadZure.py <command> [options]`. They split into
offline operations and commands that deploy against a tenant.

| Command | Runs | Purpose |
|---|---|---|
| `build` | online | Create the lab in the tenant |
| `show` | online | Show the current lab's resources |
| `destroy` | online | Tear down the lab |
| `plan` | online | Terraform dry-run preflight |
| `check` | offline | Attack-path reachability gate |
| `report` | offline | Render the interactive HTML report |

---

## build

Create resources and attack paths in the tenant.

```bash
python BadZure.py build [--config badzure.yml] [--verbose]
```

Runs the reachability gate, provisions the baseline and attack paths with Terraform, plants looted secrets, and prints foothold credentials. Refuses to deploy an unreachable path unless `BADZURE_SKIP_REACHABILITY=1`. Authentication requirements are in [Installation](../installation.md#authenticate-to-azure).

- `--config`: config file (default `badzure.yml`).
- `--verbose`: detailed output.

## show

Show the resources created in the current lab.

```bash
python BadZure.py show [--verbose]
```

Calls `terraform show` on the current state.

## destroy

Destroy all resources the lab created.

```bash
python BadZure.py destroy [--verbose]
```

## plan

Preflight a config with `terraform plan`: a dry run that creates nothing but needs an Azure login. Catches deploy-breaking Terraform errors that `check` cannot see.

```bash
python BadZure.py plan [--config my-lab.yml] [--verbose]
```

## check

Attack-path reachability gate (offline). Walks the graph and reports whether each objective is reachable. An unreachable verdict identifies where the traversal stops.

```bash
python BadZure.py check [--config badzure.yml] [--json] [--verbose]
```

- `--json`: machine-readable verdict on stdout.
- `--verbose`: list every derived step.

Exit code `0` when all paths are reachable, non-zero otherwise.

## report

Render a comprehensive interactive HTML report (offline). See
[How to Read These Graphs](../attack-paths/reading-graphs.md#the-full-lab-report).

```bash
python BadZure.py report [--config badzure.yml] [--output PATH] [--no-open] [--verbose]
```

- `--output`: output HTML path (default `<config-stem>.report.html`).
- `--no-open`: do not open a browser.
