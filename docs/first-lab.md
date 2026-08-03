# Your First Lab

This walkthrough takes one attack path from a config file to a deployed lab and back to a clean tenant. It uses a bundled example, a single Key Vault secret theft, so there is nothing to author yet.

## 1. Pick a config

`examples/atomic/atomic_kv_theft_user.yml` defines a small baseline and one attack path: a compromised user reads a privileged application's secret from a Key Vault and escalates to Global Administrator.

## 2. Validate it

`check` walks the attack graph and confirms the objective is reachable before deployment. It requires no Azure login:

```bash
python BadZure.py check --config examples/atomic/atomic_kv_theft_user.yml
```

It prints the derived steps and a verdict. A `reachable` result means the path is traversable; an `unreachable` result names the hop where it dead-ends. See the [`check` reference](reference/commands.md#check).

## 3. Generate & review the report

`report` renders the lab as an interactive HTML report and opens it in your browser:

```bash
python BadZure.py report --config examples/atomic/atomic_kv_theft_user.yml
```

The report has a graph for the tenant state (**posture**) and a graph for the adversary's actions (**attack**), plus the identity, resource, and assignment inventories. Explore it before you deploy anything. See [How to Read These Graphs](attack-paths/reading-graphs.md#the-full-lab-report).

## 4. Build it

`build` provisions the baseline and the attack path with Terraform. This step creates real resources and requires an Azure login with the roles listed in [Installation](installation.md):

```bash
python BadZure.py build --config examples/atomic/atomic_kv_theft_user.yml
```

BadZure creates the entities and Azure resources, wires the misconfigurations, and prints the foothold credentials for the compromised identity. Those credentials are your starting point for exploring the path.

## 5. Destroy it

When you are done, remove everything the lab created:

```bash
python BadZure.py destroy
```

Add `--verbose` for detailed teardown output.

## What's next

- Change the lab by swapping the initial access, assignment type, or objective. See the [technique catalog](attack-paths/techniques/index.md).
- Author your own: [Author an Atomic Path](building/authoring-atomic.md),
  [Author a Chained Path](building/authoring-chained.md), or
  [Author with Claude Code](building/authoring-with-claude.md).
- Understand the graphs: [How to Read These Graphs](attack-paths/reading-graphs.md).
