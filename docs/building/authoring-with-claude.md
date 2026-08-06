# Authoring with Claude Code

BadZure ships an agentic authoring workflow: a crew of [Claude Code](https://claude.com/claude-code) agents that build a lab conversationally, validated at every step by the same offline gates you would run by hand. You describe the lab; the crew writes the config, checks its reachability, and renders it for review.

This is optional. You can also build the configuration yourself: see
[Author an Atomic Path](authoring-atomic.md) or
[Author a Chained Path](authoring-chained.md).

## Start the crew

Open Claude Code in the BadZure repository and start the assistant:

```
/badzure-init
```

The crew greets you and walks you through building a lab. Describe the organization and the attack you want in natural language; the crew produces a validated config you can then `build`.

## The crew

Three agents divide the work, each with a single responsibility:

- **🏢 Org Builder**: generates and refines the realistic org baseline from your description: departments, groups, applications, Azure resources, and everyday assignments. It renders the interactive lab report for review. It does not author attack paths.
- **🗡️ Adversary**: designs a chained attack path through the baseline, weaving real entities into a multi-hop escalation to the objective you state. It self-repairs against the reachability gate: if a hop dead-ends, it fixes the chain and re-checks.
- **🛡️ Gatekeeper**: runs the deterministic gates and reports the verdict. It runs `check` (offline reachability) always, and `plan` (a Terraform dry run) on request. It only reports: it never edits a config or designs a path.

The division matters: the Adversary designs, but the Gatekeeper's verdict is a graph walk, not an opinion. A path is accepted only when `check` confirms it is traversable.

## The commands behind it

The crew drives the same commands you can run directly:

- **`generate`**: author a config from a natural-language prompt with an LLM, for you to review and build:

    ```bash
    python BadZure.py generate --prompt "a 30-person fintech startup with an over-privileged CI/CD pipeline"
    ```

- **`compile-baseline`**: expand an org-design YAML into a full baseline config, offline, with no LLM and no deploy:

    ```bash
    python BadZure.py compile-baseline --design org-design.yml -o generated.yml
    ```

- **`baseline-spec`**: print the org-design authoring contract, for an agent writing a design to compile.

The org-design workflow the crew and `compile-baseline` use is summarized under
[Generating an explicit baseline](../reference/tenant-baseline.md#generating-an-explicit-baseline).
Run `baseline-spec` for the complete, current format.

## Review before you build

Whatever the crew produces is a config file like any other. Review it, check it, and report it before deploying:

```bash
python BadZure.py check  --config generated.yml
python BadZure.py report --config generated.yml
python BadZure.py build  --config generated.yml
```
