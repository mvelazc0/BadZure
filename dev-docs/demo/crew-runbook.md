# Crew runbook — running the agentic BadZure demo

How to drive the "Conjure a Breach" demo with Claude Code. This is the operator's guide; the
design rationale is in `conjure-a-breach.md` and the build plan in `agentic-badzure-plan.md`.

## What's installed
- **Subagents** (`.claude/agents/`): `org-builder`, `adversary`, `gatekeeper` — the colored crew
  Claude Code delegates to and shows taking turns.
- **Slash command** (`.claude/commands/badzure-init.md`): `/badzure-init` — boots the assistant.
  The main agent becomes the 🧭 Architect, greets you, explains the steps, and asks for the org;
  from there it's a normal conversation (no more commands).
- **Authoring skills** (`.claude/skills/badzure-{baseline,attack}-authoring/SKILL.md`): the
  condensed authoring contracts, preloaded into the Org Builder / Adversary subagents at startup
  (via each subagent's `skills:` field) so the full guidance is always in context.
- The crew drives existing BadZure CLI commands — all OFFLINE except the final `build`:
  `generate` (org), `check` (the Gatekeeper's gate), `graph` (the review surface), `uniquify`
  (pre-deploy), and `build` (the only Azure step, run by you).

## Prerequisites
- An LLM key for `badzure generate` and for the subagents (set `BADZURE_LLM_MODEL` /
  `BADZURE_LLM_API_KEY` in `.env`, or pass `--model`). `pip install litellm` if needed.
- Claude Code running in the repo root.
- For the final live `build` only: `az login` as Entra ID Global Administrator AND subscription
  Owner. The design phase needs none of this.

## Run it
In Claude Code, boot the assistant with one command — then it's all conversation:
```
/badzure-init
```
The 🧭 Architect greets you, explains the steps, and asks what organization to model. Answer in
plain language (e.g. "a 300-person biotech called Helix Bio with R&D, Clinical, Finance and IT"),
then follow the prompts:
1. **Org review** — the identity/resource graphs auto-open in your browser. Give feedback in
   chat ("use prod/dev prefixes on the resource groups"); the org re-renders. Approve when happy.
2. **Attack** — tell it the intrusion you want (foothold → objective, rough hops). Watch the
   Gatekeeper reject and the Adversary repair; the attack graph auto-opens. Steer it if you want
   ("make the last step a Key Vault theft"). Approve when happy.
3. **Deploy** — the Architect runs `uniquify`, then asks you to confirm (this creates real Azure
   resources). On your "yes" it runs `build` itself and relays BadZure's final summary — the
   attack path, the initial-access credentials, and the `users.txt` note. No terminal needed.
   Be `az login`'d as Global Administrator + Owner first. Then `az login` as the phished user
   (creds in `users.txt`) and walk a hop. Tear down by asking the Architect to run
   `python BadZure.py destroy`.

## Driving the steps by hand (without the crew)
Every crew action is a plain CLI call you can run yourself:
```
python BadZure.py generate --prompt "<company>" -o generated.yml
python BadZure.py graph    --config generated.yml --view identity   --output generated.identity.html
python BadZure.py graph    --config generated.yml --view resources  --output generated.resources.html
# (author/edit attack_paths in generated.yml — see the cheat-sheet)
python BadZure.py check    --config generated.yml --json
python BadZure.py graph    --config generated.yml --view attack     --output generated.attack.html
python BadZure.py uniquify --config generated.yml
python BadZure.py build    --config generated.yml          # live; needs az login
```

## Notes & knobs
- **Models per agent** are set in each subagent's front-matter (`adversary: opus`,
  `org-builder: sonnet`, `gatekeeper: haiku`). Adjust to taste.
- **The Gatekeeper is deterministic.** Its verdict comes from `badzure check` (a graph walk), not
  model judgment — that is the demo's credibility anchor.
- **Nothing deploys during design.** Steps 1–2 only edit YAML and render graphs; `build` is the
  single, final Azure step and only you run it.
- **Demo-gods fallback:** keep a pre-built, reachable tenant ready to show for the reveal in case a
  live `build` stalls; the offline design phase is the real wow and survives a build hiccup.
