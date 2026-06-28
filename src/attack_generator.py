"""
attack_generator.py — turn a natural-language attack prompt + an existing config into a
validated, REACHABLE chained attack path merged into that config.

The CLI counterpart of the Claude Code Adversary agent. Mirrors `org_generator.py`:
    (base config, prompt)
      -> LLM authors a chained `attack_paths` block (JSON) that threads through the org
      -> MERGE it into the config
      -> VALIDATE with the deterministic reachability gate (loader + reachability); on a
         blocked/invalid path, feed the reason back and RETRY
      -> return the merged config (baseline + verified attack paths).

The reliability gate is the SAME reachability check `badzure check` exposes — the LLM's
output is never trusted for traversability; the graph walk proves it. The breadth of LLM
providers (LiteLLM) therefore doesn't have to be trusted for correctness.
"""
import copy
import json
import logging
import re
from typing import Dict, List, Optional

from src import reachability
from src.entity_generator import EntityGenerator
from src.scenario_loader import ScenarioLoader, ScenarioConfigError


class AttackGenerationError(RuntimeError):
    """Raised when the LLM cannot produce a reachable attack path within the retries."""


_VALIDATION_DOMAIN = "example.com"


class AttackPathGenerator:
    """Generates a reachable chained attack path into an existing config via an LLM."""

    def __init__(self, provider, entity_generator: Optional[EntityGenerator] = None,
                 max_attempts: int = 3):
        # `provider` is any object with `.generate(system, user) -> str` (LLMProvider
        # in production; a fake in tests).
        self.provider = provider
        self.generator = entity_generator or EntityGenerator()
        self.max_attempts = max_attempts

    # -- public API -----------------------------------------------------------
    def generate_attack_paths(self, base_config: Dict, prompt: str) -> Dict:
        """(config, prompt) -> the config with verified attack_paths merged in. Raises
        AttackGenerationError if no reachable path is produced within max_attempts."""
        system = self._system_prompt(base_config)
        user = self._user_prompt(prompt)
        last_error: Optional[Exception] = None

        for attempt in range(1, self.max_attempts + 1):
            logging.info(f"Generating attack path (attempt {attempt}/{self.max_attempts})")
            raw = self.provider.generate(system, user)  # provider errors propagate
            try:
                attack_paths = self._parse(raw)
                merged = self._merge(base_config, attack_paths)
                self._validate_reachable(merged, list(attack_paths))
            except Exception as e:  # noqa: BLE001 — any failure -> feedback + retry
                last_error = e
                logging.warning(f"Attempt {attempt} invalid: {e}")
                user = self._user_prompt(prompt) + self._feedback(e, raw)
                continue
            logging.info(f"Produced a reachable attack path on attempt {attempt}.")
            return merged

        raise AttackGenerationError(
            f"Could not produce a reachable attack path after {self.max_attempts} "
            f"attempts. Last error: {last_error}"
        )

    # -- merge ----------------------------------------------------------------
    @staticmethod
    def _merge(base_config: Dict, attack_paths: Dict) -> Dict:
        """Return a deep copy of base_config with `attack_paths` added (new names only;
        a generated name that collides with an existing path is an error)."""
        merged = copy.deepcopy(base_config) if isinstance(base_config, dict) else {}
        existing = merged.get("attack_paths") or {}
        for name in attack_paths:
            if name in existing:
                raise AttackGenerationError(
                    f"generated attack path '{name}' collides with an existing path; "
                    f"use a different name.")
        existing.update(attack_paths)
        merged["attack_paths"] = existing
        return merged

    # -- validation: the reachability gate ------------------------------------
    def _validate_reachable(self, config: Dict, new_paths: List[str]) -> None:
        """Hard gate: compile the merged config and confirm every NEWLY-added attack path
        is traversable. Structural errors (dangling refs, bad roles) surface as the
        loader raising; an unreachable objective surfaces as a blocked verdict."""
        loader = ScenarioLoader(self.generator)
        scenario = loader.load(config, tenant_id="generate",
                               domain=_VALIDATION_DOMAIN, subscription_id="generate",
                               enforce_reachability=False)
        by_name = {ov.name: ov for ov in scenario.attack_paths}
        for name in new_paths:
            ov = by_name.get(name)
            if ov is None:
                raise AttackGenerationError(f"attack path '{name}' did not compile.")
            status = (ov.reachability or {}).get("status")
            if status not in (reachability.REACHED, reachability.UNVERIFIED):
                reason = (ov.reachability or {}).get("reason", "objective not reachable")
                raise AttackGenerationError(f"path '{name}' is not reachable: {reason}")

    # -- JSON extraction (mirrors org_generator._parse_design) ----------------
    @staticmethod
    def _parse(raw: str) -> Dict:
        """Extract the attack_paths mapping from the model's reply (tolerating ```json
        fences and surrounding prose). Accepts either a bare {name: path,...} mapping or
        an object wrapping it under an `attack_paths` key."""
        if not raw or not raw.strip():
            raise AttackGenerationError("LLM returned an empty response.")
        text = raw.strip()
        fence = re.search(r"```(?:json)?\s*(.*?)```", text, re.DOTALL)
        if fence:
            text = fence.group(1).strip()
        if not text.startswith("{"):
            start, end = text.find("{"), text.rfind("}")
            if start == -1 or end == -1 or end <= start:
                raise AttackGenerationError("No JSON object found in the LLM response.")
            text = text[start:end + 1]
        try:
            obj = json.loads(text)
        except json.JSONDecodeError as e:
            raise AttackGenerationError(f"LLM response was not valid JSON: {e}")
        if not isinstance(obj, dict) or not obj:
            raise AttackGenerationError("attack design must be a non-empty JSON object.")
        # Unwrap an `attack_paths:` envelope if present.
        if set(obj) == {"attack_paths"} and isinstance(obj["attack_paths"], dict):
            obj = obj["attack_paths"]
        return obj

    # -- prompt construction --------------------------------------------------
    @staticmethod
    def _summarize_entities(base_config: Dict) -> str:
        """A compact inventory of the baseline's refs so the LLM can thread the attack
        through (or borrow) the real org."""
        baseline = (base_config or {}).get("baseline") or {}
        ids = baseline.get("identities") or {}
        res = baseline.get("resources") or {}

        def refs(items):
            return [i.get("ref") for i in (items or []) if isinstance(i, dict) and i.get("ref")]

        lines = []
        for kind in ("users", "groups", "applications", "administrative_units"):
            r = refs(ids.get(kind))
            if r:
                shown = ", ".join(r[:20]) + (" ..." if len(r) > 20 else "")
                lines.append(f"  {kind}: {shown}")
        for kind, items in res.items():
            r = refs(items)
            if r:
                lines.append(f"  {kind}: {', '.join(r)}")
        return "\n".join(lines) or "  (baseline has no declared entities)"

    @classmethod
    def _system_prompt(cls, base_config: Dict) -> str:
        return (
            "You design realistic, multi-hop privilege-escalation ATTACK PATHS for an "
            "authorized BadZure security lab. Given an existing org config and a goal, you "
            "author a chained `attack_paths` block that a deterministic reachability gate "
            "confirms is actually traversable.\n\n"
            "Return ONLY a single JSON object mapping each path name to its spec — no "
            "markdown, no prose, no comments.\n\n"
            "EXISTING BASELINE ENTITIES you may thread through (borrow one with "
            "`{\"ref\": \"x\", \"from\": \"baseline\"}`, which binds to a real baseline "
            "entity of that kind):\n"
            f"{cls._summarize_entities(base_config)}\n\n"
            "A chained path is a JSON object with these keys:\n"
            "  - objective: {name, capability, role|target_ref, impact, description}. "
            "capability is the goal, e.g. `entra_role` (+ role: \"Global Administrator\") "
            "or a resource-access capability (+ target_ref).\n"
            "  - initial_access: {method: \"compromised_identity\", principal_ref: <ref>} "
            "— the starting foothold (a user/SP you declare inline or borrow from baseline).\n"
            "  - identities: {users:[{ref}], applications:[{ref}], groups:[{ref}], "
            "administrative_units:[{ref}]} — entities the path uses, declared inline (or "
            "borrow with from: baseline).\n"
            "  - resources: {resource_groups:[{ref,location}], key_vaults:[{ref,"
            "resource_group}], storage_accounts:[...], cosmos_dbs:[...], virtual_machines:"
            "[...], logic_apps:[...], automation_accounts:[...], function_apps:[...]}.\n"
            "  - assignments: the chain. Each is {id, type, ...}. type is one of: "
            "entra_role (principal_ref, role), azure_rbac (principal_ref, role, scope_ref; "
            "for a managed identity add principal_type: managed_identity + mi_source: "
            "vm|logic_app|automation_account|function_app), api_permission (principal_ref, "
            "api_type: graph, app_role), group_membership (principal_ref, group_ref), "
            "group_ownership (principal_ref, group_ref), app_ownership (principal_ref, "
            "app_ref), au_membership (principal_ref, au_ref).\n"
            "  - credentials: [{ref, app_ref, type: password}] — creds minted on an app.\n"
            "  - data_injects: [{id, material: app_secret, credential_ref, location: "
            "key_vault_secret|storage_blob|cosmos_document, location_ref, name}] — a planted "
            "secret an attacker loots to control the NEXT app.\n\n"
            "HOW HOPS CHAIN (the gate enforces this):\n"
            "  - own an app -> mint a credential -> authenticate as that service principal.\n"
            "  - own/are a member of a group -> wield the roles/RBAC the group holds.\n"
            "  - control a resource (azure_rbac control role) -> run as its managed identity.\n"
            "  - an MI with a read role on a Key Vault/storage/Cosmos loots a planted secret "
            "(data_inject) -> becomes the next app. Identity -> resource -> identity pivot.\n"
            "  - the FINAL controlled principal must hold the objective (e.g. the Entra role).\n\n"
            "RULES:\n"
            "  - Every hop must be derivable from initial_access forward; name the "
            "ownership/RBAC grant that confers each step — never skip it.\n"
            "  - One planted secret per store: give each MI a read role scoped to a SINGLE "
            "resource, and put each looted secret in its OWN vault/storage/cosmos.\n"
            "  - Reference real Entra role / Graph permission NAMES and Azure RBAC role names.\n"
            "  - Resource refs become REAL Azure names: key_vault 3-24 lowercase "
            "letters/digits/hyphens; storage_account 3-24 lowercase letters/digits only.\n"
            "  - Prefer realistic misconfigurations (a help-desk group that owns an app; an "
            "over-permissioned CI service principal) over contrived puzzles.\n"
            "  - Make the chain reach the stated goal in roughly the requested number of hops."
        )

    @staticmethod
    def _user_prompt(prompt: str) -> str:
        return (f"Design this attack path:\n\n{prompt}\n\n"
                "Return the attack_paths JSON now.")

    @staticmethod
    def _feedback(error: Exception, raw: str) -> str:
        return (
            "\n\nYour previous response was REJECTED by the deterministic reachability gate "
            f"with this error:\n{error}\n\n"
            "The error names where the chain breaks. Insert the missing hop (usually an "
            "app_ownership/group_ownership or an azure_rbac grant) or re-route, and return a "
            "corrected attack_paths JSON. Return ONLY the JSON.")
