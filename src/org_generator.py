"""
org_generator.py — turn a natural-language prompt into a realistic, DEPLOYABLE
declarative org-baseline config.

The flow (locked decision #1, Hybrid):
    prompt
      -> LLM emits a compact ORG DESIGN (departments+headcounts, explicit
         groups/SPs/resources/RBAC) — NOT the full IR
      -> a deterministic COMPILER expands it into the explicit-baseline IR
         (named users with realistic names + department-group memberships, ...)
      -> VALIDATE the compiled config (scenario_validator + a loader/build_tfvars
         dry-run); on failure feed the error back to the LLM and RETRY
      -> return a reviewable declarative config the existing `build` deploys.

The LLM never touches Terraform or the IR's referential details directly — the
compiler owns expansion and the deterministic validator is the reliability gate, so
the breadth of providers (LiteLLM) doesn't have to be trusted for structure.

Built composable / layer-aware (decision #8): `generate_baseline` is one layer over
a shared config dict; the attack-path layer (`--attack-prompt`) is a second function
(`attack_generator.AttackPathGenerator`) that reads an existing baseline and authors a
reachability-verified chain into it.
"""
import json
import logging
import random
import re
import string
from typing import Dict, List, Optional

from src import vocabulary
from src import scenario_validator
from src.entity_generator import EntityGenerator
from src.scenario_loader import ScenarioLoader
from src.terraform_builder import build_tfvars


class OrgGenerationError(RuntimeError):
    """Raised when the LLM cannot produce a valid org config within the retries."""


# Domain used only to dry-run the loader during validation; the real tenant/domain
# is resolved at `build` time from env/config.
_VALIDATION_DOMAIN = "example.com"


class OrgGenerator:
    """Generates a declarative org-baseline config from a prompt via an LLM."""

    def __init__(self, provider, entity_generator: Optional[EntityGenerator] = None,
                 max_attempts: int = 3):
        # `provider` is any object with `.generate(system, user) -> str` (LLMProvider
        # in production; a fake in tests).
        self.provider = provider
        self.generator = entity_generator or EntityGenerator()
        self.max_attempts = max_attempts

    # -- public API -----------------------------------------------------------
    def generate_baseline(self, prompt: str) -> Dict:
        """Prompt -> validated declarative baseline config (a dict). Raises
        OrgGenerationError if no valid config is produced within max_attempts."""
        system = self._system_prompt()
        user = self._user_prompt(prompt)
        last_error: Optional[Exception] = None

        for attempt in range(1, self.max_attempts + 1):
            logging.info(f"Generating org design (attempt {attempt}/{self.max_attempts})")
            raw = self.provider.generate(system, user)  # provider errors propagate
            try:
                design = self._parse_design(raw)
                config = self.compile_design(design)
                self._validate(config)
            except Exception as e:  # noqa: BLE001 — any failure -> feedback + retry
                last_error = e
                logging.warning(f"Attempt {attempt} invalid: {e}")
                user = self._user_prompt(prompt) + self._feedback(e, raw)
                continue
            logging.info(f"Produced a valid org config on attempt {attempt}.")
            return config

        raise OrgGenerationError(
            f"Could not produce a valid org config after {self.max_attempts} "
            f"attempts. Last error: {last_error}"
        )

    # -- compiler: org design -> explicit baseline IR -------------------------
    def compile_design(self, design: Dict) -> Dict:
        """Deterministically expand an org design into the explicit-baseline IR
        (the Slice-1 config shape). Pure/offline — no LLM, no Azure."""
        if not isinstance(design, dict):
            raise OrgGenerationError("org design must be a JSON object.")

        expander = _UserExpander(self.generator)
        users_by_dept: Dict[str, List[str]] = {}
        user_refs: List[str] = []
        group_refs: List[str] = []
        seen_groups = set()
        assignments: List[Dict] = []

        def add_group(ref: str) -> None:
            if ref and ref not in seen_groups:
                seen_groups.add(ref)
                group_refs.append(ref)

        # Departments -> realistic users + a department group + memberships.
        for dept in design.get("departments") or []:
            name = dept.get("name")
            headcount = int(dept.get("headcount", 0) or 0)
            if not name or headcount <= 0:
                continue
            group_ref = dept.get("group_ref") or name
            add_group(group_ref)
            refs = expander.refs(headcount)
            users_by_dept[name] = refs
            for u in refs:
                user_refs.append(u)
                assignments.append({"type": "group_membership",
                                    "principal_ref": u, "group_ref": group_ref})

        # Extra functional groups (optional auto-membership by department).
        for g in design.get("groups") or []:
            ref = g.get("ref")
            if not ref:
                continue
            add_group(ref)
            depts = g.get("members_from") or ([g["department"]] if g.get("department") else [])
            for dept_name in depts:
                for u in users_by_dept.get(dept_name, []):
                    assignments.append({"type": "group_membership",
                                        "principal_ref": u, "group_ref": ref})

        # Service principals -> applications + their Graph perms / Azure RBAC.
        app_refs: List[str] = []
        for sp in design.get("service_principals") or []:
            ref = sp.get("ref")
            if not ref:
                continue
            app_refs.append(ref)
            for perm in sp.get("api_permissions") or []:
                assignments.append({"type": "api_permission", "principal_ref": ref,
                                    "app_role": perm, "api_type": "graph"})
            for ar in sp.get("azure_roles") or []:
                if ar.get("role") and ar.get("scope"):
                    assignments.append({"type": "azure_rbac", "principal_ref": ref,
                                        "role": ar["role"], "scope_ref": ar["scope"]})

        # Administrative units -> entities + (optional) memberships by department.
        au_refs: List[str] = []
        for au in design.get("administrative_units") or []:
            ref = au.get("ref")
            if not ref:
                continue
            au_refs.append(ref)
            for dept_name in au.get("departments") or []:
                for u in users_by_dept.get(dept_name, []):
                    assignments.append({"type": "au_membership",
                                        "principal_ref": u, "au_ref": ref})
            for g in au.get("groups") or []:  # AU members can be groups too
                assignments.append({"type": "au_membership",
                                    "principal_ref": g, "au_ref": ref})

        # Standalone RBAC + Entra-role grants. `principal` may be a group/sp ref or a
        # DEPARTMENT name (-> a representative user, since users aren't named in the
        # design). Groups/SPs pass through; the loader infers principal_type.
        for r in design.get("rbac") or []:
            if r.get("principal") and r.get("role") and r.get("scope"):
                assignments.append({"type": "azure_rbac",
                                    "principal_ref": _resolve_principal(r["principal"], users_by_dept),
                                    "role": r["role"], "scope_ref": r["scope"]})
        for er in design.get("entra_roles") or []:
            if er.get("principal") and er.get("role"):
                assignments.append({"type": "entra_role",
                                    "principal_ref": _resolve_principal(er["principal"], users_by_dept),
                                    "role": er["role"]})

        # Ownership of groups / apps (every real Entra group & app registration has
        # owners). Owner = a department's representative user or an SP (groups can't
        # own); target classified by which set it's in.
        group_set, app_set = set(group_refs), set(app_refs)
        for o in design.get("ownerships") or []:
            owner, target = o.get("owner"), o.get("target")
            if not owner or not target:
                continue
            owner_ref = _resolve_principal(owner, users_by_dept)
            if owner_ref in group_set:
                raise OrgGenerationError(
                    f"ownership owner '{owner}' is a group; owners must be a user "
                    f"(department name) or a service principal.")
            if target in group_set:
                assignments.append({"type": "group_ownership",
                                    "principal_ref": owner_ref, "group_ref": target})
            elif target in app_set:
                assignments.append({"type": "app_ownership",
                                    "principal_ref": owner_ref, "app_ref": target})
            else:
                raise OrgGenerationError(
                    f"ownership target '{target}' is not a declared group or application.")

        # SP client secrets -> baseline.credentials (passwords; certs need a file).
        credentials: List[Dict] = []
        for sp in design.get("service_principals") or []:
            ref = sp.get("ref")
            if not ref:
                continue
            for i, c in enumerate(sp.get("credentials") or []):
                credentials.append({
                    "ref": f"{ref}-secret{i}" if i else f"{ref}-secret",
                    "app_ref": ref, "type": "password",
                    "display_name": (c or {}).get("display_name", "client-secret"),
                })

        # Benign planted material -> baseline.data_injects (material=literal).
        data_injects: List[Dict] = []
        for s in design.get("secrets") or []:
            if s.get("vault") and s.get("name"):
                data_injects.append({
                    "material": "literal", "location_type": "key_vault_secret",
                    "location_ref": s["vault"], "name": s["name"],
                    "literal_value": s.get("value") or _fake_secret(),
                })
        for b in design.get("blobs") or []:
            if b.get("storage") and b.get("name"):
                data_injects.append({
                    "material": "literal", "location_type": "storage_blob",
                    "location_ref": b["storage"], "name": b["name"],
                    "literal_value": b.get("content") or _fake_secret(),
                })

        identities: Dict[str, List[Dict]] = {
            "users": [{"ref": u} for u in user_refs],
            "groups": [{"ref": g} for g in group_refs],
        }
        if app_refs:
            identities["applications"] = [{"ref": a} for a in app_refs]
        if au_refs:
            identities["administrative_units"] = [{"ref": x} for x in au_refs]

        baseline: Dict = {"identities": identities, "assignments": assignments}
        resources = design.get("resources") or {}
        if resources:
            baseline["resources"] = resources
        if credentials:
            baseline["credentials"] = credentials
        if data_injects:
            baseline["data_injects"] = data_injects

        config: Dict = {
            "tenant": {"tenant_id": None, "domain": None, "subscription_id": None},
            "baseline": baseline,
        }
        company = design.get("company")
        if company:
            config["metadata"] = {"company": company}  # human context; loader ignores it
        return config

    # -- validation -----------------------------------------------------------
    def validate(self, config: Dict) -> None:
        """Public alias for the deterministic gate — used by the offline
        `compile-baseline` command (which has no LLM provider)."""
        self._validate(config)

    def _validate(self, config: Dict) -> None:
        """Hard gate: structural validation + a full loader/build_tfvars dry-run so
        dangling refs and unresolvable role/permission names fail HERE, not at
        `terraform apply`."""
        scenario_validator.validate(config)
        loader = ScenarioLoader(self.generator)
        model = loader.load(config, tenant_id="generate",
                            domain=_VALIDATION_DOMAIN, subscription_id="generate").model
        build_tfvars(model)

    # -- prompt construction --------------------------------------------------
    @staticmethod
    def _system_prompt() -> str:
        return (
            "You design realistic but ENTIRELY FICTIONAL Microsoft Entra ID / Azure "
            "organizations for an authorized security lab. Given a description, you "
            "emit a compact JSON 'org design' that a deterministic compiler turns "
            "into a real lab tenant.\n\n"
            "Return ONLY a single JSON object — no markdown, no prose, no comments.\n\n"
            "Use ONLY the vocabulary below. Anything else will be rejected.\n\n"
            f"{vocabulary.render_for_prompt()}\n\n"
            "ORG DESIGN SCHEMA (all top-level keys optional except `departments`):\n"
            f"{_ORG_DESIGN_EXAMPLE}\n\n"
            "RULES:\n"
            "- Do NOT enumerate individual users — give each department a `headcount`; "
            "the compiler generates realistic named users and their group membership.\n"
            "- Every `ref` is a unique symbolic id. User/group/app/AU refs are also "
            "display-ish names; resource refs become REAL Azure resource names.\n"
            "- key_vault refs: 3-24 chars, lowercase letters/digits/hyphens. "
            "storage_account refs: 3-24 chars, lowercase letters/digits ONLY (no "
            "hyphens). Add a short suffix to keep them globally unique-ish.\n"
            "- Reference only role/permission NAMES from the lists above. Use Entra "
            "roles sparingly and only the low-privileged ones listed.\n"
            "- RBAC/role/ownership/AU refs must reference refs you declared (a "
            "group/user/sp ref; a resource_group/resource ref for an RBAC scope).\n"
            "- POPULATE A FULLY-WIRED ORG — a believable tenant is not just group "
            "membership. Make active use of EVERY relationship type:\n"
            "    * `entra_roles`: assign a few low-priv Entra roles to IT/security/"
            "helpdesk users AND admin groups.\n"
            "    * `rbac`: realistic Azure RBAC across resources — groups/users get "
            "Reader/Contributor on the RGs and resources their team owns; mix "
            "least-privilege with mild over-provisioning like a real org.\n"
            "    * service_principals: give the right ones `api_permissions` (Graph) "
            "and `azure_roles`, AND `credentials` (a client secret) where an app "
            "would really have one.\n"
            "    * `ownerships`: EVERY group and app registration should have an "
            "owner. `owner` is a DEPARTMENT name (a representative user from it "
            "becomes the owner) or a service-principal ref — NOT a group. `target` "
            "is a group or app ref.\n"
            "- For `rbac`/`entra_roles`, `principal` may be a group ref, a service-"
            "principal ref, or a DEPARTMENT name (resolves to a representative user).\n"
            "    * `secrets`: put a few believable (but FAKE) secrets in key vaults "
            "(e.g. db-connection-string, api-key). `blobs`: a few files in storage.\n"
            "    * administrative_units: scope by department, and optionally include "
            "department groups.\n"
            "- Make it look like the described org. Secrets/blobs must be FAKE."
        )

    @staticmethod
    def _user_prompt(prompt: str) -> str:
        return f"Design this organization:\n\n{prompt}\n\nReturn the org design JSON now."

    @staticmethod
    def _feedback(error: Exception, raw: str) -> str:
        return (
            "\n\nYour previous response was INVALID and was rejected by the "
            f"deterministic validator with this error:\n{error}\n\n"
            "Fix it and return a corrected JSON org design. Return ONLY the JSON."
        )

    # -- JSON extraction ------------------------------------------------------
    @staticmethod
    def _parse_design(raw: str) -> Dict:
        """Extract a JSON object from the model's reply (tolerating ```json fences
        and surrounding prose)."""
        if not raw or not raw.strip():
            raise OrgGenerationError("LLM returned an empty response.")
        text = raw.strip()
        # Strip a ```json ... ``` (or bare ```) fence if present.
        fence = re.search(r"```(?:json)?\s*(.*?)```", text, re.DOTALL)
        if fence:
            text = fence.group(1).strip()
        # Otherwise grab the outermost {...}.
        if not text.startswith("{"):
            start, end = text.find("{"), text.rfind("}")
            if start == -1 or end == -1 or end <= start:
                raise OrgGenerationError("No JSON object found in the LLM response.")
            text = text[start:end + 1]
        try:
            return json.loads(text)
        except json.JSONDecodeError as e:
            raise OrgGenerationError(f"LLM response was not valid JSON: {e}")


def _fake_secret() -> str:
    """A benign placeholder value for a planted KV secret / blob (fake only)."""
    return "FAKE-" + "".join(random.choices(string.ascii_letters + string.digits, k=20))


def _resolve_principal(name: str, users_by_dept: Dict[str, List[str]]) -> str:
    """Map a design `principal`/`owner` to a real ref. A DEPARTMENT name resolves to
    that department's representative (first) user — individual users aren't named in
    the org design. Group/SP refs (and anything already concrete) pass through."""
    users = users_by_dept.get(name)
    return users[0] if users else name


class _UserExpander:
    """Deterministic-ish expansion of department headcounts into unique, realistic
    `first.last` user refs, reusing EntityGenerator's name word-lists."""

    def __init__(self, generator: EntityGenerator):
        try:
            self.first = generator._read_names_from_file("first-names.txt")
            self.last = generator._read_names_from_file("last-names.txt")
        except Exception:  # noqa: BLE001 — keep generation working without the files
            self.first = ["alex", "sam", "jordan", "taylor", "casey", "morgan", "riley"]
            self.last = ["smith", "jones", "lee", "patel", "garcia", "khan", "nguyen"]
        self.used = set()

    def refs(self, n: int) -> List[str]:
        out: List[str] = []
        cap = max(n * 50, 200)
        tries = 0
        while len(out) < n and tries < cap:
            tries += 1
            ref = f"{random.choice(self.first)}.{random.choice(self.last)}".lower()
            if ref not in self.used:
                self.used.add(ref)
                out.append(ref)
        # Pool exhausted (small word-lists / huge headcount) -> numbered fallback.
        i = 1
        while len(out) < n:
            ref = f"user{i}"
            i += 1
            if ref not in self.used:
                self.used.add(ref)
                out.append(ref)
        return out


# A compact, illustrative org design embedded in the system prompt.
_ORG_DESIGN_EXAMPLE = """{
  "company": {"name": "Northwind Tech", "industry": "SaaS", "size": "small"},
  "departments": [
    {"name": "Engineering", "headcount": 12},
    {"name": "Sales", "headcount": 6},
    {"name": "Finance", "headcount": 4},
    {"name": "IT", "headcount": 3}
  ],
  "groups": [
    {"ref": "IT-Admins", "department": "IT"}
  ],
  "service_principals": [
    {"ref": "cicd-pipeline", "purpose": "CI/CD deploys",
     "api_permissions": ["User.Read.All", "Application.Read.All"],
     "azure_roles": [{"role": "Contributor", "scope": "rg-dev"}],
     "credentials": [{"display_name": "github-actions"}]},
    {"ref": "backup-service", "purpose": "nightly backups",
     "azure_roles": [{"role": "Storage Blob Data Reader", "scope": "stnwprod01"}],
     "credentials": [{}]}
  ],
  "administrative_units": [
    {"ref": "Finance-Unit", "departments": ["Finance"], "groups": ["IT-Admins"]}
  ],
  "resources": {
    "resource_groups": [
      {"ref": "rg-prod", "location": "West US 2"},
      {"ref": "rg-dev", "location": "West US 2"}
    ],
    "key_vaults": [{"ref": "kv-nwprod01", "resource_group": "rg-prod"}],
    "storage_accounts": [{"ref": "stnwprod01", "resource_group": "rg-prod"}]
  },
  "rbac": [
    {"principal": "IT-Admins", "role": "Reader", "scope": "rg-prod"},
    {"principal": "cicd-pipeline", "role": "Key Vault Secrets User", "scope": "kv-nwprod01"}
  ],
  "entra_roles": [
    {"principal": "IT-Admins", "role": "Helpdesk Administrator"}
  ],
  "ownerships": [
    {"owner": "IT", "target": "cicd-pipeline"},
    {"owner": "Engineering", "target": "Engineering"}
  ],
  "secrets": [
    {"vault": "kv-nwprod01", "name": "db-connection-string"}
  ],
  "blobs": [
    {"storage": "stnwprod01", "name": "backup-config.json"}
  ]
}"""
