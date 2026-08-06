"""
test_org_generator.py — offline test of the LLM org-baseline generator (Slice 2).

Drives the REAL OrgGenerator with a FAKE provider (canned org-design JSON — no
network, no API key). Asserts:
  - the compiler expands departments into the right number of named users + their
    department-group memberships, and compiles SPs/RBAC/entra-roles/resources/AUs
  - the compiled config passes the deterministic gate (scenario_validator + a full
    loader/build_tfvars dry-run)
  - the validate->retry loop re-prompts with error feedback on bad output and
    eventually succeeds, and raises OrgGenerationError when it can't
  - importing src.cli (the generate command) does NOT require litellm

Runs two ways:
    python tests/test_org_generator.py
    pytest tests/test_org_generator.py
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.entity_generator import EntityGenerator  # noqa: E402
from src.org_generator import OrgGenerator, OrgGenerationError  # noqa: E402
from src import scenario_validator  # noqa: E402

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _gen():
    return EntityGenerator(data_dir=os.path.join(_REPO, "entity_data"))


class _FakeProvider:
    """Returns canned responses in order; records the prompts it was called with."""

    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def generate(self, system, user):
        self.calls.append({"system": system, "user": user})
        return self.responses.pop(0)


# A known-good org design (small headcounts so users are easy to count).
_DESIGN = {
    "company": {"name": "Acme Labs", "industry": "SaaS", "size": "small"},
    "departments": [
        {"name": "Engineering", "headcount": 3},
        {"name": "Sales", "headcount": 2},
        {"name": "IT", "headcount": 1},
    ],
    "groups": [
        {"ref": "IT-Admins", "department": "IT"},
    ],
    "service_principals": [
        {"ref": "cicd-pipeline",
         "api_permissions": ["User.Read.All"],
         "azure_roles": [{"role": "Contributor", "scope": "rg-dev"}]},
        {"ref": "backup-service",
         "azure_roles": [{"role": "Storage Blob Data Reader", "scope": "stacme01"}]},
    ],
    "administrative_units": [
        {"ref": "Finance-Unit", "departments": ["Sales"]},
    ],
    "resources": {
        "resource_groups": [
            {"ref": "rg-prod", "location": "East US"},
            {"ref": "rg-dev", "location": "East US"},
        ],
        "key_vaults": [{"ref": "kv-acme01", "resource_group": "rg-prod"}],
        "storage_accounts": [{"ref": "stacme01", "resource_group": "rg-prod"}],
    },
    "rbac": [
        {"principal": "IT-Admins", "role": "Reader", "scope": "rg-prod"},
    ],
    "entra_roles": [
        {"principal": "IT-Admins", "role": "Helpdesk Administrator"},
    ],
}

_TOTAL_USERS = 3 + 2 + 1


# ---------------------------------------------------------------------------
# Compiler
# ---------------------------------------------------------------------------
def test_compiler_expands_departments_into_users():
    og = OrgGenerator(_FakeProvider([]), _gen())
    config = og.compile_design(_DESIGN)
    ids = config["baseline"]["identities"]

    users = [u["ref"] for u in ids["users"]]
    assert len(users) == _TOTAL_USERS
    assert len(set(users)) == _TOTAL_USERS          # unique
    assert all("." in u for u in users)              # realistic first.last refs

    groups = {g["ref"] for g in ids["groups"]}
    assert {"Engineering", "Sales", "IT", "IT-Admins"} <= groups
    assert {a["ref"] for a in ids["applications"]} == {"cicd-pipeline", "backup-service"}
    assert {a["ref"] for a in ids["administrative_units"]} == {"Finance-Unit"}


def test_compiler_emits_expected_assignments():
    og = OrgGenerator(_FakeProvider([]), _gen())
    a = config_assignments(og.compile_design(_DESIGN))

    # one department membership per user, + 1 functional (the single IT user -> IT-Admins)
    gm = [x for x in a if x["type"] == "group_membership"]
    assert len(gm) == _TOTAL_USERS + 1
    assert any(x["type"] == "api_permission" and x["app_role"] == "User.Read.All" for x in a)
    assert any(x["type"] == "azure_rbac" and x["scope_ref"] == "rg-dev" for x in a)
    assert any(x["type"] == "azure_rbac" and x["scope_ref"] == "stacme01" for x in a)
    assert any(x["type"] == "entra_role" and x["principal_ref"] == "IT-Admins" for x in a)
    # AU membership for the 2 Sales users
    assert len([x for x in a if x["type"] == "au_membership"]) == 2


def test_compiled_config_passes_the_gate():
    og = OrgGenerator(_FakeProvider([]), _gen())
    config = og.compile_design(_DESIGN)
    og._validate(config)  # scenario_validator + loader + build_tfvars; raises on failure


def config_assignments(config):
    return config["baseline"]["assignments"]


# A design that exercises the full substrate: ownership, SP secrets, KV secrets,
# storage blobs, groups-as-AU-members.
_RICH_DESIGN = dict(_DESIGN)
_RICH_DESIGN["service_principals"] = [
    {"ref": "cicd-pipeline", "api_permissions": ["User.Read.All"],
     "azure_roles": [{"role": "Contributor", "scope": "rg-dev"}],
     "credentials": [{"display_name": "gh-actions"}]},
]
_RICH_DESIGN["ownerships"] = [
    {"owner": "IT", "target": "cicd-pipeline"},        # dept user owns the SP
    {"owner": "Engineering", "target": "Engineering"},  # dept user owns the group
]
_RICH_DESIGN["secrets"] = [{"vault": "kv-acme01", "name": "db-connection-string"}]
_RICH_DESIGN["blobs"] = [{"storage": "stacme01", "name": "config.json"}]
_RICH_DESIGN["administrative_units"] = [
    {"ref": "Finance-Unit", "departments": ["Sales"], "groups": ["IT-Admins"]},
]


def test_rich_design_compiles_all_primitive_kinds():
    og = OrgGenerator(_FakeProvider([]), _gen())
    config = og.compile_design(_RICH_DESIGN)
    a = config["baseline"]["assignments"]
    types = {x["type"] for x in a}
    assert {"group_ownership", "app_ownership", "au_membership", "entra_role",
            "azure_rbac", "api_permission", "group_membership"} <= types
    # SP secret -> baseline.credentials; KV secret + blob -> baseline.data_injects
    assert config["baseline"]["credentials"][0]["app_ref"] == "cicd-pipeline"
    injects = config["baseline"]["data_injects"]
    assert {d["location_type"] for d in injects} == {"key_vault_secret", "storage_blob"}
    assert all(d["material"] == "literal" for d in injects)
    # ownership owners resolved to real principals (dept -> a user, not the dept name)
    owns = [x for x in a if x["type"] in ("group_ownership", "app_ownership")]
    assert owns and all("." in o["principal_ref"] or o["principal_ref"] in
                        {"cicd-pipeline"} for o in owns)


def test_rich_design_passes_the_gate():
    og = OrgGenerator(_FakeProvider([]), _gen())
    og._validate(og.compile_design(_RICH_DESIGN))


def test_group_cannot_be_an_owner():
    bad = dict(_DESIGN)
    bad["ownerships"] = [{"owner": "IT-Admins", "target": "cicd-pipeline"}]
    og = OrgGenerator(_FakeProvider([]), _gen())
    try:
        og.compile_design(bad)
    except OrgGenerationError as e:
        assert "group" in str(e).lower()
        return
    raise AssertionError("expected OrgGenerationError for a group owner")


# ---------------------------------------------------------------------------
# generate_baseline (provider + parsing + retry)
# ---------------------------------------------------------------------------
def test_generate_baseline_happy_path():
    provider = _FakeProvider([json.dumps(_DESIGN)])
    og = OrgGenerator(provider, _gen())
    config = og.generate_baseline("a small SaaS startup")
    assert "baseline" in config and "schema" not in config
    assert len(config["baseline"]["identities"]["users"]) == _TOTAL_USERS
    assert len(provider.calls) == 1


def test_generate_baseline_strips_code_fences():
    fenced = "Here you go:\n```json\n" + json.dumps(_DESIGN) + "\n```\n"
    og = OrgGenerator(_FakeProvider([fenced]), _gen())
    config = og.generate_baseline("startup")
    assert len(config["baseline"]["identities"]["users"]) == _TOTAL_USERS


def test_generate_baseline_retries_with_feedback():
    # First response is junk; second is valid -> succeeds on attempt 2 with feedback.
    provider = _FakeProvider(["not json at all", json.dumps(_DESIGN)])
    og = OrgGenerator(provider, _gen(), max_attempts=3)
    config = og.generate_baseline("startup")
    assert "baseline" in config and "schema" not in config
    assert len(provider.calls) == 2
    assert "INVALID" in provider.calls[1]["user"]  # error fed back on the retry


def test_generate_baseline_exhausts_and_raises():
    provider = _FakeProvider(["garbage", "still garbage", "nope"])
    og = OrgGenerator(provider, _gen(), max_attempts=3)
    try:
        og.generate_baseline("startup")
    except OrgGenerationError:
        assert len(provider.calls) == 3
        return
    raise AssertionError("expected OrgGenerationError after exhausting attempts")


def test_invalid_role_name_is_rejected_and_retried():
    bad = json.loads(json.dumps(_DESIGN))
    bad["entra_roles"] = [{"principal": "IT-Admins", "role": "Supreme Overlord"}]
    provider = _FakeProvider([json.dumps(bad), json.dumps(_DESIGN)])
    og = OrgGenerator(provider, _gen(), max_attempts=3)
    config = og.generate_baseline("startup")
    assert len(provider.calls) == 2  # bad role name forced a retry
    assert "baseline" in config and "schema" not in config


# ---------------------------------------------------------------------------
# Import guard: the CLI must import without litellm installed.
# ---------------------------------------------------------------------------
def test_cli_imports_without_litellm():
    import importlib
    cli = importlib.import_module("src.cli")
    assert hasattr(cli, "GenerateCommand")


def _main():
    tests = [v for k, v in sorted(globals().items())
             if k.startswith("test_") and callable(v)]
    failed = 0
    for t in tests:
        try:
            t()
            print(f"PASS  {t.__name__}")
        except AssertionError as e:
            failed += 1
            print(f"FAIL  {t.__name__}: {e}")
        except Exception as e:  # noqa: BLE001
            failed += 1
            print(f"ERROR {t.__name__}: {type(e).__name__}: {e}")
    print(f"\n{len(tests) - failed}/{len(tests)} passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(_main())
