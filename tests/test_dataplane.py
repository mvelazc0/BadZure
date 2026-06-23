"""
test_dataplane.py — offline test of the Python post-apply data-plane phase.

Exercises the PURE parts of src/dataplane.py (no Azure): collecting cosmos_document
injects from a model, resolving each material's concrete value from Terraform
outputs / local files / literals, and shaping the Cosmos document. The azure-cosmos
upsert in execute() is the live acceptance step, not covered here.

Runs two ways:
    python tests/test_dataplane.py
    pytest tests/test_dataplane.py
"""
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.primitives import (  # noqa: E402
    DeploymentModel, DataInject, AppCredential, ATTACK_PATH,
)
import src.dataplane as dataplane  # noqa: E402


def _cosmos(pk="/id"):
    return {"cos01": {"name": "cos01", "location": "West US",
                      "resource_group_name": "rg1", "database_name": "cos01-db",
                      "container_name": "cos01-container", "partition_key_path": pk}}


def _model(primitives, pk="/id"):
    return DeploymentModel(
        domain="contoso.com", applications={"app_hp": {"display_name": "app_hp"}},
        cosmos_dbs=_cosmos(pk), primitives=primitives)


# --- collect_dataplane_injects ----------------------------------------------
def test_collect_only_dataplane_injects():
    primitives = [
        DataInject("kv", ATTACK_PATH, material="app_secret",
                   location_type="key_vault_secret", location_ref="kv01",
                   name="s", credential_ref="c"),
        DataInject("cos", ATTACK_PATH, material="literal",
                   location_type="cosmos_document", location_ref="cos01",
                   name="seed", literal_value="{}"),
    ]
    items = dataplane.collect_dataplane_injects(_model(primitives))
    # the KV inject (a Terraform resource) is ignored; only cosmos_document is taken
    assert len(items) == 1 and items[0].inject.key == "cos"
    assert items[0].database_name == "cos01-db"
    assert items[0].container_name == "cos01-container"
    assert items[0].partition_key_path == "/id"


def test_collect_unknown_account_raises():
    primitives = [DataInject("cos", ATTACK_PATH, material="literal",
                             location_type="cosmos_document", location_ref="nope",
                             name="seed", literal_value="{}")]
    try:
        dataplane.collect_dataplane_injects(_model(primitives))
        assert False, "expected KeyError for unknown cosmos ref"
    except KeyError:
        pass


# --- resolve_value (one per material) ---------------------------------------
def test_resolve_literal():
    inj = DataInject("d", ATTACK_PATH, material="literal",
                     location_type="cosmos_document", location_ref="cos01",
                     name="seed", literal_value='{"note":"hi"}')
    assert dataplane.resolve_value(inj, {}, {}) == '{"note":"hi"}'


def test_resolve_app_client_id():
    inj = DataInject("d", ATTACK_PATH, material="app_client_id",
                     location_type="cosmos_document", location_ref="cos01",
                     name="id", source_ref="app_hp")
    outputs = {"application_client_ids": {"app_hp": "1111-2222"}}
    assert dataplane.resolve_value(inj, outputs, {}) == "1111-2222"


def test_resolve_app_secret_uses_origin_prefixed_key():
    cred = AppCredential("app_hp_secret", ATTACK_PATH, app_ref="app_hp", type="password")
    inj = DataInject("d", ATTACK_PATH, material="app_secret",
                     location_type="cosmos_document", location_ref="cos01",
                     name="sec", credential_ref="app_hp_secret")
    model = _model([cred, inj])
    cred_origin = dataplane.credential_origin_map(model)
    # output is keyed by the origin-prefixed credential key, like generic.tf
    outputs = {"generic_app_credentials": {"ap:app_hp_secret": {"client_secret": "S3cr3t"}}}
    assert dataplane.resolve_value(inj, outputs, cred_origin) == "S3cr3t"


def test_resolve_app_certificate_reads_file_relative_to_tf_dir():
    with tempfile.TemporaryDirectory() as d:
        with open(os.path.join(d, "cert.pem"), "w") as f:
            f.write("-----BEGIN CERT-----\nXYZ\n-----END CERT-----\n")
        inj = DataInject("d", ATTACK_PATH, material="app_certificate",
                         location_type="cosmos_document", location_ref="cos01",
                         name="cert", source_ref="app_hp", file_path="cert.pem")
        out = dataplane.resolve_value(inj, {}, {}, terraform_dir=d)
        assert out.startswith("-----BEGIN CERT-----")


def test_resolve_missing_secret_output_raises():
    cred = AppCredential("c", ATTACK_PATH, app_ref="app_hp", type="password")
    inj = DataInject("d", ATTACK_PATH, material="app_secret",
                     location_type="cosmos_document", location_ref="cos01",
                     name="sec", credential_ref="c")
    cred_origin = dataplane.credential_origin_map(_model([cred, inj]))
    try:
        dataplane.resolve_value(inj, {"generic_app_credentials": {}}, cred_origin)
        assert False, "expected KeyError for missing credential output"
    except KeyError:
        pass


# --- build_document ----------------------------------------------------------
def test_build_document_default_partition_key():
    inj = DataInject("d", ATTACK_PATH, material="literal",
                     location_type="cosmos_document", location_ref="cos01",
                     name="doc1", literal_value="v")
    item = dataplane.collect_dataplane_injects(_model([inj]))[0]
    # /id partition key: the pk field IS id, so just {id, content}
    assert dataplane.build_document(item, "the-value") == {"id": "doc1", "content": "the-value"}


def test_build_document_custom_partition_key():
    inj = DataInject("d", ATTACK_PATH, material="literal",
                     location_type="cosmos_document", location_ref="cos01",
                     name="doc1", literal_value="v")
    item = dataplane.collect_dataplane_injects(_model([inj], pk="/pk"))[0]
    # non-/id partition key becomes its own field, populated with the doc id
    assert dataplane.build_document(item, "the-value") == \
        {"id": "doc1", "pk": "doc1", "content": "the-value"}


# --- execute -----------------------------------------------------------------
def test_execute_empty_is_noop():
    res = dataplane.execute([], {}, _model([]))
    assert res.planted == 0 and res.failures == []


def _main():
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
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
