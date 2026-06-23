"""
dataplane.py — the Python post-apply data-plane phase.

Some attack-path material can't be planted by Terraform: the azurerm provider has
no resource to write a Cosmos DB item, and the same is true for the data-plane and
Graph operations BadZure will grow into (OneDrive/SharePoint content, SQL rows,
license assignment, mail). Rather than shell those out of Terraform one by one,
this module is a dedicated phase that runs AFTER `terraform apply`: it reads what
it needs from Terraform outputs, then performs the imperative API calls directly.

Today it implements exactly one location_type — `cosmos_document` — but the shape
is built to extend: `collect_dataplane_injects` gathers every DataInject whose
location_type is data-plane-only (see DATAPLANE_LOCATION_TYPES), and `execute`
dispatches by location_type. A future onedrive_file / sql_row inject adds a
collector branch + an executor function; nothing else moves.

Split for testing: `collect_dataplane_injects`, `resolve_value`, and
`build_document` are pure (no Azure, fully offline-testable). Only `execute`
touches the SDK, and it lazy-imports `azure-cosmos` so labs without cosmos_document
injects never need the package.
"""
import logging
import os
from dataclasses import dataclass
from typing import Dict, List, Optional

from src.primitives import DataInject, DeploymentModel
from src.primitive_handlers import DATAPLANE_LOCATION_TYPES
from src.terraform_builder import origin_prefixed_key, credential_origin_map


# =============================================================================
# Planning (pure) — gather data-plane injects and resolve their concrete values.
# =============================================================================
@dataclass
class DataPlaneItem:
    """One data-plane inject plus the resolved coordinates of its target. For a
    cosmos_document inject the coordinates come from the model's cosmos_dbs entity
    map (the same symbolic ref the inject's location_ref points at)."""
    inject: DataInject
    account_ref: str
    database_name: str
    container_name: str
    partition_key_path: str


def collect_dataplane_injects(model: DeploymentModel) -> List[DataPlaneItem]:
    """Every DataInject in the model whose location_type is data-plane-only (has no
    Terraform resource), paired with its target's coordinates. Order-preserving."""
    items: List[DataPlaneItem] = []
    for p in model.primitives:
        if not isinstance(p, DataInject):
            continue
        if p.location_type not in DATAPLANE_LOCATION_TYPES:
            continue
        if p.location_type == "cosmos_document":
            acct = model.cosmos_dbs.get(p.location_ref)
            if acct is None:
                # build_tfvars ref-validation should have caught this already.
                raise KeyError(
                    f"DataInject '{p.key}': cosmos_document location_ref "
                    f"'{p.location_ref}' is not a declared cosmos_db."
                )
            items.append(DataPlaneItem(
                inject=p,
                account_ref=p.location_ref,
                database_name=acct["database_name"],
                container_name=acct["container_name"],
                partition_key_path=acct["partition_key_path"],
            ))
    return items


def resolve_value(inject: DataInject, outputs: Dict, cred_origin: Dict[str, str],
                  terraform_dir: str = "") -> str:
    """The concrete string to plant, by material:
      literal          -> literal_value (verbatim)
      app_certificate  -> the PEM/key file contents (file_path is relative to the
                          terraform dir, where crypto.py writes the certs)
      app_secret       -> the minted client secret, looked up in the
                          generic_app_credentials TF output by the SAME
                          origin-prefixed key the builder writes
      app_client_id    -> the application's client id, from application_client_ids
    """
    material = inject.material
    if material == "literal":
        return inject.literal_value or ""
    if material == "app_certificate":
        path = inject.file_path or ""
        if terraform_dir and not os.path.isabs(path):
            path = os.path.join(terraform_dir, path)
        with open(path, "r") as f:
            return f.read()
    if material == "app_secret":
        bare = inject.credential_ref or ""
        origin = cred_origin.get(bare)
        if origin is None:
            raise KeyError(
                f"DataInject '{inject.key}': credential_ref '{bare}' names no "
                f"declared app_credential."
            )
        key = origin_prefixed_key(bare, origin)
        creds = outputs.get("generic_app_credentials") or {}
        entry = creds.get(key)
        if not entry:
            raise KeyError(
                f"DataInject '{inject.key}': no generic_app_credentials output for "
                f"'{key}' (was the app credential created?)."
            )
        return entry.get("client_secret", "")
    if material == "app_client_id":
        ids = outputs.get("application_client_ids") or {}
        client_id = ids.get(inject.source_ref or "")
        if client_id is None:
            raise KeyError(
                f"DataInject '{inject.key}': no application_client_ids output for "
                f"source_ref '{inject.source_ref}'."
            )
        return client_id
    raise ValueError(f"DataInject '{inject.key}': unknown material '{material}'.")


def build_document(item: DataPlaneItem, value: str) -> Dict:
    """The Cosmos document to upsert: {id, <partition-key field>, content}. The
    partition-key field is whatever partition_key_path names (BadZure defaults to
    /id), so any single-path partition key works."""
    pk_field = (item.partition_key_path or "/id").lstrip("/") or "id"
    doc_id = item.inject.name
    return {"id": doc_id, pk_field: doc_id, "content": value}


# =============================================================================
# Execution (touches Azure) — upsert each planned document via azure-cosmos.
# =============================================================================
@dataclass
class DataPlaneResult:
    """Per-run summary the build flow reports. Failures never abort the build or
    taint Terraform state — they're logged per inject and counted here."""
    planted: int = 0
    failures: List[str] = None  # human-readable "<key>: <reason>" lines

    def __post_init__(self):
        if self.failures is None:
            self.failures = []


def execute(items: List[DataPlaneItem], outputs: Dict, model: DeploymentModel,
            terraform_dir: str = "") -> DataPlaneResult:
    """Plant every collected data-plane inject. Warn-and-continue: a single failure
    is logged and recorded, the rest still run, and the build proceeds. Returns a
    DataPlaneResult summary."""
    result = DataPlaneResult()
    if not items:
        return result

    try:
        from azure.cosmos import CosmosClient  # lazy: only needed for cosmos injects
    except ImportError:
        msg = ("the 'azure-cosmos' package is required to plant cosmos_document "
               "injects. Install it into the BadZure venv: pip install azure-cosmos")
        logging.error(f"Data-plane phase skipped: {msg}")
        result.failures = [f"{it.inject.key}: {msg}" for it in items]
        return result

    # The Azure SDK's HTTP logging policy emits every request/response (URLs,
    # headers, status) and propagates to the root logger — far too noisy for the
    # build output. Quiet the whole 'azure' logger tree to WARNING.
    logging.getLogger("azure").setLevel(logging.WARNING)

    cred_origin = credential_origin_map(model)
    connections = outputs.get("cosmos_db_connections") or {}
    # Cache one container client per (account, db, container) so we connect once.
    container_clients: Dict[tuple, object] = {}

    for item in items:
        inject = item.inject
        try:
            conn = connections.get(item.account_ref)
            if not conn:
                raise KeyError(
                    f"no cosmos_db_connections output for account "
                    f"'{item.account_ref}'."
                )
            cache_key = (item.account_ref, item.database_name, item.container_name)
            container = container_clients.get(cache_key)
            if container is None:
                client = CosmosClient(conn["endpoint"], credential=conn["primary_key"])
                container = (client
                             .get_database_client(item.database_name)
                             .get_container_client(item.container_name))
                container_clients[cache_key] = container

            value = resolve_value(inject, outputs, cred_origin, terraform_dir)
            container.upsert_item(build_document(item, value))
            result.planted += 1
            logging.info(
                f"  planted Cosmos document '{inject.name}' in "
                f"{item.database_name}/{item.container_name}")
        except Exception as e:  # noqa: BLE001 — warn-and-continue per inject
            reason = str(e)
            result.failures.append(f"{inject.key}: {reason}")
            logging.warning(
                f"  failed to plant Cosmos document '{inject.name}' "
                f"({inject.key}): {reason}")

    return result
