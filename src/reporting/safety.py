"""Stable identifiers and safe-property helpers for report projection."""

from __future__ import annotations

import re
from typing import Any, Dict, Iterable, Mapping


FORBIDDEN_PROPERTY_NAMES = frozenset({
    "password",
    "admin_password",
    "client_secret",
    "secret_value",
    "literal_value",
    "pfx_password",
    "certificate_path",
    "file_path",
    "private_key",
    "token",
    "access_token",
    "refresh_token",
    "generic_credential_key",
})


class UnsafeReportPropertyError(ValueError):
    """Raised when code attempts to expose a forbidden report property."""


def typed_id(type_name: str, symbolic_ref: Any) -> str:
    """Return a stable graph ID without conflating type and display caption."""

    if not type_name or symbolic_ref is None or str(symbolic_ref) == "":
        raise ValueError("typed_id requires a non-empty type and symbolic reference")
    return f"{type_name}:{symbolic_ref}"


def edge_id(panel_key: str, edge_type: str, discriminator: Any) -> str:
    """Return a stable edge ID namespaced to its panel."""

    if not panel_key or not edge_type or discriminator is None:
        raise ValueError("edge_id requires panel, type, and discriminator")
    return f"{panel_key}:{edge_type}:{discriminator}"


def dom_id(value: Any, prefix: str = "panel") -> str:
    """Turn an arbitrary config/path name into a deterministic safe DOM ID."""

    token = re.sub(r"[^0-9A-Za-z_-]+", "-", str(value)).strip("-_").lower()
    return f"{prefix}-{token or 'item'}"


def safe_properties(source: Mapping[str, Any], allowed: Iterable[str]) -> Dict[str, Any]:
    """Copy an explicit allowlist from ``source`` into JSON-safe report data.

    A forbidden key is rejected even if a caller accidentally adds it to an
    allowlist.  Unknown source keys are ignored: projectors must opt fields in.
    """

    allowed_set = set(allowed)
    forbidden = {key for key in allowed_set if key.lower() in FORBIDDEN_PROPERTY_NAMES}
    if forbidden:
        raise UnsafeReportPropertyError(
            "Report allowlist contains forbidden field(s): " + ", ".join(sorted(forbidden))
        )

    result: Dict[str, Any] = {}
    for key in allowed_set:
        if key in source and source[key] is not None:
            result[key] = _json_safe(source[key], key)
    return result


def _json_safe(value: Any, path: str) -> Any:
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    if isinstance(value, (list, tuple)):
        return [_json_safe(item, f"{path}[]") for item in value]
    if isinstance(value, Mapping):
        forbidden = {str(key) for key in value if str(key).lower() in FORBIDDEN_PROPERTY_NAMES}
        if forbidden:
            raise UnsafeReportPropertyError(
                f"Report property '{path}' contains forbidden nested field(s): "
                + ", ".join(sorted(forbidden))
            )
        return {str(k): _json_safe(v, f"{path}.{k}") for k, v in value.items()}
    raise UnsafeReportPropertyError(
        f"Report property '{path}' has unsupported value type {type(value).__name__}"
    )
