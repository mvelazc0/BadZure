"""
scenario_validator.py — fail-fast validation for the declarative graph config (Slice 5).

The scenario loader and Terraform builder already enforce *referential* integrity
(a `principal_ref` must resolve to a real entity, a role name must resolve to a
GUID, ...). This module sits IN FRONT of them and catches the structural mistakes
that are cheaper to report up front and all at once: a malformed objective, an
unknown assignment `type`, a `step` that links to an id that doesn't exist.

It is intentionally REGISTRY-DRIVEN — it validates `type`/`capability` tokens
against the same vocabularies the rest of the system uses
(`scenario_loader.ASSIGNMENT_TYPES`, `capabilities.KNOWN_CAPABILITIES`) rather
than re-listing them — so a new assignment type or capability is validated the
moment it's registered, with no edit here.

Design choices that keep it from fighting the loader:
  - It AGGREGATES problems and raises ONE `ScenarioConfigError` listing them all,
    so the operator fixes everything in one pass.
  - `objective` is treated as RECOMMENDED, not required: a path without one draws a
    warning (the reachability gate can't validate it), not a hard failure — many
    legitimate partial configs (and the Slice 1–3 fixtures) omit it.
  - It does NOT re-implement type/scope inference or ref resolution; those stay the
    loader's job and surface their own (already-clear) errors. This validator only
    owns what it can decide from the raw YAML alone.
"""
import logging
from typing import Dict, List

from src import capabilities
from src.scenario_loader import ScenarioConfigError, ASSIGNMENT_TYPES

# Per-capability required objective fields (beyond the human-facing name/impact).
# Capabilities not listed here (e.g. read_mail) need nothing extra.
_TARGET_REF_CAPABILITIES = set(capabilities.READ_CAPABILITY_RESOURCE) | {
    "code_execution", "control_principal",
}


def validate(config: Dict) -> None:
    """Validate the declarative config's `baseline` and `attack_paths` sections.
    Raises ScenarioConfigError (aggregating every problem found) on a hard error;
    logs warnings for soft issues."""
    attack_paths = config.get("attack_paths") or {}
    if not isinstance(attack_paths, dict):
        raise ScenarioConfigError("`attack_paths` must be a mapping of name -> path.")

    errors: List[str] = []
    warnings: List[str] = []

    _validate_baseline(config.get("baseline"), errors)
    for name, path in attack_paths.items():
        _validate_path(str(name), path, errors, warnings)

    for w in warnings:
        logging.warning(f"Declarative config: {w}")
    if errors:
        raise ScenarioConfigError(
            f"Declarative config has {len(errors)} problem(s):\n"
            + "\n".join(f"  - {e}" for e in errors)
        )


def _validate_baseline(baseline, errors: List[str]) -> None:
    """Validate the EXPLICIT (list-of-specs) baseline forms: each declared
    identity/resource has a unique `ref`, and each explicit assignment has a known
    `type` and a `principal_ref`. Count-form kinds (integers) and a None baseline
    are no-ops here — they carry nothing to check structurally."""
    if baseline is None:
        return
    if not isinstance(baseline, dict):
        errors.append("`baseline` must be a mapping.")
        return

    refs = set()
    for section in ("identities", "resources"):
        block = baseline.get(section)
        if block is None:
            continue
        if not isinstance(block, dict):
            errors.append(f"baseline.{section} must be a mapping.")
            continue
        for kind, val in block.items():
            if not isinstance(val, list):
                continue  # count form (int) — nothing structural to validate
            for i, spec in enumerate(val):
                if not isinstance(spec, dict):
                    errors.append(
                        f"baseline.{section}.{kind}[{i}] must be a mapping with a `ref`.")
                    continue
                ref = spec.get("ref")
                if not ref:
                    errors.append(
                        f"baseline.{section}.{kind}[{i}] is missing a required `ref`.")
                    continue
                if ref in refs:
                    errors.append(f"baseline: duplicate entity ref '{ref}'.")
                refs.add(ref)

    assignments = baseline.get("assignments")
    if isinstance(assignments, list):
        for idx, a in enumerate(assignments):
            if not isinstance(a, dict):
                errors.append(f"baseline.assignments[{idx}] must be a mapping.")
                continue
            aid = a.get("id") or f"a{idx}"
            atype = a.get("type")
            if not atype:
                errors.append(f"baseline assignment '{aid}' has no `type`.")
            elif atype not in ASSIGNMENT_TYPES:
                errors.append(
                    f"baseline assignment '{aid}' has unknown type '{atype}'. "
                    f"Valid: {', '.join(sorted(ASSIGNMENT_TYPES))}.")
            if not a.get("principal_ref"):
                errors.append(f"baseline assignment '{aid}' has no `principal_ref`.")


def _validate_path(name: str, path, errors: List[str], warnings: List[str]) -> None:
    if not isinstance(path, dict):
        errors.append(f"attack_path '{name}' must be a mapping.")
        return

    _validate_objective(name, path.get("objective"), warnings, errors)
    _validate_initial_access(name, path.get("initial_access"), errors)

    assignment_ids, inject_ids, cred_refs = _validate_assignments(name, path, errors)
    _validate_steps(name, path.get("steps") or [], assignment_ids,
                    inject_ids | cred_refs, errors)


def _validate_objective(name, objective, warnings, errors) -> None:
    if objective is None:
        warnings.append(
            f"attack_path '{name}' declares no objective - the reachability gate "
            f"can't validate it (it will be reported 'unverified')."
        )
        return
    if not isinstance(objective, dict):
        errors.append(f"attack_path '{name}': objective must be a mapping.")
        return

    capability = objective.get("capability")
    if not capability:
        return  # name/impact only — gate reports 'unverified', not an error.
    if capability not in capabilities.KNOWN_CAPABILITIES:
        warnings.append(
            f"attack_path '{name}': capability '{capability}' is not modelled in "
            f"capabilities.py yet - the gate will mark it 'unverified'."
        )
        return
    if capability == "entra_role" and not (objective.get("role") or objective.get("name")):
        errors.append(
            f"attack_path '{name}': objective capability 'entra_role' needs a "
            f"`role:` (or `name:`) naming the target role."
        )
    elif capability in _TARGET_REF_CAPABILITIES and not objective.get("target_ref"):
        errors.append(
            f"attack_path '{name}': objective capability '{capability}' needs a "
            f"`target_ref:` naming the resource/identity to reach."
        )


def _validate_initial_access(name, ia, errors) -> None:
    if ia is None:
        return  # absent is allowed; the gate flags it only if an objective needs a seed.
    if not isinstance(ia, dict):
        errors.append(f"attack_path '{name}': initial_access must be a mapping.")
        return
    if not ia.get("principal_ref"):
        errors.append(
            f"attack_path '{name}': initial_access has no `principal_ref` "
            f"(the identity the attacker starts from)."
        )


def _validate_assignments(name, path, errors):
    """Validate each assignment's type/principal_ref and return the id sets the
    steps link against: (assignment_ids, data_inject_ids, credential_refs)."""
    assignment_ids, inject_ids, cred_refs = set(), set(), set()

    assignments = path.get("assignments") or []
    if not isinstance(assignments, list):
        errors.append(f"attack_path '{name}': assignments must be a list.")
        assignments = []
    for idx, a in enumerate(assignments):
        if not isinstance(a, dict):
            errors.append(f"attack_path '{name}': assignment #{idx} must be a mapping.")
            continue
        aid = a.get("id") or f"a{idx}"
        assignment_ids.add(aid)
        atype = a.get("type")
        if not atype:
            errors.append(f"attack_path '{name}': assignment '{aid}' has no `type`.")
        elif atype not in ASSIGNMENT_TYPES:
            errors.append(
                f"attack_path '{name}': assignment '{aid}' has unknown type "
                f"'{atype}'. Valid: {', '.join(sorted(ASSIGNMENT_TYPES))}."
            )
        if not a.get("principal_ref"):
            errors.append(
                f"attack_path '{name}': assignment '{aid}' has no `principal_ref`.")

    for idx, d in enumerate(path.get("data_injects") or []):
        if isinstance(d, dict):
            inject_ids.add(d.get("id") or f"d{idx}")
    for c in path.get("credentials") or []:
        if isinstance(c, dict) and c.get("ref"):
            cred_refs.add(c["ref"])

    return assignment_ids, inject_ids, cred_refs


def _validate_steps(name, steps, assignment_ids, readable_ids, errors) -> None:
    """`uses:` must reference declared assignment ids; `reads:` must reference a
    declared data_inject id or credential ref."""
    if not isinstance(steps, list):
        errors.append(f"attack_path '{name}': steps must be a list.")
        return
    for sidx, step in enumerate(steps):
        if not isinstance(step, dict):
            errors.append(f"attack_path '{name}': step #{sidx} must be a mapping.")
            continue
        label = step.get("name", f"#{sidx}")
        for u in step.get("uses") or []:
            if u not in assignment_ids:
                errors.append(
                    f"attack_path '{name}': step '{label}' uses unknown assignment "
                    f"id '{u}'.")
        for r in step.get("reads") or []:
            if r not in readable_ids:
                errors.append(
                    f"attack_path '{name}': step '{label}' reads unknown "
                    f"data_inject/credential id '{r}'.")
