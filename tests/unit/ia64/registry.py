"""Typed, explicit registry for IA-64 architectural microprogram cases."""

from __future__ import annotations

from collections import Counter
from pathlib import Path

from . import (cases_core, cases_fp, cases_interrupt, cases_memory_nat,
               cases_mmu, cases_pal, cases_rse, encoding)
from .case import CaseObservation, IA64Case


GROUPS = ("core", "memory-nat", "fp", "rse", "mmu", "interrupt", "pal")

GROUP_MODULES = {
    "core": cases_core,
    "memory-nat": cases_memory_nat,
    "fp": cases_fp,
    "rse": cases_rse,
    "mmu": cases_mmu,
    "interrupt": cases_interrupt,
    "pal": cases_pal,
}


def _registered_cases() -> dict[str, IA64Case]:
    cases: dict[str, IA64Case] = {}
    for group in GROUPS:
        for name, case in GROUP_MODULES[group].CASES.items():
            if name in cases:
                raise RuntimeError(f"duplicate IA-64 case id {name!r}")
            cases[name] = case
    return cases


CASES_BY_NAME = _registered_cases()


def group_for_name(name: str) -> str:
    try:
        return CASES_BY_NAME[name].group
    except KeyError as exc:
        raise ValueError(f"unassigned IA-64 test case {name!r}") from exc


def cases_for_group(group: str) -> dict[str, IA64Case]:
    if group not in GROUP_MODULES:
        raise ValueError(f"unknown IA-64 test group {group!r}")
    return dict(GROUP_MODULES[group].CASES)


def all_cases() -> dict[str, IA64Case]:
    return dict(sorted(CASES_BY_NAME.items()))


def coverage_inventory() -> list[dict[str, object]]:
    """Return deterministic, serialization-ready coverage metadata."""

    inventory = []
    for name, case in all_cases().items():
        metadata = case.metadata
        inventory.append({
            "id": name,
            "group": case.group,
            "tags": sorted(metadata.tags),
            "spec_refs": list(metadata.spec_refs),
            "required_features": sorted(metadata.required_features),
            "encoding_evidence": metadata.encoding_evidence.name.lower(),
            "expectation_evidence": (
                metadata.expectation_evidence.name.lower()),
            "observation": metadata.observation.name.lower(),
            "bundle_count": len(case.bundles),
            "expected_fields": sorted(case.expected),
        })
    return inventory


def _validate_migration_manifest(names: set[str]) -> None:
    path = Path(__file__).with_name("legacy-case-ids.txt")
    legacy = {
        line.strip() for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.startswith("#")
    }
    missing = sorted(legacy - names)
    extra = sorted(names - legacy)
    if missing or extra:
        raise RuntimeError(
            "IA-64 registry differs from the pre-B6 case manifest: "
            f"missing={missing!r}, extra={extra!r}")


def _validate_case_metadata(case: IA64Case) -> None:
    case.metadata.validate(case.name)
    if case.group not in case.metadata.tags:
        raise RuntimeError(
            f"IA-64 case {case.name!r} lacks its family coverage tag")
    if case.metadata.observation is CaseObservation.TNAT_PREDICATE and \
            not case.name.startswith("tnat_"):
        raise RuntimeError(
            f"non-tnat case {case.name!r} declares a tnat observer")
    if case.name.startswith("tnat_") and \
            case.metadata.observation is not CaseObservation.TNAT_PREDICATE:
        raise RuntimeError(f"tnat case {case.name!r} lacks observer metadata")
    if case.metadata.observation is CaseObservation.FP_TRANSFER and \
            case.group != "fp":
        raise RuntimeError(
            f"non-FP case {case.name!r} declares an FP transfer observer")


def _validate_case_programs(cases: dict[str, IA64Case]) -> None:
    duplicate_bundle_cases: list[str] = []
    effect_self_loop_cases: list[str] = []
    missing_successor_cases: list[str] = []
    effect_at_terminal_cases: list[str] = []

    for name, case in cases.items():
        if not case.bundles:
            continue
        program = encoding.normalized_bundles(case.bundles)
        address_counts = Counter(bundle[0] for bundle in program)
        for address, count in address_counts.items():
            if count > 1:
                duplicate_bundle_cases.append(f"{name}@0x{address:x}")

        for bundle in program:
            address = bundle[0]
            has_effect = bundle[2] != encoding.nop_m() or bundle[3] not in (
                encoding.nop_i(), encoding.nop_f(), encoding.nop_m())
            if not has_effect:
                continue
            if bundle[4] == encoding.br_cond(address, address) and \
                    not case.metadata.nonterminal_effect_loop:
                effect_self_loop_cases.append(f"{name}@0x{address:x}")
            if bundle[4] == encoding.br_cond(address, address + 0x10) and \
                    address + 0x10 not in address_counts:
                missing_successor_cases.append(f"{name}@0x{address:x}")

        terminal_ip = case.expected.get("ip")
        if not isinstance(terminal_ip, int) or \
                case.metadata.terminal_is_fault_ip:
            continue
        for bundle in program:
            if bundle[0] == terminal_ip:
                if bundle[2] != encoding.nop_m() or bundle[3] not in (
                        encoding.nop_i(), encoding.nop_f(),
                        encoding.nop_m()):
                    effect_at_terminal_cases.append(name)
                break

    if duplicate_bundle_cases:
        raise RuntimeError(
            "IA-64 cases contain colliding bundle addresses: " +
            ", ".join(sorted(duplicate_bundle_cases)))
    if effect_self_loop_cases:
        raise RuntimeError(
            "IA-64 cases couple effects to a self-loop observation point: " +
            ", ".join(sorted(effect_self_loop_cases)))
    if missing_successor_cases:
        raise RuntimeError(
            "IA-64 effect bundles branch to an absent successor: " +
            ", ".join(sorted(missing_successor_cases)))
    if effect_at_terminal_cases:
        raise RuntimeError(
            "IA-64 cases observe a terminal bundle before its effects retire: " +
            ", ".join(sorted(effect_at_terminal_cases)))


def validate_registry() -> None:
    manifest_names = [
        name
        for group in GROUPS
        for name in GROUP_MODULES[group].CASE_NAMES
    ]
    manifest_duplicates = sorted(
        name for name, count in Counter(manifest_names).items() if count > 1)
    registered_names = set(CASES_BY_NAME)
    missing = sorted(set(manifest_names) - registered_names)
    extra = sorted(registered_names - set(manifest_names))
    if manifest_duplicates or missing or extra:
        raise RuntimeError(
            "invalid explicit IA-64 family membership: "
            f"duplicates={manifest_duplicates!r}, missing={missing!r}, "
            f"extra={extra!r}")

    for name, case in CASES_BY_NAME.items():
        if not isinstance(case, IA64Case):
            raise RuntimeError(f"untyped IA-64 case {name!r}")
        if case.name != name:
            raise RuntimeError(
                f"IA-64 registry key {name!r} disagrees with {case.name!r}")
        if case.group not in GROUP_MODULES or \
                name not in GROUP_MODULES[case.group].CASES:
            raise RuntimeError(
                f"IA-64 case {name!r} has invalid group {case.group!r}")
        _validate_case_metadata(case)

    _validate_migration_manifest(registered_names)
    _validate_case_programs(CASES_BY_NAME)
