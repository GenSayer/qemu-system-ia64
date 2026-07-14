"""Single, non-overlapping registry for IA-64 microprogram cases."""

from __future__ import annotations

import ast
from collections.abc import Callable
from collections import Counter
from inspect import getclosurevars
from pathlib import Path

from . import (cases_core, cases_fp, cases_interrupt, cases_memory_nat,
               cases_mmu, cases_pal, cases_rse, encoding)


TEST_NAMES = encoding.TEST_NAMES


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

GROUP_BY_NAME = {
    name: group
    for group, module in GROUP_MODULES.items()
    for name in module.CASE_NAMES
}

def group_for_name(name: str) -> str:
    try:
        return GROUP_BY_NAME[name]
    except KeyError as exc:
        raise ValueError(f"unassigned IA-64 test case {name!r}") from exc


def cases_for_group(group: str) -> dict[str, Callable[[str], None]]:
    if group not in GROUP_MODULES:
        raise ValueError(f"unknown IA-64 test group {group!r}")
    return dict(GROUP_MODULES[group].CASES)


def all_cases() -> dict[str, Callable[[str], None]]:
    return dict(sorted(TEST_NAMES.items()))


def validate_registry() -> None:
    source = Path(encoding.__file__).read_text(encoding="utf-8")
    tree = ast.parse(source, filename=encoding.__file__)
    literal_names: list[str] = []
    for statement in tree.body:
        if not isinstance(statement, ast.Assign) or \
                not any(isinstance(target, ast.Name) and
                        target.id == "TEST_NAMES"
                        for target in statement.targets) or \
                not isinstance(statement.value, ast.Dict):
            continue
        literal_names.extend(
            key.value for key in statement.value.keys
            if isinstance(key, ast.Constant) and isinstance(key.value, str)
        )
    duplicates = sorted(name for name, count in Counter(literal_names).items()
                        if count > 1)
    if duplicates:
        raise RuntimeError(
            "duplicate literal IA-64 microprogram names: " +
            ", ".join(duplicates))

    manifest_names = [
        name
        for module in GROUP_MODULES.values()
        for name in module.CASE_NAMES
    ]
    manifest_duplicates = sorted(
        name for name, count in Counter(manifest_names).items() if count > 1)
    missing = sorted(set(TEST_NAMES) - set(manifest_names))
    extra = sorted(set(manifest_names) - set(TEST_NAMES))
    if manifest_duplicates or missing or extra:
        raise RuntimeError(
            "invalid explicit IA-64 group membership: "
            f"duplicates={manifest_duplicates!r}, missing={missing!r}, "
            f"extra={extra!r}")

    registration_mismatches = []
    for registered_name, function in TEST_NAMES.items():
        implementation_name = getclosurevars(function).nonlocals.get("name")
        if isinstance(implementation_name, str) and \
                implementation_name != registered_name:
            registration_mismatches.append(
                f"{registered_name}->{implementation_name}")
    if registration_mismatches:
        raise RuntimeError(
            "IA-64 registry names disagree with implementations: " +
            ", ".join(registration_mismatches))

    observer_cases: list[str] = []
    tnat_observer_cases: list[str] = []
    transfer_prefixes = ("getf", "setf", "ldf", "stf")
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or \
                not isinstance(node.func, ast.Name) or \
                node.func.id != "require_registers" or len(node.args) < 2 or \
                not isinstance(node.args[0], ast.Constant) or \
                not isinstance(node.args[0].value, str):
            continue
        name = node.args[0].value
        callees = {
            child.func.id for child in ast.walk(node.args[1])
            if isinstance(child, ast.Call) and
            isinstance(child.func, ast.Name)
        }
        if any(callee.startswith("tnat_") for callee in callees) and \
                not name.startswith("tnat_"):
            tnat_observer_cases.append(name)

        checks_direct_fp = group_for_name(name) == "fp" or \
            "rotating_floating_registers" in name
        if not checks_direct_fp or \
                name.startswith(transfer_prefixes) or \
                name in ("data_big_endian_ldfe_stfe",
                         "data_big_endian_stf_spill_ldf_fill") or \
                name.startswith("fpmodel_") or \
                name == "disabled_fp_store_sets_isr_w":
            continue
        if any(callee.startswith(("getf_", "stf")) for callee in callees):
            observer_cases.append(name)
    if tnat_observer_cases:
        raise RuntimeError(
            "non-tnat cases use tnat as a NaT observer: " +
            ", ".join(sorted(tnat_observer_cases)))
    if observer_cases:
        raise RuntimeError(
            "FP arithmetic cases use transfer instructions as observers: " +
            ", ".join(sorted(observer_cases)))

    fault_ip_terminal_cases = {
        "itc_d_4g_page_size_reserved_field_fault",
        "itc_d_not_present_rejects_low_itir_reserved_field",
        "itc_d_present_reserved_itir_field_fault",
        "itc_d_present_reserved_ma_field_fault",
        "itc_d_present_reserved_pte_field_fault",
        "itc_i_present_reserved_pte_field_fault",
        "itr_d_4g_page_size_reserved_field_fault",
    }
    nonterminal_effect_loop_cases = {
        # These loops are polling points or deliberately wrong-path markers;
        # none is the completion IP for its case.
        "async_timer_interrupt_enters_ivt",
        "async_timer_interrupt_preserves_bank1_grs",
        "async_timer_interrupt_records_boundary_ri",
        "future_itm_rearm_preserves_pended_timer_irr",
        "interruption_serializes_pending_ptr_d",
        "invalid_itv_vector_is_ignored",
        "itr_i_8k_translation_uses_unrounded_paddr",
        "itr_i_clear_accessed_raises_inst_access_bit",
        "masked_itv_discards_due_timer",
        "masking_itv_preserves_pended_timer_irr",
        "past_itm_does_not_fire",
        "ptr_i_purges_matching_itr_by_address",
        "rfi_target_rse_fill_fault_uses_restored_psr",
        "rse_spill_fault_sets_isr_rs",
        "rse_uses_rsc_pl_for_access_rights",
        "rsm_ic_inflight_dtlb_not_data_nested",
        "short_vhpt_walker_rejects_pending_table_purge",
        "ssm_ic_inflight_dtlb_sets_ni",
        "ssm_ic_inflight_short_vhpt_entry_miss_raises_dtlb",
    }
    effect_at_terminal_cases: list[str] = []
    effect_self_loop_cases: list[str] = []
    missing_successor_cases: list[str] = []
    duplicate_bundle_cases: list[str] = []
    for name, function in TEST_NAMES.items():
        nonlocals = getclosurevars(function).nonlocals
        bundles = nonlocals.get("bundles")
        expected = nonlocals.get("expected")
        if not isinstance(bundles, (list, tuple)):
            continue
        program = encoding.normalized_bundles(bundles)
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
                    name not in nonterminal_effect_loop_cases:
                effect_self_loop_cases.append(f"{name}@0x{address:x}")
            if bundle[4] == encoding.br_cond(address, address + 0x10) and \
                    address + 0x10 not in address_counts:
                missing_successor_cases.append(f"{name}@0x{address:x}")

        if not isinstance(expected, dict) or \
                not isinstance(expected.get("ip"), int) or \
                name in fault_ip_terminal_cases:
            continue
        terminal_ip = expected["ip"]
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

    invalid = [name for name, function in TEST_NAMES.items()
               if not callable(function)]
    if invalid:
        raise RuntimeError(f"non-callable IA-64 cases: {invalid!r}")
    assigned = sum((list(cases_for_group(group)) for group in GROUPS), [])
    if len(assigned) != len(TEST_NAMES) or set(assigned) != set(TEST_NAMES):
        raise RuntimeError("IA-64 cases are missing or multiply assigned")
