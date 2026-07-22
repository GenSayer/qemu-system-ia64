"""Typed IA-64 architectural microprogram cases and registration helpers."""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field, replace
from enum import Enum, auto
from typing import Any


CaseRunner = Callable[[str], None]
Bundle = tuple[int, int, int, int, int]


class CaseEvidence(Enum):
    """Independent inputs used to construct a test case."""

    SDM_ENCODING_TABLE = auto()
    ARCHITECTURAL_SEMANTICS = auto()
    PAL_OR_PLATFORM_ABI = auto()
    EXTERNAL_GUEST_REGRESSION = auto()


class CaseObservation(Enum):
    """How a case observes the architectural result."""

    DIRECT_STATE = auto()
    FP_TRANSFER = auto()
    TNAT_PREDICATE = auto()


@dataclass(frozen=True)
class CaseMetadata:
    """Reviewable coverage data and exceptions to registry invariants."""

    encoding_evidence: CaseEvidence = CaseEvidence.SDM_ENCODING_TABLE
    expectation_evidence: CaseEvidence = CaseEvidence.ARCHITECTURAL_SEMANTICS
    observation: CaseObservation = CaseObservation.DIRECT_STATE
    tags: frozenset[str] = frozenset()
    spec_refs: tuple[str, ...] = ()
    required_features: frozenset[str] = frozenset()
    terminal_is_fault_ip: bool = False
    nonterminal_effect_loop: bool = False

    def overlay(self, other: CaseMetadata) -> CaseMetadata:
        """Apply case-specific data while retaining family coverage data."""

        return replace(
            other,
            tags=self.tags | other.tags,
            spec_refs=tuple(dict.fromkeys(self.spec_refs + other.spec_refs)),
            required_features=(
                self.required_features | other.required_features),
        )

    def validate(self, name: str) -> None:
        if self.encoding_evidence is self.expectation_evidence:
            raise RuntimeError(
                f"{name}: encoding and expectation use the same evidence")
        if not self.tags:
            raise RuntimeError(f"{name}: case metadata has no coverage tags")
        if not self.spec_refs:
            raise RuntimeError(f"{name}: case metadata has no specification")
        if not self.required_features:
            raise RuntimeError(f"{name}: case metadata has no required feature")
        for field_name, values in (
                ("tag", self.tags),
                ("specification reference", self.spec_refs),
                ("required feature", self.required_features)):
            invalid = sorted(value for value in values
                             if not value or value != value.strip())
            if invalid:
                raise RuntimeError(
                    f"{name}: invalid {field_name} metadata {invalid!r}")


COMMON_FEATURES = frozenset({"ia64-vpc", "qmp", "tcg-system"})

GROUP_METADATA = {
    "core": CaseMetadata(
        tags=frozenset({"architectural", "core"}),
        spec_refs=(
            "IA64-softdevman-vol1.pdf: IA-64 Application Architecture",
            "IA64-softdevman-vol3.pdf: Instruction Set Reference",
        ),
        required_features=COMMON_FEATURES,
    ),
    "memory-nat": CaseMetadata(
        tags=frozenset({"architectural", "memory-nat"}),
        spec_refs=(
            "IA64-softdevman-vol1.pdf: IA-64 Application Architecture",
            "IA64-softdevman-vol2.pdf: System Architecture, chapter 4",
            "IA64-softdevman-vol3.pdf: Instruction Set Reference",
        ),
        required_features=COMMON_FEATURES,
    ),
    "fp": CaseMetadata(
        tags=frozenset({"architectural", "fp"}),
        spec_refs=(
            "IA64-softdevman-vol1.pdf: Application Architecture, chapter 5",
            "IA64-softdevman-vol3.pdf: Instruction Set Reference",
        ),
        required_features=COMMON_FEATURES,
    ),
    "rse": CaseMetadata(
        tags=frozenset({"architectural", "rse"}),
        spec_refs=(
            "IA64-softdevman-vol1.pdf: Application Architecture, chapter 4",
            "IA64-softdevman-vol2.pdf: System Architecture, chapter 6",
            "IA64-softdevman-vol3.pdf: Instruction Set Reference",
        ),
        required_features=COMMON_FEATURES,
    ),
    "mmu": CaseMetadata(
        tags=frozenset({"architectural", "mmu"}),
        spec_refs=(
            "IA64-softdevman-vol2.pdf: System Architecture, chapter 4",
            "IA64-softdevman-vol3.pdf: Instruction Set Reference",
        ),
        required_features=COMMON_FEATURES,
    ),
    "interrupt": CaseMetadata(
        tags=frozenset({"architectural", "interrupt"}),
        spec_refs=(
            "IA64-softdevman-vol2.pdf: System Architecture, chapters 5 and 8",
            "IA64-softdevman-vol3.pdf: Instruction Set Reference",
        ),
        required_features=COMMON_FEATURES,
    ),
    "pal": CaseMetadata(
        tags=frozenset({"architectural", "pal"}),
        spec_refs=(
            "IA64-softdevman-vol2.pdf: System Architecture, chapter 11",
        ),
        required_features=COMMON_FEATURES | {"firmware-pal"},
    ),
}


@dataclass(frozen=True)
class IA64Case:
    """One named, callable IA-64 test with explicit validation metadata."""

    name: str
    runner: CaseRunner
    bundles: tuple[Bundle, ...] = ()
    expected: Mapping[str, Any] = field(default_factory=dict)
    group: str = ""
    metadata: CaseMetadata = field(default_factory=CaseMetadata)

    def __call__(self, qemu: str) -> None:
        self.runner(qemu)

    def bind(self, group: str,
             metadata: CaseMetadata | None = None) -> IA64Case:
        return replace(self, group=group,
                       metadata=self.metadata if metadata is None else metadata)


def _as_case(name: str, value: IA64Case | CaseRunner) -> IA64Case:
    if isinstance(value, IA64Case):
        if value.name != name:
            raise RuntimeError(
                f"IA-64 case id {name!r} disagrees with {value.name!r}")
        return value
    if callable(value):
        return IA64Case(name=name, runner=value)
    raise RuntimeError(f"IA-64 case {name!r} is not callable")


def bind_cases(group: str, case_names: Sequence[str],
               namespace: Mapping[str, Any], *,
               aliases: Mapping[str, IA64Case | CaseRunner] | None = None,
               extras: Mapping[str, IA64Case | CaseRunner] | None = None,
               metadata: Mapping[str, CaseMetadata] | None = None,
               ) -> dict[str, IA64Case]:
    """Resolve an explicit family manifest into typed, uniquely named cases."""

    aliases = aliases or {}
    extras = extras or {}
    metadata = metadata or {}
    try:
        group_metadata = GROUP_METADATA[group]
    except KeyError as exc:
        raise RuntimeError(f"unknown IA-64 case family {group!r}") from exc
    duplicates = sorted({name for name in case_names
                         if case_names.count(name) > 1})
    if duplicates:
        raise RuntimeError(f"duplicate IA-64 case ids in {group}: {duplicates}")

    unknown_metadata = sorted(set(metadata) - set(case_names))
    if unknown_metadata:
        raise RuntimeError(
            f"metadata for unknown IA-64 {group} cases: {unknown_metadata}")

    cases: dict[str, IA64Case] = {}
    for name in case_names:
        value = namespace.get("test_" + name)
        if value is None:
            value = aliases.get(name)
        if value is None:
            value = extras.get(name)
        if value is None:
            raise RuntimeError(f"missing IA-64 {group} case {name!r}")
        case = _as_case(name, value)
        case_metadata = group_metadata.overlay(case.metadata)
        if name in metadata:
            case_metadata = case_metadata.overlay(metadata[name])
        case = case.bind(group, case_metadata)
        case.metadata.validate(name)
        cases[name] = case
    return cases
