#!/usr/bin/env python3
"""Pure regression tests for the machine-readable IA64STATE parser."""

from __future__ import annotations

import os
import sys

if __package__ in (None, ""):
    sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
    from ia64.state import (ExpectedBits, ExpectedFP, StateExpectation,
                            StateParseError, parse_state)
else:
    from .state import (ExpectedBits, ExpectedFP, StateExpectation,
                        StateParseError, parse_state)


def sample_state() -> str:
    lines = [
        "IA64STATE SCHEMA version=0000000000000001",
        "IA64STATE META ip=0000000000000030 psr=0000000000000040 "
        "halted=0",
        "IA64STATE EXCEPTION code=0000000000000000 "
        "fault_code=000000000000001b fault_ip=0000000000000010 "
        "fault_imm=0000000000000002",
        "IA64STATE GRNAT lo=0000000000000020 hi=0000000000000000",
    ]
    for index in range(128):
        lines.append(
            f"IA64STATE GR index={index:03x} value={index:016x} "
            f"nat={1 if index == 5 else 0}")
    for index in range(8):
        lines.append(
            f"IA64STATE BR index={index:03x} value={index + 0x80:016x}")
    lines += [
        "IA64STATE PR value=0000000000010081",
        "IA64STATE AR ccv=00000000000000ff unat=0000000100000000 "
        "fpsr=000000000000033b csd=0000000000000000 "
        "ssd=0000000000000000 rsc=0000000000000003 "
        "rnat=0000000000000000 pfs=0000000000000000",
        "IA64STATE CFM sof=0000000000000008 sol=0000000000000004 "
        "sor=0000000000000002 rrb_gr=0000000000000001 "
        "rrb_fr=0000000000000002 rrb_pr=0000000000000003",
    ]
    for index in range(128):
        low = 0x8000000000000000 if index == 1 else index
        high = 0xffff if index == 1 else 0
        lines.append(
            f"IA64STATE FR index={index:03x} low={low:016x} "
            f"high={high:016x} nat={1 if index == 9 else 0}")
    return "unrelated HMP text\n" + "\n".join(lines) + "\n"


def test_complete_parse() -> None:
    state = parse_state(sample_state())
    assert state.schema_version == 1
    assert state.ip == 0x30
    assert state.exception == 0 and state.fault_code == 0x1b
    assert state.gr[5] == 5 and state.gr_nat[5]
    assert state.pr_mask == 0x10081
    assert state.ar["ccv"] == 0xff and state.ar["unat"] == 1 << 32
    assert state.cfm["rrb_pr"] == 3
    assert state.fr[1].low == 0x8000000000000000
    assert state.fr[9].nat


def test_typed_expectations() -> None:
    state = parse_state(sample_state())
    values = {
        "pr_mask": ExpectedBits(mask=(1 << 16) | (1 << 7),
                                value=(1 << 16) | (1 << 7)),
        "f1": ExpectedFP(0x8000000000000000, 0xffff),
        "r5_nat": 1,
        "ar_fpsr": 0x33b,
        "fault_code": 0x1b,
    }
    expectation = StateExpectation(values)
    values["r5_nat"] = 0
    assert expectation.matches(state)
    assert expectation.ip is None
    assert not expectation.mismatches(state)
    assert not StateExpectation({"r5_nat": 0}).matches(state)


def test_invalid_expectation_key_rejected() -> None:
    state = parse_state(sample_state())
    try:
        StateExpectation({"register_five": 5}).matches(state)
    except StateParseError as exc:
        assert "unknown scalar expectation key" in str(exc)
    else:
        raise AssertionError("unknown architectural expectation was accepted")


def test_missing_records_rejected() -> None:
    try:
        parse_state("IA64STATE META ip=0 psr=0 halted=0\n")
    except StateParseError as exc:
        assert "missing IA64STATE records" in str(exc)
    else:
        raise AssertionError("partial state was accepted")


def test_duplicate_register_rejected() -> None:
    text = sample_state().replace(
        "IA64STATE GR index=001 value=0000000000000001 nat=0\n",
        "IA64STATE GR index=001 value=0000000000000001 nat=0\n"
        "IA64STATE GR index=001 value=0000000000000001 nat=0\n")
    try:
        parse_state(text)
    except StateParseError as exc:
        assert "duplicate or invalid GR index" in str(exc)
    else:
        raise AssertionError("duplicate GR record was accepted")


def test_duplicate_singleton_rejected() -> None:
    text = sample_state().replace(
        "IA64STATE META ip=0000000000000030 psr=0000000000000040 "
        "halted=0\n",
        "IA64STATE META ip=0000000000000030 psr=0000000000000040 "
        "halted=0\n"
        "IA64STATE META ip=0000000000000030 psr=0000000000000040 "
        "halted=0\n")
    try:
        parse_state(text)
    except StateParseError as exc:
        assert "duplicate IA64STATE META" in str(exc)
    else:
        raise AssertionError("duplicate META record was accepted")


def test_unknown_schema_rejected() -> None:
    text = sample_state().replace(
        "IA64STATE SCHEMA version=0000000000000001",
        "IA64STATE SCHEMA version=0000000000000002")
    try:
        parse_state(text)
    except StateParseError as exc:
        assert "unsupported IA64STATE schema version 2" in str(exc)
    else:
        raise AssertionError("unknown IA64STATE schema was accepted")


def test_exception_fault_code_required() -> None:
    text = sample_state().replace(
        "fault_code=000000000000001b ", "")
    try:
        parse_state(text)
    except StateParseError as exc:
        assert "EXCEPTION line lacks fields: fault_code" in str(exc)
    else:
        raise AssertionError("EXCEPTION record without fault_code was accepted")


def test_non_boolean_and_trailing_field_rejected() -> None:
    invalid_nat = sample_state().replace(
        "IA64STATE GR index=005 value=0000000000000005 nat=1",
        "IA64STATE GR index=005 value=0000000000000005 nat=2")
    try:
        parse_state(invalid_nat)
    except StateParseError as exc:
        assert "nat must be zero or one" in str(exc)
    else:
        raise AssertionError("non-boolean NaT was accepted")

    trailing = sample_state().replace(
        "IA64STATE PR value=0000000000010081",
        "IA64STATE PR value=0000000000010081 reserved=0")
    try:
        parse_state(trailing)
    except StateParseError as exc:
        assert "unexpected fields" in str(exc)
    else:
        raise AssertionError("unexpected state field was accepted")


def main() -> int:
    tests = (
        ("complete state", test_complete_parse),
        ("typed expectations", test_typed_expectations),
        ("invalid expectation", test_invalid_expectation_key_rejected),
        ("missing records", test_missing_records_rejected),
        ("duplicate register", test_duplicate_register_rejected),
        ("duplicate singleton", test_duplicate_singleton_rejected),
        ("schema version", test_unknown_schema_rejected),
        ("exception fault code", test_exception_fault_code_required),
        ("field validation", test_non_boolean_and_trailing_field_rejected),
    )
    print("TAP version 13")
    print(f"1..{len(tests)}")
    failed = 0
    for index, (name, function) in enumerate(tests, 1):
        try:
            function()
            print(f"ok {index} - {name}")
        except Exception as exc:
            failed += 1
            print(f"not ok {index} - {name}")
            print(f"# {exc}")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
