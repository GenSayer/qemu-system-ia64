#!/usr/bin/env python3
"""TAP entry point for one IA-64 microprogram group."""

from __future__ import annotations

import argparse
import json
import os
import statistics
import sys
import time

if __package__ in (None, ""):
    sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
    from ia64.registry import (GROUPS, all_cases, cases_for_group,
                               coverage_inventory, validate_registry)
else:
    from .registry import (GROUPS, all_cases, cases_for_group,
                           coverage_inventory, validate_registry)


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("qemu", nargs="?", help="qemu-system-ia64 executable")
    parser.add_argument("--group", choices=GROUPS)
    parser.add_argument("--list", action="store_true")
    parser.add_argument("--inventory", action="store_true")
    parser.add_argument("--test", action="append", default=[])
    parser.add_argument("--match")
    parser.add_argument("--repeat", type=int, default=1)
    args = parser.parse_args(argv)
    if args.list and args.inventory:
        parser.error("--list and --inventory are mutually exclusive")
    if not (args.list or args.inventory) and args.qemu is None:
        parser.error(
            "QEMU_SYSTEM_IA64 is required unless --list or --inventory is used")
    if args.repeat <= 0:
        parser.error("--repeat must be positive")
    return args


def select(args: argparse.Namespace):
    cases = cases_for_group(args.group) if args.group else all_cases()
    if args.test:
        unknown = sorted(set(args.test) - set(cases))
        if unknown:
            raise KeyError("unknown test(s): " + ", ".join(unknown))
        cases = {name: cases[name] for name in args.test}
    if args.match is not None:
        cases = {name: function for name, function in cases.items()
                 if args.match in name}
    return cases


def main(argv: list[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    validate_registry()
    if args.inventory:
        print(json.dumps(coverage_inventory(), indent=2, sort_keys=True))
        return 0
    try:
        cases = select(args)
    except KeyError as exc:
        print(f"Bail out! {exc.args[0]}")
        return 1

    if args.list:
        for name in cases:
            print(name)
        return 0
    if not cases:
        print("Bail out! selection contains no tests")
        return 1

    executions = [(name, function, repeat)
                  for name, function in cases.items()
                  for repeat in range(1, args.repeat + 1)]
    print("TAP version 13")
    print(f"1..{len(executions)}")
    failed = 0
    durations = []
    for index, (name, function, repeat) in enumerate(executions, 1):
        label = name if args.repeat == 1 else f"{name} repeat={repeat}"
        started = time.monotonic()
        try:
            function(args.qemu)
            duration = time.monotonic() - started
            durations.append(duration)
            print(f"ok {index} - {label}")
        except Exception as exc:  # test diagnostics must retain the last state
            failed += 1
            print(f"not ok {index} - {label}")
            for line in str(exc).splitlines() or [repr(exc)]:
                print(f"# {line}")

    if durations:
        ordered = sorted(durations)
        p95_index = min(len(ordered) - 1, int(len(ordered) * 0.95))
        print(f"# timing count={len(ordered)} "
              f"p50={statistics.median(ordered):.6f}s "
              f"p95={ordered[p95_index]:.6f}s "
              f"total={sum(ordered):.6f}s")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
