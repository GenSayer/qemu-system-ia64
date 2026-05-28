#!/usr/bin/env python3
#
# Compare the IA-64 target decoder opcode selected by QEMU with GNU objdump's
# disassembly for the same bundles.

import argparse
import json
import re
import subprocess
import sys
import tempfile
import time
from pathlib import Path


SLOT_BIT_OFFSETS = (5, 46, 87)
SLOT_ADDR_TO_INDEX = {0: 0, 6: 1, 12: 2}
DEFAULT_SAMPLE_ASM = """
    .text
    .global _start
_start:
    add r8 = r9, r10
    ld8 r8 = [r9]
    st8 [r9] = r8
    nop.m 0
    nop.i 0
    br.ret.sptk.many b0
"""


def run(args, *, input_text=None, timeout=20):
    proc = subprocess.run(
        args,
        input=input_text,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout,
    )
    if proc.returncode != 0:
        raise RuntimeError(
            "command failed: {}\nstdout:\n{}\nstderr:\n{}".format(
                " ".join(args), proc.stdout, proc.stderr
            )
        )
    return proc.stdout


def repo_root():
    return Path(__file__).resolve().parents[1]


def parse_opcode_enum():
    cpu_c = repo_root() / "target" / "ia64" / "cpu.c"
    text = cpu_c.read_text(encoding="utf-8")
    match = re.search(
        r"typedef enum Ia64Opcode \{(?P<body>.*?)\} Ia64Opcode;",
        text,
        re.S,
    )
    if not match:
        raise RuntimeError("could not find Ia64Opcode enum in target/ia64/cpu.c")
    names = []
    for line in match.group("body").splitlines():
        line = line.split("/*", 1)[0].split("//", 1)[0]
        found = re.search(r"\bIA64_OP_[A-Z0-9_]+\b", line)
        if found:
            names.append(found.group(0))
    return names


def assemble_to_raw(asm_text, tools, tmpdir):
    asm_path = tmpdir / "input.s"
    obj_path = tmpdir / "input.o"
    bin_path = tmpdir / "input.bin"
    asm_path.write_text(asm_text, encoding="utf-8")
    run([tools["as"], "-o", str(obj_path), str(asm_path)])
    run(
        [
            tools["objcopy"],
            "-O",
            "binary",
            "--only-section=.text",
            str(obj_path),
            str(bin_path),
        ]
    )
    return bin_path.read_bytes()


def objdump_file_to_raw(path, objdump):
    output = run([objdump, "-d", str(path)])
    bundles = {}
    line_re = re.compile(
        r"^\s*([0-9a-fA-F]+):\s+((?:[0-9a-fA-F]{2}\s+)+).*$"
    )
    for line in output.splitlines():
        match = line_re.match(line)
        if not match:
            continue
        addr = int(match.group(1), 16)
        slot_offset = addr % 16
        if slot_offset not in SLOT_ADDR_TO_INDEX:
            continue
        data = bytes(int(byte, 16) for byte in match.group(2).split())
        bundle_addr = addr - slot_offset
        bundle = bundles.setdefault(bundle_addr, bytearray(16))
        bundle[slot_offset : slot_offset + len(data)] = data

    raw = bytearray()
    for bundle_addr in sorted(bundles):
        raw.extend(bundles[bundle_addr])
    return bytes(raw)


def load_inputs(paths, input_kind, tools, tmpdir):
    if not paths:
        return assemble_to_raw(DEFAULT_SAMPLE_ASM, tools, tmpdir)

    chunks = []
    for path_text in paths:
        path = Path(path_text)
        kind = input_kind
        if kind == "auto":
            if path.suffix.lower() in (".s", ".S"):
                kind = "asm"
            elif path.suffix.lower() in (".efi", ".elf", ".o", ".so"):
                kind = "objdump"
            else:
                kind = "raw"
        if kind == "asm":
            chunks.append(assemble_to_raw(path.read_text(encoding="utf-8"), tools, tmpdir))
        elif kind == "objdump":
            chunks.append(objdump_file_to_raw(path, tools["objdump"]))
        elif kind == "raw":
            chunks.append(path.read_bytes())
        else:
            raise RuntimeError(f"unsupported input kind: {kind}")
    return b"".join(chunks)


def bundle_words(bundle):
    if len(bundle) != 16:
        raise ValueError("IA-64 bundles must be 16 bytes")
    value = int.from_bytes(bundle, "little")
    low = value & ((1 << 64) - 1)
    high = value >> 64
    return low, high


def set_false_predicate(bundle, qp):
    value = int.from_bytes(bundle, "little")
    for offset in SLOT_BIT_OFFSETS:
        value &= ~(((1 << 6) - 1) << offset)
        value |= qp << offset
    return value.to_bytes(16, "little")


def split_bundles(data, false_predicate_qp):
    usable = len(data) - (len(data) % 16)
    bundles = [data[i : i + 16] for i in range(0, usable, 16)]
    if false_predicate_qp is not None:
        bundles = [set_false_predicate(bundle, false_predicate_qp) for bundle in bundles]
    return bundles, len(data) - usable


def objdump_slots(raw_path, objdump):
    output = run([objdump, "-D", "-b", "binary", "-m", "ia64", str(raw_path)])
    slots = {}
    line_re = re.compile(
        r"^\s*([0-9a-fA-F]+):\s+((?:[0-9a-fA-F]{2}\s+)+)(.*?)\s*$"
    )
    for line in output.splitlines():
        match = line_re.match(line)
        if not match:
            continue
        addr = int(match.group(1), 16)
        slot = SLOT_ADDR_TO_INDEX.get(addr % 16)
        if slot is None:
            continue
        text = match.group(3).strip()
        text = re.sub(r"^\[[^\]]+\]\s+", "", text)
        text = re.sub(r";;+\s*$", "", text)
        if not text or re.fullmatch(r"(?:[0-9a-fA-F]{2}\s*)+", text):
            continue
        slots[(addr // 16, slot)] = {
            "addr": addr,
            "text": text,
            "mnemonic": normalize_objdump_mnemonic(text),
        }
    return slots, output


def normalize_objdump_mnemonic(text):
    text = re.sub(r"^\([^)]*\)\s*", "", text.strip())
    if not text:
        return ""
    return text.split()[0].lower()


def normalize_qemu_opcode(name):
    if name == "IA64_OP_ILLEGAL":
        return "illegal"
    op = name.removeprefix("IA64_OP_").lower()

    if op == "nop":
        return "nop"
    if op == "break":
        return "break"
    if op == "movl":
        return "movl"
    if op.startswith("mov_"):
        return "mov"
    if op in ("add_one", "sub_one"):
        return op.split("_", 1)[0]
    if op.endswith("_imm"):
        op = op[: -len("_imm")]

    op = re.sub(r"^(ld[1248])s$", r"\1.s", op)
    op = re.sub(r"^(ld[1248])a$", r"\1.a", op)
    op = re.sub(r"^(ld[1248])sa$", r"\1.s.a", op)
    op = re.sub(r"^(ld[1248])fill$", r"\1.fill", op)
    op = re.sub(r"^(ld[1248])c_clr$", r"\1.c.clr", op)
    op = re.sub(r"^(ld[1248])c_nc$", r"\1.c.nc", op)
    op = re.sub(r"^(st[1248])rel$", r"\1.rel", op)
    op = re.sub(r"^(st[1248])spill$", r"\1.spill", op)
    op = op.replace("_", ".")
    return op


def run_qemu_chunk(qemu, bundles, start_index, args):
    with tempfile.NamedTemporaryFile(prefix="ia64-qemu-code-", suffix=".bin") as code, \
            tempfile.NamedTemporaryFile(prefix="ia64-qemu-decode-", suffix=".log") as log:
        code.write(b"".join(bundles))
        code.flush()
        address = args.base + start_index * 16
        qemu_args = [
            qemu,
            "-machine",
            "ia64-vpc",
            "-smp",
            "1",
            "-display",
            "none",
            "-serial",
            "none",
            "-monitor",
            "stdio",
            "-d",
            "in_asm",
            "-D",
            log.name,
            "-device",
            f"loader,file={code.name},addr={address},force-raw=true",
        ]
        qemu_args += ["-device", f"loader,addr={address},cpu-num=0"]
        proc = subprocess.Popen(
            qemu_args,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        try:
            time.sleep(args.delay)
            proc.communicate(input="quit\n", timeout=args.timeout)
        except Exception:
            proc.kill()
            proc.communicate()
        log.seek(0)
        return log.read().decode("utf-8", errors="replace")


def parse_qemu_decode_log(log_text, opcode_names, base, max_bundles):
    decoded = {}
    current_bundle = None
    bundle_re = re.compile(
        r"QEMU-IA64-DECODE: bundle=0x([0-9a-fA-F]+).*defined=([01])"
    )
    slot_re = re.compile(
        r"QEMU-IA64-DECODE: slot=([0-2]) unit=([^ ]+) opcode=([0-9]+) "
        r"valid=([01]) qp=([0-9]+) raw=0x([0-9a-fA-F]+)"
    )

    for line in log_text.splitlines():
        bundle_match = bundle_re.search(line)
        if bundle_match:
            bundle_addr = int(bundle_match.group(1), 16)
            if bundle_addr >= base:
                current_bundle = (bundle_addr - base) // 16
                if current_bundle >= max_bundles:
                    current_bundle = None
            else:
                current_bundle = None
            continue
        slot_match = slot_re.search(line)
        if slot_match and current_bundle is not None:
            opcode = int(slot_match.group(3), 10)
            name = opcode_names[opcode] if opcode < len(opcode_names) else f"OP_{opcode}"
            slot = int(slot_match.group(1), 10)
            decoded[(current_bundle, slot)] = {
                "unit": slot_match.group(2),
                "opcode": opcode,
                "opcode_name": name,
                "mnemonic": normalize_qemu_opcode(name),
                "valid": slot_match.group(4) == "1",
                "qp": int(slot_match.group(5), 10),
                "raw": int(slot_match.group(6), 16),
            }
    return decoded


def collect_qemu_decode(qemu, bundles, opcode_names, args):
    decoded = {}
    logs = []
    for start in range(0, len(bundles), args.batch_size):
        chunk = bundles[start : start + args.batch_size]
        log_text = run_qemu_chunk(qemu, chunk, start, args)
        logs.append(log_text)
        decoded.update(parse_qemu_decode_log(
            log_text, opcode_names, args.base, len(bundles)))

    missing_bundles = sorted(
        {
            bundle_index
            for bundle_index in range(len(bundles))
            if not any((bundle_index, slot) in decoded for slot in range(3))
        }
    )
    if len(missing_bundles) > args.rerun_missing_limit:
        return decoded, "".join(logs)

    for bundle_index in missing_bundles:
        log_text = run_qemu_chunk(qemu, [bundles[bundle_index]], bundle_index, args)
        logs.append(log_text)
        decoded.update(parse_qemu_decode_log(
            log_text, opcode_names, args.base, len(bundles)))

    return decoded, "".join(logs)


def mnemonic_matches(qemu_mnemonic, objdump_mnemonic):
    if qemu_mnemonic == objdump_mnemonic:
        return True
    if qemu_mnemonic == "nop" and objdump_mnemonic.startswith("nop."):
        return True
    if qemu_mnemonic == "mov" and objdump_mnemonic.startswith("mov"):
        return True
    return objdump_mnemonic.startswith(qemu_mnemonic + ".")


def compare(objdump, qemu, strict):
    issues = []
    all_keys = sorted(objdump)
    for key in all_keys:
        obj = objdump.get(key)
        q = qemu.get(key)
        if q is None:
            issues.append({"kind": "missing-log", "bundle": key[0], "slot": key[1],
                           "objdump": obj, "qemu": q})
            continue
        obj_mnemonic = obj["mnemonic"]
        if not q["valid"] and obj_mnemonic not in ("", "data8", "illegal"):
            issues.append({"kind": "qemu-invalid", "bundle": key[0], "slot": key[1],
                           "objdump": obj, "qemu": q})
        elif strict and not mnemonic_matches(q["mnemonic"], obj_mnemonic):
            issues.append({"kind": "mnemonic-mismatch", "bundle": key[0],
                           "slot": key[1], "objdump": obj, "qemu": q})
    priority = {"qemu-invalid": 0, "mnemonic-mismatch": 1, "missing-log": 2}
    return sorted(issues, key=lambda issue: (
        priority.get(issue["kind"], 99), issue["bundle"], issue["slot"]))


def print_report(bundles, skipped_tail, objdump_slots_map, qemu_slots, issues, args):
    compared = len(set(objdump_slots_map) & set(qemu_slots))
    invalid = sum(1 for issue in issues if issue["kind"] == "qemu-invalid")
    mismatches = sum(1 for issue in issues if issue["kind"] == "mnemonic-mismatch")
    missing = sum(1 for issue in issues if issue["kind"] == "missing-log")

    if args.json:
        print(json.dumps({
            "bundles": len(bundles),
            "slots_compared": compared,
            "skipped_tail_bytes": skipped_tail,
            "qemu_invalid": invalid,
            "mnemonic_mismatches": mismatches,
            "missing_log_entries": missing,
            "issues": issues[: args.max_issues],
        }, indent=2, sort_keys=True))
        return

    print(f"bundles: {len(bundles)}")
    print(f"slots compared: {compared}")
    if skipped_tail:
        print(f"skipped tail bytes: {skipped_tail}")
    print(f"qemu invalid while objdump decodes: {invalid}")
    print(f"mnemonic mismatches: {mismatches}")
    print(f"missing qemu log entries: {missing}")

    for issue in issues[: args.max_issues]:
        bundle = issue["bundle"]
        slot = issue["slot"]
        obj = issue.get("objdump") or {}
        q = issue.get("qemu") or {}
        addr = args.base + bundle * 16
        print(
            "issue: {kind} bundle={bundle} slot={slot} addr=0x{addr:x} "
            "qemu={qemu} objdump={objdump} raw={raw}".format(
                kind=issue["kind"],
                bundle=bundle,
                slot=slot,
                addr=addr,
                qemu=q.get("opcode_name", "<missing>"),
                objdump=obj.get("text", "<missing>"),
                raw=("0x%010x" % q["raw"]) if "raw" in q else "<missing>",
            )
        )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("inputs", nargs="*", help="IA-64 assembly or raw bundle files")
    parser.add_argument("--qemu", default="build/qemu-system-ia64")
    parser.add_argument("--kind", choices=("auto", "asm", "raw", "objdump"),
                        default="auto")
    parser.add_argument("--objdump", default="ia64-linux-gnu-objdump")
    parser.add_argument("--as", dest="assembler", default="ia64-linux-gnu-as")
    parser.add_argument("--objcopy", default="ia64-linux-gnu-objcopy")
    parser.add_argument("--base", type=lambda value: int(value, 0), default=0x1000)
    parser.add_argument("--batch-size", type=int, default=4096)
    parser.add_argument("--delay", type=float, default=0.10)
    parser.add_argument("--timeout", type=float, default=4.0)
    parser.add_argument("--false-predicate", type=int, default=1,
                        help="set every slot qp field to this false predicate; use -1 to disable")
    parser.add_argument("--strict", action="store_true",
                        help="also report coarse mnemonic mismatches")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--max-issues", type=int, default=80)
    parser.add_argument("--limit-bundles", type=int)
    parser.add_argument("--rerun-missing-limit", type=int, default=256,
                        help="rerun this many missing bundles individually")
    args = parser.parse_args()

    tools = {
        "as": args.assembler,
        "objcopy": args.objcopy,
        "objdump": args.objdump,
    }
    false_predicate = args.false_predicate
    if false_predicate < 0:
        false_predicate = None
    elif false_predicate == 0 or false_predicate > 63:
        parser.error("--false-predicate must be -1 or a predicate number from 1 to 63")

    with tempfile.TemporaryDirectory(prefix="ia64-compare-decode-") as tmp:
        tmpdir = Path(tmp)
        data = load_inputs(args.inputs, args.kind, tools, tmpdir)
        bundles, skipped_tail = split_bundles(data, false_predicate)
        if args.limit_bundles is not None:
            bundles = bundles[: args.limit_bundles]
        raw_path = tmpdir / "mutated.bin"
        raw_path.write_bytes(b"".join(bundles))

        opcode_names = parse_opcode_enum()
        objdump_map, _ = objdump_slots(raw_path, args.objdump)
        qemu_map, _ = collect_qemu_decode(args.qemu, bundles, opcode_names, args)
        issues = compare(objdump_map, qemu_map, args.strict)
        print_report(bundles, skipped_tail, objdump_map, qemu_map, issues, args)

    return 1 if any(issue["kind"] == "qemu-invalid" for issue in issues) else 0


if __name__ == "__main__":
    sys.exit(main())
