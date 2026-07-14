#!/usr/bin/env python3
"""End-to-end IA-64 GDB remote-protocol regression test."""

from __future__ import annotations

import re
import socket
import struct
import subprocess
import sys
import time

from qmp import QmpClient


GDB_PORT = 1234
GDB_NUM_RAW_REGS = 462
GDB_RAW_REGISTER_BYTES = 128 * 8 + 128 * 16 + (GDB_NUM_RAW_REGS - 256) * 8

# Establish a five-register clean RSE partition: set BSPSTORE, allocate and
# populate a frame, cover it, then flushrs.  The bytes are the same instruction
# sequence used by rse_cover_flushrs_spills_covered_frame in encoding.py.
RSE_CLEAN_PROGRAM = bytes.fromhex(
    "04000000010000000000006000000260"
    "01000c242a0400000002000000000400"
    "00081406800500000002000000000400"
    "04000000010000000000000014018860"
    "04000000010000000000002024021061"
    "04000000010000000000004034039861"
    "04000000010000000000006044042062"
    "0400000001000000000000805405a862"
    "19000000010000000002000000000800"
    "000000000c0000000002000000000400"
)


class RspClient:
    def __init__(self, sock: socket.socket) -> None:
        self.sock = sock

    def _byte(self) -> int:
        value = self.sock.recv(1)
        if not value:
            raise RuntimeError("GDB connection closed while reading a packet")
        return value[0]

    def request(self, payload: str) -> str:
        encoded = payload.encode("ascii")
        checksum = sum(encoded) & 0xff
        self.sock.sendall(b"$" + encoded + b"#" + f"{checksum:02x}".encode())

        ack = self._byte()
        if ack != ord("+"):
            raise RuntimeError(
                f"GDB stub did not acknowledge {payload!r}: byte 0x{ack:02x}")

        while self._byte() != ord("$"):
            pass

        wire = bytearray()
        escaped = False
        while True:
            byte = self._byte()
            if byte == ord("#") and not escaped:
                break
            wire.append(byte)
            escaped = byte == ord("}") and not escaped
            if byte != ord("}"):
                escaped = False

        received_checksum = int(bytes((self._byte(), self._byte())), 16)
        actual_checksum = sum(wire) & 0xff
        if received_checksum != actual_checksum:
            self.sock.sendall(b"-")
            raise RuntimeError(
                f"bad RSP checksum: got {received_checksum:02x}, "
                f"calculated {actual_checksum:02x}")
        self.sock.sendall(b"+")

        decoded = bytearray()
        index = 0
        while index < len(wire):
            if wire[index] == ord("}"):
                index += 1
                if index == len(wire):
                    raise RuntimeError("truncated RSP escape")
                decoded.append(wire[index] ^ 0x20)
            else:
                decoded.append(wire[index])
            index += 1
        return decoded.decode("ascii")


def _connect(proc: subprocess.Popen[str], timeout_s: float) -> socket.socket:
    deadline = time.monotonic() + timeout_s
    output = ""
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            stdout, stderr = proc.communicate(timeout=1)
            output = (stdout or "") + (stderr or "")
            break
        try:
            client = socket.create_connection(("127.0.0.1", GDB_PORT), 0.1)
            client.settimeout(3.0)
            return client
        except OSError:
            time.sleep(0.01)
    raise RuntimeError("QEMU -s did not open TCP port 1234\n" + output)


def _reg_offset(reg: int) -> int:
    if reg < 128:
        return reg * 8
    if reg < 256:
        return 128 * 8 + (reg - 128) * 16
    return 128 * 8 + 128 * 16 + (reg - 256) * 8


def _read_reg(rsp: RspClient, reg: int, size: int) -> bytes:
    reply = rsp.request(f"p{reg:x}")
    try:
        value = bytes.fromhex(reply)
    except ValueError as exc:
        raise RuntimeError(f"register {reg} returned non-hex data {reply!r}") from exc
    if len(value) != size:
        raise RuntimeError(
            f"register {reg} has {len(value)} bytes, expected {size}: {reply!r}")
    return value


def _write_reg(rsp: RspClient, reg: int, value: bytes) -> None:
    reply = rsp.request(f"P{reg:x}={value.hex()}")
    if reply != "OK":
        raise RuntimeError(f"register {reg} write failed: {reply!r}")


def _expect_round_trip(rsp: RspClient, reg: int, value: bytes) -> None:
    _write_reg(rsp, reg, value)
    actual = _read_reg(rsp, reg, len(value))
    if actual != value:
        raise RuntimeError(
            f"register {reg} round trip changed {value.hex()} to {actual.hex()}")


def _rse_state(qmp: QmpClient) -> tuple[int, ...]:
    registers = qmp.hmp("info registers")
    match = re.search(
        r"RSE: bol=(\d+) dirty=(\d+)/(\d+) clean=(\d+)/(\d+) "
        r"invalid=(\d+)", registers)
    if match is None:
        raise RuntimeError("info registers did not contain the RSE state:\n" +
                           registers)
    return tuple(int(value) for value in match.groups())


def test_gdbstub(qemu: str) -> None:
    proc = subprocess.Popen([
        qemu,
        "-machine", "ia64-vpc",
        "-nodefaults",
        "-display", "none",
        "-monitor", "none",
        "-qmp", "stdio",
        "-serial", "none",
        "-S",
        "-s",
    ], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, text=True, bufsize=1)
    try:
        if proc.stdin is None or proc.stdout is None:
            raise RuntimeError("QEMU QMP pipes were not created")
        qmp = QmpClient(proc.stdout, proc.stdin)
        with _connect(proc, 3.0) as sock:
            rsp = RspClient(sock)
            stop = rsp.request("?")
            if not stop.startswith("T05"):
                raise RuntimeError(f"unexpected initial GDB stop reply: {stop!r}")

            all_regs_hex = rsp.request("g")
            try:
                all_regs = bytes.fromhex(all_regs_hex)
            except ValueError as exc:
                raise RuntimeError("g packet was not hexadecimal") from exc
            if len(all_regs) != GDB_RAW_REGISTER_BYTES:
                raise RuntimeError(
                    f"g packet has {len(all_regs)} bytes, expected "
                    f"{GDB_RAW_REGISTER_BYTES}")

            # The raw layout is 128 GRs, 128 128-bit FRs, 64 PRs, 8 BRs,
            # two virtual registers, PR/IP/PSR/CFM, and 128 ARs.
            if all_regs[_reg_offset(0):_reg_offset(0) + 8] != bytes(8):
                raise RuntimeError("architectural r0 was not zero")
            if struct.unpack_from("<Q", all_regs, _reg_offset(256))[0] != 1:
                raise RuntimeError("architectural p0 was not true")
            if struct.unpack_from("<Q", all_regs, _reg_offset(330))[0] != 1:
                raise RuntimeError("aggregate predicate register was not 1")

            # A same-value mov-to-BSPSTORE is not architecturally inert: it
            # invalidates the RSE clean partition.  Debugger register restores
            # must therefore bypass that setter when BSPSTORE is unchanged.
            if rsp.request(
                    f"M10,{len(RSE_CLEAN_PROGRAM):x}:"
                    f"{RSE_CLEAN_PROGRAM.hex()}") != "OK":
                raise RuntimeError("GDB memory write for RSE probe failed")
            # ia64-vpc enters firmware with RSC.mode=lazy; mov-to-BSPSTORE
            # and flushrs require enforced-lazy mode (mode=0).
            _write_reg(rsp, 350, bytes(8))
            _write_reg(rsp, 331, struct.pack("<Q", 0x10))
            _write_reg(rsp, 332, bytes(8))
            current_ip = 0
            for _ in range(64):
                current_ip = struct.unpack("<Q", _read_reg(rsp, 331, 8))[0]
                if current_ip == 0xb0:
                    break
                step = rsp.request("s")
                if not step.startswith("T05"):
                    raise RuntimeError(
                        f"unexpected RSE probe single-step reply: {step!r}")
            else:
                raise RuntimeError(
                    "RSE probe did not reach the post-flushrs IP; "
                    f"last IP was 0x{current_ip:x}")

            rse_before = _rse_state(qmp)
            if rse_before[3] == 0:
                raise RuntimeError(
                    f"RSE probe did not establish a clean partition: "
                    f"{rse_before!r}")
            bspstore = _read_reg(rsp, 352, 8)
            _write_reg(rsp, 352, bspstore)
            rse_after_p = _rse_state(qmp)
            if rse_after_p != rse_before:
                raise RuntimeError(
                    "same-value AR.BSPSTORE P write changed RSE state from "
                    f"{rse_before!r} to {rse_after_p!r}")

            rse_regs = rsp.request("g")
            if rsp.request("G" + rse_regs) != "OK":
                raise RuntimeError("RSE-state G register echo was rejected")
            if len(bytes.fromhex(rsp.request("g"))) != GDB_RAW_REGISTER_BYTES:
                raise RuntimeError(
                    "full G write corrupted the raw register layout")
            rse_after_g = _rse_state(qmp)
            if rse_after_g != rse_before:
                raise RuntimeError(
                    "same-value AR.BSPSTORE g/G echo changed RSE state from "
                    f"{rse_before!r} to {rse_after_g!r}")

            gr_value = struct.pack("<Q", 0x1122334455667788)
            _expect_round_trip(rsp, 2, gr_value)

            # IA-64 FRs use the 16-byte spill representation on the wire.
            fp_value = struct.pack("<QQ", 0x0123456789abcdef, 0x1003e)
            _expect_round_trip(rsp, 130, fp_value)

            _expect_round_trip(rsp, 257, struct.pack("<Q", 1))
            _write_reg(rsp, 256, bytes(8))
            if _read_reg(rsp, 256, 8) != struct.pack("<Q", 1):
                raise RuntimeError("GDB write changed constant predicate p0")

            predicate_value = 1 | (1 << 2) | (1 << 63)
            _expect_round_trip(rsp, 330, struct.pack("<Q", predicate_value))
            if _read_reg(rsp, 258, 8) != struct.pack("<Q", 1):
                raise RuntimeError("aggregate PR write did not update p2")

            _expect_round_trip(rsp, 320,
                               struct.pack("<Q", 0xfeedfacecafebeef))
            _expect_round_trip(rsp, 331, struct.pack("<Q", 0x100000))
            _expect_round_trip(rsp, 332, struct.pack("<Q", 1 << 41))
            _expect_round_trip(rsp, 334,
                               struct.pack("<Q", 0xa5a55a5a11223344))

            _write_reg(rsp, 0, struct.pack("<Q", 0xffffffffffffffff))
            if _read_reg(rsp, 0, 8) != bytes(8):
                raise RuntimeError("GDB write changed constant general register r0")

            # The raw PR register is a physical file.  GDB applies RRB.PR
            # when presenting logical $p16..$p63.  Put physical bit 39 under
            # RRB.PR=23: it must become logical p16 inside the CPU and guard
            # the predicated adds below.
            _write_reg(rsp, 333, struct.pack("<Q", 23 << 32))
            rotated_pr = 1 | (1 << 39)
            _write_reg(rsp, 330, struct.pack("<Q", rotated_pr))
            if _read_reg(rsp, 330, 8) != struct.pack("<Q", rotated_pr):
                raise RuntimeError("RRB.PR changed the raw physical PR file")

            # MII: nop.m; (p16) adds r2=0x5a,r0; nop.i.
            bundle = bytes.fromhex("00000000010024d00200420000000400")
            if rsp.request(f"M100000,10:{bundle.hex()}") != "OK":
                raise RuntimeError("GDB memory write for predicate probe failed")
            _write_reg(rsp, 2, bytes(8))
            _write_reg(rsp, 331, struct.pack("<Q", 0x100000))
            _write_reg(rsp, 332, bytes(8))
            for _ in range(3):
                step = rsp.request("s")
                if not step.startswith("T05"):
                    raise RuntimeError(f"unexpected single-step reply: {step!r}")
                if _read_reg(rsp, 2, 8) == struct.pack("<Q", 0x5a):
                    break
            else:
                raise RuntimeError(
                    "physical PR bit 39 did not select logical p16 at RRB.PR=23")

            cfm = _read_reg(rsp, 333, 8)
            _write_reg(rsp, 333,
                       struct.pack("<Q", (23 << 32) | 4 | (2 << 7)))
            if _read_reg(rsp, 333, 8) != cfm:
                raise RuntimeError("unsafe GDB CFM frame-shape write was accepted")

            # AR writes must use the architectural state setters: BSP is
            # derived/read-only, BSPSTORE rebases BSP, EC is six bits, and
            # reserved ARs ignore writes.
            old_bsp = _read_reg(rsp, 351, 8)
            _write_reg(rsp, 351, struct.pack("<Q", 0xdeadbeef))
            if _read_reg(rsp, 351, 8) != old_bsp:
                raise RuntimeError("GDB write modified derived AR.BSP")

            _write_reg(rsp, 352, struct.pack("<Q", 0x1000))
            if _read_reg(rsp, 352, 8) != struct.pack("<Q", 0x1000) or \
                    _read_reg(rsp, 351, 8) != struct.pack("<Q", 0x1000):
                raise RuntimeError("AR.BSPSTORE write did not rebase AR.BSP")

            _write_reg(rsp, 400, struct.pack("<Q", 0xffffffffffffffff))
            if _read_reg(rsp, 400, 8) != struct.pack("<Q", 0x3f):
                raise RuntimeError("AR.EC write bypassed its six-bit mask")

            reserved = _read_reg(rsp, 446, 8)
            _write_reg(rsp, 446, struct.pack("<Q", 0xdeadbeef))
            if _read_reg(rsp, 446, 8) != reserved:
                raise RuntimeError("GDB write modified reserved AR112")
    finally:
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=2)


def main() -> int:
    if len(sys.argv) != 2:
        print("Bail out! usage: test_gdbstub.py QEMU_SYSTEM_IA64")
        return 1
    print("TAP version 13")
    print("1..1")
    try:
        test_gdbstub(sys.argv[1])
        print("ok 1 - IA-64 -s GDB register protocol")
        return 0
    except Exception as exc:
        print("not ok 1 - IA-64 -s GDB register protocol")
        for line in str(exc).splitlines():
            print(f"# {line}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
