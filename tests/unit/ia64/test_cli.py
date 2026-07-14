#!/usr/bin/env python3
"""Behavior tests for IA-64-related character-device CLI ownership."""

from __future__ import annotations

import os
import socket
import subprocess
import sys
import tempfile
import time


def test_duplicate_debug_port(qemu: str) -> None:
    result = subprocess.run([
        qemu, "-machine", "none", "-display", "none", "-monitor", "none",
        "-serial", "none", "-debug-port", "none", "-debug-port", "none",
    ], check=False, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        text=True, timeout=8)
    if result.returncode == 0 or \
            "only one -debug-port option is supported" not in result.stdout:
        raise RuntimeError("multiple -debug-port options were not rejected\n" +
                           result.stdout)


def _wait_unix_socket(path: str, proc: subprocess.Popen, timeout_s: float) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            output, _ = proc.communicate(timeout=1)
            raise RuntimeError(f"QEMU exited before QMP became ready\n{output}")
        try:
            with socket.socket(socket.AF_UNIX) as client:
                client.settimeout(0.1)
                client.connect(path)
                return
        except OSError:
            time.sleep(0.01)
    raise RuntimeError("QMP socket did not become ready")


def test_nographic_debug_stdio(qemu: str) -> None:
    with tempfile.TemporaryDirectory(prefix="ia64-cli-") as tmpdir:
        qmp_path = os.path.join(tmpdir, "qmp.sock")
        proc = subprocess.Popen([
            qemu, "-machine", "none", "-S", "-nographic",
            "-monitor", "none", "-serial", "none",
            "-qmp", f"unix:{qmp_path},server=on,wait=off",
            "-debug-port", "stdio",
        ], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, text=True)
        try:
            _wait_unix_socket(qmp_path, proc, 3.0)
        finally:
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=2)


def test_debug_tcp_server(qemu: str) -> None:
    probe = socket.socket()
    try:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    finally:
        probe.close()

    proc = subprocess.Popen([
        qemu, "-machine", "none", "-S", "-display", "none",
        "-monitor", "none", "-serial", "none",
        "-debug-port", f"tcp:127.0.0.1:{port},server=on,wait=off",
    ], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    connected = False
    output = ""
    try:
        deadline = time.monotonic() + 3.0
        while time.monotonic() < deadline:
            if proc.poll() is not None:
                output, _ = proc.communicate(timeout=1)
                break
            try:
                with socket.create_connection(("127.0.0.1", port),
                                              timeout=0.1):
                    connected = True
                    break
            except OSError:
                time.sleep(0.01)
        if not connected:
            raise RuntimeError("debug TCP server did not accept a client\n" +
                               output)
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
        print("Bail out! usage: test_cli.py QEMU_SYSTEM_IA64")
        return 1
    tests = [
        ("duplicate debug-port rejected", test_duplicate_debug_port),
        ("debug-port owns nographic stdio", test_nographic_debug_stdio),
        ("debug-port TCP server accepts", test_debug_tcp_server),
    ]
    print("TAP version 13")
    print(f"1..{len(tests)}")
    failed = 0
    for index, (name, function) in enumerate(tests, 1):
        try:
            function(sys.argv[1])
            print(f"ok {index} - {name}")
        except Exception as exc:
            failed += 1
            print(f"not ok {index} - {name}")
            for line in str(exc).splitlines():
                print(f"# {line}")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
