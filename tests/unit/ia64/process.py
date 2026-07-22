"""Shared process and endpoint lifecycle helpers for IA-64 tests."""

from __future__ import annotations

import socket
import subprocess
import time


def _exited_output(proc: subprocess.Popen[str]) -> str:
    """Return any remaining text output after *proc* has exited."""
    if proc.poll() is None:
        return ""
    try:
        stdout, stderr = proc.communicate(timeout=0.2)
    except (subprocess.TimeoutExpired, ValueError):
        return ""
    return (stdout or "") + (stderr or "")


def kill_process(proc: subprocess.Popen[str], timeout_s: float = 2.0) -> None:
    """Kill *proc* if needed and synchronously reap it."""
    if proc.poll() is not None:
        return
    proc.kill()
    proc.wait(timeout=timeout_s)


def terminate_process(proc: subprocess.Popen[str],
                      timeout_s: float = 2.0) -> None:
    """Terminate and reap *proc*, escalating to SIGKILL on timeout."""
    if proc.poll() is not None:
        return
    proc.terminate()
    try:
        proc.wait(timeout=timeout_s)
    except subprocess.TimeoutExpired:
        kill_process(proc, timeout_s)


def _early_exit(proc: subprocess.Popen[str], description: str) -> None:
    output = _exited_output(proc)
    suffix = f"\n{output}" if output else ""
    raise RuntimeError(f"{description}: QEMU exited before it was ready{suffix}")


def connect_tcp(proc: subprocess.Popen[str], host: str, port: int,
                timeout_s: float, description: str) -> socket.socket:
    """Connect to a TCP endpoint while checking its owning process."""
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            _early_exit(proc, description)
        try:
            client = socket.create_connection((host, port), timeout=0.1)
            client.settimeout(timeout_s)
            return client
        except OSError:
            time.sleep(0.01)
    if proc.poll() is not None:
        _early_exit(proc, description)
    raise RuntimeError(f"{description}: timed out after {timeout_s:.1f}s")


def connect_unix(proc: subprocess.Popen[str], path: str, timeout_s: float,
                 description: str) -> socket.socket:
    """Connect to a Unix endpoint while checking its owning process."""
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            _early_exit(proc, description)
        client = socket.socket(socket.AF_UNIX)
        client.settimeout(0.1)
        try:
            client.connect(path)
            client.settimeout(timeout_s)
            return client
        except OSError:
            client.close()
            time.sleep(0.01)
    if proc.poll() is not None:
        _early_exit(proc, description)
    raise RuntimeError(f"{description}: timed out after {timeout_s:.1f}s")
