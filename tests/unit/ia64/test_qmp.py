#!/usr/bin/env python3
"""Pure regression tests for the IA-64 QMP client."""

from __future__ import annotations

from collections import deque
import os
from pathlib import Path
import sys
import tempfile
import unittest

if __package__ in (None, ""):
    sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
    from ia64.qmp import QmpClient
    from ia64.runner import (Completion, ExpectedExit, MicroProgram,
                             run_expected_exit)
    from ia64.state import StateExpectation
else:
    from .qmp import QmpClient
    from .runner import (Completion, ExpectedExit, MicroProgram,
                         run_expected_exit)
    from .state import StateExpectation


class QmpClientTest(unittest.TestCase):
    def test_two_messages_buffered_by_one_read(self) -> None:
        """A buffered second line must not wait for fd readability again."""
        read_fd, write_fd = os.pipe()
        reader = os.fdopen(read_fd, "r", encoding="utf-8")
        try:
            client = object.__new__(QmpClient)
            client.reader = reader
            client.events = deque()
            client._read_buffer = bytearray()

            os.write(
                write_fd,
                b'{"return":{"enabled":true}}\n{"event":"STOP"}\n',
            )
            self.assertEqual(
                client._read_message(0.1),
                {"return": {"enabled": True}},
            )
            self.assertEqual(
                client._read_message(0.1),
                {"event": "STOP"},
            )
        finally:
            os.close(write_fd)
            reader.close()

    def test_expected_exit_may_close_before_cont_reply(self) -> None:
        """The fatal guest path may win the race with the QMP response."""
        with tempfile.TemporaryDirectory() as temporary:
            qemu = Path(temporary) / "fake-qemu"
            qemu.write_text(
                """#!/usr/bin/env python3
import json
import sys

print(json.dumps({"QMP": {"version": {}, "capabilities": []}}),
      flush=True)
request = json.loads(sys.stdin.readline())
print(json.dumps({"return": {}, "id": request["id"]}), flush=True)
sys.stdin.readline()
print("expected-fatal-diagnostic", file=sys.stderr, flush=True)
raise SystemExit(7)
""",
                encoding="utf-8")
            qemu.chmod(0o755)
            program = MicroProgram(
                name="expected-exit-qmp-race",
                bundles=(),
                entry=0,
                expected=StateExpectation(),
                completion=Completion(terminal_ip=None, timeout_s=1.0),
                expected_exit=ExpectedExit(
                    returncode=7,
                    stderr_contains=("expected-fatal-diagnostic",)),
            )
            output = run_expected_exit(str(qemu), program)
            self.assertIn("expected-fatal-diagnostic", output)


if __name__ == "__main__":
    unittest.main()
