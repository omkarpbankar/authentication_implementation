"""Helpers for live checks: start real servers, wait until they answer, stop them after."""

import contextlib
import socket
import subprocess
import sys
import time
from collections.abc import Iterator
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def wait_for_port(port: int, timeout: float = 30) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        with contextlib.suppress(OSError), socket.create_connection(("127.0.0.1", port), 0.5):
            return
        time.sleep(0.2)
    raise TimeoutError(f"Nothing answered on port {port}")


@contextlib.contextmanager
def servers(*apps: tuple[str, int], env: dict[str, str] | None = None) -> Iterator[None]:
    """Each app is ("module:attribute", port)."""
    import os

    processes = [
        subprocess.Popen(
            [
                sys.executable,
                "-m",
                "uvicorn",
                target,
                "--port",
                str(port),
                "--log-level",
                "warning",
            ],
            cwd=ROOT,
            env={**os.environ, "LOG_LEVEL": "WARNING", **(env or {})},
        )
        for target, port in apps
    ]
    try:
        for _, port in apps:
            wait_for_port(port)
        yield
    finally:
        for process in processes:
            process.terminate()
        for process in processes:
            process.wait(timeout=10)


class Report:
    def __init__(self) -> None:
        self.failures = 0

    def check(self, label: str, passed: bool) -> None:
        print(f"[{'PASS' if passed else 'FAIL'}] {label}")
        self.failures += 0 if passed else 1

    def finish(self) -> None:
        print(
            "\nAll checks passed." if not self.failures else f"\n{self.failures} check(s) failed."
        )
        sys.exit(1 if self.failures else 0)
