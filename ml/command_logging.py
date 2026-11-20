"""Stream Colab subprocess output and keep one ordered, durable transcript."""

from __future__ import annotations

import codecs
import contextlib
import os
import signal
import subprocess
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path


def display_line(text: str) -> None:
    print(text, end="", flush=True)


def _stop_processes(process: subprocess.Popen) -> None:
    if os.name == "posix":
        # A failed leader can leave children alive, including ones ignoring SIGTERM.
        with contextlib.suppress(ProcessLookupError):
            os.killpg(process.pid, signal.SIGKILL)
    elif process.poll() is None:
        process.kill()
    process.wait()


def run_logged(phase: str, command: Sequence[str | Path], log: Path, *, env=None) -> None:
    """Run an argv without a shell. In Colab each phase owns its process group."""
    log.parent.mkdir(parents=True, exist_ok=True)
    with log.open("ab", buffering=0) as writer, log.open("rb") as reader:
        def status(message: str) -> None:
            line = f"[{datetime.now(UTC).isoformat(timespec='seconds')}] {phase}: {message}\n"
            writer.write(line.encode("utf-8"))
            display_line(line)

        status("started")
        reader.seek(0, os.SEEK_END)
        decoder = codecs.getincrementaldecoder("utf-8")(errors="replace")

        def forward(*, final: bool = False) -> None:
            while chunk := reader.read(65536):
                display_line(decoder.decode(chunk))
            if final and (tail := decoder.decode(b"", final=True)):
                display_line(tail)

        try:
            process = subprocess.Popen(
                command, stdout=writer, stderr=subprocess.STDOUT,
                start_new_session=os.name == "posix",
                env={**(os.environ if env is None else env), "PYTHONUNBUFFERED": "1"},
            )
        except OSError as exc:
            status(f"failed to start ({type(exc).__name__}: {exc})")
            raise
        try:
            while process.poll() is None:
                forward()
                with contextlib.suppress(subprocess.TimeoutExpired):
                    process.wait(timeout=0.15)
            if process.returncode:
                raise subprocess.CalledProcessError(process.returncode, command)
        except BaseException as exc:
            _stop_processes(process)
            forward(final=True)
            status(f"failed ({type(exc).__name__}, exit={process.returncode})")
            raise
        forward(final=True)
        status("completed (exit=0)")
