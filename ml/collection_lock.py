"""Kernel-held mutex for a checkout's mutating collection operations.

The file is a stable lock target, not a PID sentinel. Never unlink it to recover
from a crash: closing the descriptor (including process exit) releases the lock.
"""

from __future__ import annotations

import os
from contextlib import contextmanager
from pathlib import Path


class CollectionLockError(RuntimeError):
    pass


@contextmanager
def collection_operation(project_root: Path):
    lock_path = project_root.resolve() / "evidence/.collection-operation.lock"
    try:
        lock_path.parent.mkdir(parents=True, exist_ok=True)
        handle = lock_path.open("a+b")
    except OSError as exc:
        raise CollectionLockError(f"cannot open collection operation lock: {exc}") from exc
    try:
        try:
            if os.name == "nt":
                import msvcrt

                if os.fstat(handle.fileno()).st_size == 0:
                    handle.write(b"\0")
                    handle.flush()
                handle.seek(0)
                msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl

                fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            raise CollectionLockError(
                "collection operation is busy/locked; stop or wait for the foreground "
                "collector before retrying; never delete the lock file"
            ) from exc
        yield
    finally:
        handle.close()
