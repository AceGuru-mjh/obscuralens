"""
Single-instance lock for the ObscuraLens desktop launcher.

The desktop edition is a *local* application: two copies racing for the
same port, the same SQLite database and the same cache directory would
produce confusing behaviour, so the launcher refuses to start when another
instance is already running.

Implementation notes
--------------------
* The lock is a small file named ``desktop.lock`` inside the ObscuraLens
  config directory (``OBSCURALENS_CONFIG_DIR`` when set, otherwise the
  platform user directory: ``%APPDATA%\\ObscuraLens`` on Windows,
  ``~/Library/Caches/obscuralens`` on macOS and
  ``$XDG_CACHE_HOME/obscuralens`` otherwise).
* Creation is atomic: ``os.open(path, O_CREAT | O_EXCL | O_WRONLY)``.  If
  the file already exists we probe the recorded PID.
* Stale-lock detection is platform aware.  On POSIX, ``os.kill(pid, 0)``
  tells us whether the owning process still exists (``ProcessLookupError``
  means it is gone, ``PermissionError`` means it belongs to another user
  and is very much alive).  Windows has no such probe, so there an owner
  that has not touched the lock for more than 24 hours is presumed dead.
* Everything here is standard-library only, never raises, and works with
  ASCII-safe paths on every platform.
"""

import contextlib
import os
import sys
import time
from pathlib import Path
from typing import Any, Dict, Optional, Union

#: Lock file name inside the resolved lock directory.
LOCK_FILE_NAME = "desktop.lock"

#: Age (seconds) after which an unreadable or Windows-side lock is stale.
STALE_AFTER_SECONDS = 24 * 60 * 60

#: Environment variable pointing at the ObscuraLens config directory.
CONFIG_DIR_ENV = "OBSCURALENS_CONFIG_DIR"

PathLike = Union[str, os.PathLike]


# ---------------------------------------------------------------------------
# Path + PID helpers
# ---------------------------------------------------------------------------

def default_lock_dir() -> Path:
    """Directory that hosts the desktop lock file (never raises)."""
    env = os.environ.get(CONFIG_DIR_ENV, "").strip()
    if env:
        return Path(env)
    try:
        if os.name == "nt":
            base = os.getenv("APPDATA") or str(Path.home())
            return Path(base) / "ObscuraLens"
        if sys.platform == "darwin":
            return Path.home() / "Library" / "Caches" / "obscuralens"
        base = os.getenv("XDG_CACHE_HOME") or str(Path.home() / ".cache")
        return Path(base) / "obscuralens"
    except Exception:  # pragma: no cover - Path.home() can fail oddly
        return Path(os.getcwd())


def default_lock_path() -> Path:
    """Full default path of the desktop lock file."""
    return default_lock_dir() / LOCK_FILE_NAME


def _pid_alive(pid: int) -> bool:
    """
    Whether a process with this PID exists right now.

    POSIX uses the ``os.kill(pid, 0)`` probe; a ``PermissionError`` means
    the process exists but is owned by someone else.  On Windows there is
    no reliable probe, so we conservatively report ``True`` and let the
    age-based staleness rule (see :meth:`InstanceLock.acquire`) decide.
    """
    if not pid or pid <= 0:
        return False
    if os.name == "nt":  # pragma: no cover - exercised only on Windows
        return True
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True  # exists, but belongs to another user
    except OSError:
        return True  # unknown failure: assume alive (conservative)
    return True


def lock_info(path: PathLike) -> Optional[Dict[str, Any]]:
    """
    Read the lock file at *path*; ``None`` when it does not exist.

    The returned dictionary has ``pid`` (``int`` or ``None`` when the first
    line is not a number), ``age_seconds`` (since the file's mtime),
    ``mtime``, ``path`` and ``alive`` (whether the PID currently exists,
    POSIX-only semantics -- always ``False`` for a missing PID).
    """
    target = Path(path)
    try:
        stat = target.stat()
    except OSError:
        return None
    pid: Optional[int] = None
    try:
        with open(target, "r", encoding="utf-8", errors="replace") as handle:
            first = handle.readline().strip()
        pid = int(first) if first.isdigit() else None
    except (OSError, ValueError):
        pid = None
    age = max(0.0, time.time() - stat.st_mtime)
    return {
        "pid": pid,
        "age_seconds": age,
        "mtime": stat.st_mtime,
        "path": str(target),
        "alive": _pid_alive(pid) if pid else False,
    }


def lock_url(path: PathLike) -> str:
    """
    URL recorded in the lock file by a running instance ("" when absent).

    The launcher writes ``pid / timestamp / url``; a second instance uses
    this to tell the user *where* the running desktop UI lives.
    """
    try:
        with open(Path(path), "r", encoding="utf-8", errors="replace") as handle:
            lines = handle.read().splitlines()
    except OSError:
        return ""
    for line in lines[2:]:
        candidate = line.strip()
        if candidate.startswith("http://") or candidate.startswith("https://"):
            return candidate
    return ""


# ---------------------------------------------------------------------------
# The lock object
# ---------------------------------------------------------------------------

class InstanceLock:
    """
    Cooperative single-instance lock backed by one small file.

    Usage::

        lock = InstanceLock()          # or InstanceLock(path=tmp_path/"desktop.lock")
        if not lock.acquire():
            print("already running at", lock_url(lock.path))
        try:
            ...
        finally:
            lock.release()

    or as a context manager (refused acquisition raises ``RuntimeError``)::

        with InstanceLock() as lock:
            ...

    Every method is exception-free; failures simply report ``False``.
    """

    def __init__(self,
                 path: Optional[PathLike] = None,
                 stale_after: float = STALE_AFTER_SECONDS):
        self.path = Path(path) if path is not None else default_lock_path()
        self.stale_after = float(stale_after)
        self.held = False
        self.pid = os.getpid()

    # -- internals -------------------------------------------------------

    def _create_exclusive(self) -> Optional[int]:
        """Atomically create the lock file; ``None`` if it already exists."""
        try:
            return os.open(str(self.path), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o644)
        except FileExistsError:
            return None
        except OSError:
            return None

    def _is_stale(self) -> bool:
        """Whether an existing lock file may be taken over."""
        info = lock_info(self.path)
        if info is None:
            return True  # vanished between the failed create and the probe
        pid = info["pid"]
        age = float(info["age_seconds"])
        if pid is None:
            # Unparseable owner: only reclaim old files, never fresh ones.
            return age >= self.stale_after
        if os.name == "nt":  # pragma: no cover - Windows has no PID probe
            return age >= self.stale_after
        return not _pid_alive(pid)

    def _write_payload(self, url: str = "") -> None:
        """(Re)write ``pid / timestamp / url`` into the held lock file."""
        payload = "{0}\n{1}\n{2}\n".format(os.getpid(), int(time.time()), url or "")
        # Payload is informational; the lock itself still works without it.
        with contextlib.suppress(OSError), open(self.path, "w", encoding="utf-8") as handle:
            handle.write(payload)

    # -- public API ------------------------------------------------------

    def acquire(self) -> bool:
        """
        Try to become the single desktop instance.

        Returns ``True`` when the lock is ours (freshly created or a stale
        lock was reclaimed); ``False`` when another live instance owns it
        or the lock directory is not writable.  Never raises.
        """
        if self.held:
            return True
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
        except OSError:
            return False

        fd = self._create_exclusive()
        if fd is None:
            if not self._is_stale():
                return False
            try:
                self.path.unlink()
            except OSError:
                return False
            fd = self._create_exclusive()
            if fd is None:
                return False

        try:
            payload = "{0}\n{1}\n".format(os.getpid(), int(time.time()))
            os.write(fd, payload.encode("utf-8"))
        except OSError:
            pass  # informational payload; the O_EXCL file is the real lock
        finally:
            with contextlib.suppress(OSError):
                os.close(fd)

        self.held = True
        self.pid = os.getpid()
        return True

    def release(self) -> None:
        """
        Release the lock (idempotent, never raises).

        The file is only removed when it still refers to this process, so a
        lock that was reclaimed by a newer instance is never clobbered.
        """
        if not self.held:
            return
        self.held = False
        info = lock_info(self.path)
        with contextlib.suppress(OSError):
            if info is None or info.get("pid") in (None, self.pid):
                self.path.unlink()

    def write_url(self, url: str) -> None:
        """Record the serving URL inside a *held* lock (best effort)."""
        if not self.held:
            return
        self._write_payload(url)

    @classmethod
    def stale_lock_path(cls) -> Path:
        """
        Where stale locks accumulate (the default lock file location).

        Handy for cleanup tooling and diagnostics: ``desktop.lock`` in the
        resolved config/user-cache directory.
        """
        return default_lock_path()

    # -- context manager -------------------------------------------------

    def __enter__(self) -> "InstanceLock":
        if not self.acquire():
            raise RuntimeError(
                "another ObscuraLens Desktop instance is running "
                "(lock: {0})".format(self.path)
            )
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> bool:
        self.release()
        return False  # never suppress exceptions


__all__ = [
    "CONFIG_DIR_ENV",
    "InstanceLock",
    "LOCK_FILE_NAME",
    "STALE_AFTER_SECONDS",
    "default_lock_dir",
    "default_lock_path",
    "lock_info",
    "lock_url",
]
