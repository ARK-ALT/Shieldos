"""
ShieldOS Engine — Real-Time File System Monitor
Uses watchdog library to scan files on creation/modification.
"""
import logging
import os
import sys
import threading
from pathlib import Path
from typing import Optional

from config import get_config

log = logging.getLogger("shieldos.realtime")

try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler
    WATCHDOG_AVAILABLE = True
except ImportError:
    log.warning("watchdog not installed — real-time protection unavailable")
    WATCHDOG_AVAILABLE = False


def _default_watch_paths() -> list[str]:
    """Return platform-appropriate default watch paths."""
    home = str(Path.home())
    paths: list[str] = []

    if sys.platform == "win32":
        paths = [
            home,
            os.path.join(home, "Downloads"),
            os.path.join(os.environ.get("TEMP", "C:\\Windows\\Temp")),
            os.path.join(os.environ.get("APPDATA", home), "Local", "Temp"),
            "C:\\Windows\\Temp",
        ]
    elif sys.platform == "darwin":
        paths = [
            home,
            os.path.join(home, "Downloads"),
            "/tmp",
            "/Applications",
        ]
    else:   # Linux / BSD
        paths = [
            home,
            os.path.join(home, "Downloads"),
            "/tmp",
            "/var/tmp",
            "/usr/local/bin",
        ]

    # Add user-configured watch paths
    cfg = get_config()
    extra = cfg.get("watch_paths", [])
    if isinstance(extra, list):
        paths.extend(extra)

    # Deduplicate while preserving order
    seen: set[str] = set()
    result: list[str] = []
    for p in paths:
        if p not in seen and Path(p).exists():
            seen.add(p)
            result.append(p)

    return result


class _ScanEventHandler(FileSystemEventHandler):
    """Watchdog event handler that triggers scan_engine on file events."""

    def __init__(self, scan_fn):
        super().__init__()
        self._scan_fn = scan_fn

    def _scan_async(self, path: str) -> None:
        threading.Thread(
            target=self._scan_fn,
            args=(path,),
            kwargs={"scan_type": "realtime"},
            daemon=True,
            name=f"rt-scan-{Path(path).name[:20]}",
        ).start()

    def on_created(self, event):
        if not event.is_directory:
            self._scan_async(event.src_path)

    def on_modified(self, event):
        if not event.is_directory:
            self._scan_async(event.src_path)

    def on_moved(self, event):
        # Scan the destination of the moved file
        if not event.is_directory and hasattr(event, "dest_path"):
            self._scan_async(event.dest_path)


class RealTimeGuard:
    """
    Manages the watchdog Observer and all watched paths.
    Supports runtime addition/removal of watch paths.
    """

    def __init__(self, scan_fn):
        """
        scan_fn: callable(path, scan_type="realtime") → ScanResult
        """
        self._scan_fn  = scan_fn
        self._observer: Optional[object] = None   # watchdog Observer
        self._watches: dict[str, object] = {}      # path → watch handle
        self._lock     = threading.Lock()
        self._running  = False
        self._watch_paths: list[str] = _default_watch_paths()

    # ── Lifecycle ──────────────────────────────────────────────────────────

    def start(self) -> bool:
        if not WATCHDOG_AVAILABLE:
            log.error("Cannot start real-time protection: watchdog not installed")
            return False

        with self._lock:
            if self._running:
                return True

            self._observer = Observer()
            handler = _ScanEventHandler(self._scan_fn)

            for path in self._watch_paths:
                try:
                    handle = self._observer.schedule(
                        handler, path, recursive=True
                    )
                    self._watches[path] = handle
                    log.info("Watching: %s", path)
                except Exception as exc:
                    log.warning("Cannot watch %s: %s", path, exc)

            self._observer.start()
            self._running = True
            log.info(
                "Real-time protection started — %d paths monitored",
                len(self._watches),
            )
            return True

    def stop(self) -> None:
        with self._lock:
            if not self._running or self._observer is None:
                return
            try:
                self._observer.stop()
                self._observer.join(timeout=5)
            except Exception as exc:
                log.warning("Observer stop error: %s", exc)
            self._running   = False
            self._watches   = {}
            self._observer  = None
            log.info("Real-time protection stopped")

    @property
    def running(self) -> bool:
        return self._running

    # ── Path management ────────────────────────────────────────────────────

    def add_watch_path(self, path: str) -> bool:
        """Add a new path to monitor at runtime."""
        if not WATCHDOG_AVAILABLE or not self._running or self._observer is None:
            if path not in self._watch_paths:
                self._watch_paths.append(path)
            return False

        with self._lock:
            if path in self._watches:
                return True
            try:
                handler = _ScanEventHandler(self._scan_fn)
                handle  = self._observer.schedule(handler, path, recursive=True)
                self._watches[path] = handle
                if path not in self._watch_paths:
                    self._watch_paths.append(path)
                log.info("Added watch path: %s", path)
                return True
            except Exception as exc:
                log.warning("Cannot add watch path %s: %s", path, exc)
                return False

    def remove_watch_path(self, path: str) -> bool:
        """Stop monitoring a path."""
        with self._lock:
            if path in self._watches and self._observer:
                try:
                    self._observer.unschedule(self._watches.pop(path))
                except Exception:
                    pass
            if path in self._watch_paths:
                self._watch_paths.remove(path)
            log.info("Removed watch path: %s", path)
        return True

    def get_watch_paths(self) -> list[str]:
        return list(self._watch_paths)

    def get_status(self) -> dict:
        return {
            "running":      self._running,
            "watch_paths":  self._watch_paths,
            "path_count":   len(self._watches),
        }
