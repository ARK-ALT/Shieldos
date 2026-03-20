"""
ShieldOS Engine — Running Process Scanner
Scans executables of all running processes.
"""
import logging
from typing import Callable, Optional

log = logging.getLogger("shieldos.process_monitor")

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    log.warning("psutil not installed — process scanning unavailable")
    PSUTIL_AVAILABLE = False


def get_running_processes() -> list[dict]:
    """
    Return a list of running processes with metadata.
    """
    if not PSUTIL_AVAILABLE:
        return []

    processes: list[dict] = []
    seen_exes: set[str] = set()

    for proc in psutil.process_iter(
        ["pid", "name", "exe", "status", "cpu_percent", "memory_info", "username"]
    ):
        try:
            info = proc.info
            exe  = info.get("exe") or ""

            processes.append({
                "pid":      info.get("pid"),
                "name":     info.get("name", ""),
                "exe":      exe,
                "status":   info.get("status", ""),
                "cpu":      round(info.get("cpu_percent") or 0, 1),
                "memory_mb": round(
                    (info.get("memory_info") or type("", (), {"rss": 0})()).rss
                    / (1024 * 1024), 1
                ),
                "user":     info.get("username", ""),
                "scan_result": None,   # populated by scan_processes()
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

    return processes


def scan_processes(scan_file_fn: Callable[[str], dict]) -> list[dict]:
    """
    Scan all unique running process executables.
    scan_file_fn: callable(path) → ScanResult.to_dict()
    """
    if not PSUTIL_AVAILABLE:
        return []

    processes   = get_running_processes()
    seen_exes: dict[str, dict] = {}

    for proc in processes:
        exe = proc.get("exe", "")
        if not exe:
            continue
        if exe not in seen_exes:
            try:
                result = scan_file_fn(exe)
                seen_exes[exe] = result if isinstance(result, dict) else result.to_dict()
            except Exception as exc:
                log.debug("Process scan error for %s: %s", exe, exc)
                seen_exes[exe] = {"result": "error", "threat_name": str(exc)}
        proc["scan_result"] = seen_exes[exe]

    return processes
