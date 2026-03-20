"""
ShieldOS Engine — Network Connection Monitor
Lists active network connections and flags suspicious ones.
"""
import logging
from typing import Optional

log = logging.getLogger("shieldos.network_monitor")

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False

# Known suspicious remote ports (C2 traffic often uses these)
SUSPICIOUS_PORTS: set[int] = {
    4444,   # Metasploit default
    5555,   # ADB / common RAT
    6666,
    6667,   # IRC (often used by botnets)
    1337,
    31337,
    12345,
    54321,
    8888,
}


def get_connections() -> list[dict]:
    """Return all active network connections with process info."""
    if not PSUTIL_AVAILABLE:
        return []

    conns: list[dict] = []
    try:
        for conn in psutil.net_connections(kind="inet"):
            raddr = conn.raddr
            laddr = conn.laddr

            remote_port  = raddr.port if raddr else None
            remote_ip    = raddr.ip   if raddr else None
            is_suspicious = (
                remote_port in SUSPICIOUS_PORTS
                if remote_port else False
            )

            # Get process name
            proc_name = ""
            proc_exe  = ""
            if conn.pid:
                try:
                    p = psutil.Process(conn.pid)
                    proc_name = p.name()
                    proc_exe  = p.exe()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass

            conns.append({
                "pid":           conn.pid,
                "process_name":  proc_name,
                "process_exe":   proc_exe,
                "local_addr":    f"{laddr.ip}:{laddr.port}" if laddr else "",
                "remote_addr":   f"{remote_ip}:{remote_port}" if raddr else "",
                "remote_ip":     remote_ip,
                "remote_port":   remote_port,
                "status":        conn.status,
                "family":        str(conn.family),
                "type":          str(conn.type),
                "suspicious":    is_suspicious,
            })
    except (psutil.AccessDenied, PermissionError):
        pass
    except Exception as exc:
        log.debug("Network monitor error: %s", exc)

    return conns


def get_suspicious_connections() -> list[dict]:
    return [c for c in get_connections() if c.get("suspicious")]
