"""
ShieldOS Engine — Cross-Platform OS Notifications
Uses plyer for native notifications on all platforms.
"""
import logging
from pathlib import Path

from config import ICON_PATH, APP_NAME, get_config

log = logging.getLogger("shieldos.notifications")

try:
    from plyer import notification as _notify
    PLYER_AVAILABLE = True
except ImportError:
    log.warning("plyer not installed — OS notifications disabled")
    PLYER_AVAILABLE = False


def _icon_path() -> str:
    """Return icon path string if icon file exists, else empty."""
    p = Path(ICON_PATH)
    if p.exists():
        return str(p)
    # Fallback: look next to main.py
    fallback = Path(__file__).parent / "assets" / "icon.png"
    return str(fallback) if fallback.exists() else ""


def _should_notify() -> bool:
    return get_config().get("notifications_enabled", True) and PLYER_AVAILABLE


def _send(title: str, message: str, timeout: int = 6) -> None:
    if not _should_notify():
        return
    icon = _icon_path()
    try:
        _notify.notify(
            title    = title,
            message  = message,
            app_name = APP_NAME,
            app_icon = icon,
            timeout  = timeout,
        )
    except Exception as exc:
        log.debug("Notification send failed: %s", exc)


def notify_threat(threat_name: str, file_path: str, action: str) -> None:
    """Alert the user that a threat was detected."""
    short_path = Path(file_path).name
    _send(
        title   = f"⚠ {APP_NAME} — Threat Detected",
        message = f"{threat_name}\n{short_path}\nAction: {action}",
        timeout = 8,
    )
    log.info("Threat notification: %s → %s", threat_name, action)


def notify_scan_complete(
    scanned: int, threats: int, duration_sec: float
) -> None:
    """Notify when a manual/scheduled scan completes."""
    msg = (
        f"Scanned {scanned:,} files in {duration_sec:.1f}s\n"
        f"Threats found: {threats}"
    )
    _send(
        title   = f"{APP_NAME} — Scan Complete",
        message = msg,
        timeout = 5,
    )


def notify_update_available(version: str) -> None:
    _send(
        title   = f"{APP_NAME} — Update Available",
        message = f"Version {version} is available. Open ShieldOS to update.",
        timeout = 10,
    )


def notify_realtime_enabled() -> None:
    _send(
        title   = f"{APP_NAME} — Real-Time Protection On",
        message = "File system monitoring is active.",
        timeout = 4,
    )


def notify_realtime_disabled() -> None:
    _send(
        title   = f"{APP_NAME} — Real-Time Protection Off",
        message = "Warning: real-time file monitoring has been disabled.",
        timeout = 6,
    )


def notify_engine_ready() -> None:
    _send(
        title   = f"{APP_NAME} Ready",
        message = "Engine started. Your system is protected.",
        timeout = 3,
    )
