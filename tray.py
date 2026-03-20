"""
ShieldOS Engine — System Tray Icon (pystray)
Provides tray icon with menu for all platforms.
"""
import logging
import threading
import webbrowser
from typing import Callable, Optional

from config import APP_NAME, VERSION, API_HOST, API_PORT

log = logging.getLogger("shieldos.tray")

ENGINE_URL = f"http://{API_HOST}:{API_PORT}"

try:
    import pystray
    from PIL import Image, ImageDraw
    PYSTRAY_AVAILABLE = True
except ImportError:
    log.warning("pystray/Pillow not installed — system tray disabled")
    PYSTRAY_AVAILABLE = False


def _create_shield_icon(color: str) -> "Image.Image":
    """Generate a simple shield icon programmatically."""
    from PIL import Image, ImageDraw
    size = 64
    img  = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)

    # Shield shape (polygon approximation)
    shield = [
        (size // 2, 4),             # top centre
        (size - 4, 12),             # top right
        (size - 4, size // 2),      # mid right
        (size // 2, size - 4),      # bottom centre
        (4, size // 2),             # mid left
        (4, 12),                    # top left
    ]
    draw.polygon(shield, fill=color)
    # Inner highlight
    inner = [(x + 6, y + 6) for x, y in shield]
    draw.polygon(inner, fill=_lighten(color))
    return img


def _lighten(hex_color: str) -> str:
    """Lighten a hex colour by 30%."""
    h = hex_color.lstrip("#")
    rgb = tuple(min(255, int(h[i:i+2], 16) + 60) for i in (0, 2, 4))
    return "#{:02x}{:02x}{:02x}".format(*rgb)


ICON_COLORS = {
    "protected": "#00c853",   # green
    "scanning":  "#2979ff",   # blue
    "threat":    "#d50000",   # red
    "paused":    "#757575",   # grey
}


def _api_post(endpoint: str, body: dict = None) -> None:
    """Fire-and-forget POST to local engine API."""
    import requests
    try:
        requests.post(
            f"{ENGINE_URL}{endpoint}",
            json=body or {},
            timeout=5,
        )
    except Exception as exc:
        log.debug("Tray API call failed: %s", exc)


def _open_dashboard() -> None:
    """Tell Electron to focus the main window, or open browser fallback."""
    # Electron listens on the same port; opening this will focus the app
    webbrowser.open(f"{ENGINE_URL}/")


class TrayManager:
    """Manages the pystray system tray icon and menu."""

    def __init__(
        self,
        on_quit:             Optional[Callable] = None,
        get_quarantine_count: Optional[Callable[[], int]] = None,
    ):
        self._icon: Optional[object]   = None
        self._on_quit                  = on_quit
        self._get_qcount               = get_quarantine_count or (lambda: 0)
        self._state                    = "protected"
        self._realtime_enabled         = True

    def start(self) -> None:
        if not PYSTRAY_AVAILABLE:
            log.info("Tray not available (pystray/Pillow missing)")
            return
        threading.Thread(
            target  = self._run_tray,
            daemon  = True,
            name    = "shieldos-tray",
        ).start()

    def stop(self) -> None:
        if self._icon:
            try:
                self._icon.stop()
            except Exception:
                pass

    def set_state(self, state: str) -> None:
        """Update icon colour. state: 'protected'|'scanning'|'threat'|'paused'"""
        self._state = state
        if self._icon and PYSTRAY_AVAILABLE:
            color = ICON_COLORS.get(state, "#757575")
            try:
                self._icon.icon = _create_shield_icon(color)
            except Exception:
                pass

    def _build_menu(self) -> "pystray.Menu":
        qcount = self._get_qcount()
        rt_label = "Real-Time Protection ✓" if self._realtime_enabled \
                   else "Real-Time Protection ✗"
        q_label  = f"View Quarantine ({qcount})"

        return pystray.Menu(
            pystray.MenuItem(f"{APP_NAME} v{VERSION}", None, enabled=False),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem(
                f"● {self._state.capitalize()}",
                None, enabled=False,
            ),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("Open Dashboard",          self._on_open_dashboard),
            pystray.MenuItem("Quick Scan (Home Dir)",   self._on_quick_scan),
            pystray.MenuItem("Full System Scan",        self._on_full_scan),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem(rt_label,                  self._on_toggle_realtime),
            pystray.MenuItem("Pause Protection",        self._on_pause),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem(q_label,                   self._on_view_quarantine),
            pystray.MenuItem("Update Definitions",      self._on_update_defs),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("Settings",                self._on_settings),
            pystray.MenuItem("Quit ShieldOS",           self._on_quit_clicked),
        )

    def _run_tray(self) -> None:
        color = ICON_COLORS.get(self._state, "#00c853")
        icon_img = _create_shield_icon(color)
        self._icon = pystray.Icon(
            APP_NAME,
            icon_img,
            title = f"{APP_NAME} — Protected",
            menu  = self._build_menu(),
        )
        self._icon.run()

    # ── Menu callbacks ─────────────────────────────────────────────────────

    def _on_open_dashboard(self, icon, item):
        _open_dashboard()

    def _on_quick_scan(self, icon, item):
        import pathlib
        home = str(pathlib.Path.home())
        _api_post("/scan/directory", {"path": home, "recursive": True})
        self.set_state("scanning")

    def _on_full_scan(self, icon, item):
        import pathlib, sys
        root = "C:\\" if sys.platform == "win32" else "/"
        _api_post("/scan/directory", {"path": root, "recursive": True})
        self.set_state("scanning")

    def _on_toggle_realtime(self, icon, item):
        if self._realtime_enabled:
            _api_post("/realtime/stop")
            self._realtime_enabled = False
            self.set_state("paused")
        else:
            _api_post("/realtime/start")
            self._realtime_enabled = True
            self.set_state("protected")
        # Rebuild menu to reflect new label
        if self._icon:
            self._icon.menu = self._build_menu()

    def _on_pause(self, icon, item):
        _api_post("/realtime/stop")
        self._realtime_enabled = False
        self.set_state("paused")
        if self._icon:
            self._icon.menu = self._build_menu()

    def _on_view_quarantine(self, icon, item):
        _open_dashboard()   # Electron opens quarantine page via URL hash

    def _on_update_defs(self, icon, item):
        _api_post("/rules/reload")

    def _on_settings(self, icon, item):
        _open_dashboard()

    def _on_quit_clicked(self, icon, item):
        self.stop()
        if self._on_quit:
            self._on_quit()
