"""
ShieldOS Engine — Global Configuration & Constants
"""
import pathlib
import sys
import os
import json
import logging

# ── Application metadata ───────────────────────────────────────────────────
API_HOST  = "127.0.0.1"
API_PORT  = 7734
APP_NAME  = "ShieldOS"
VERSION   = "4.2.1"

# ── Cross-platform base directory ──────────────────────────────────────────
if sys.platform == "win32":
    BASE_DIR = pathlib.Path(os.environ.get("APPDATA", "~")) / "ShieldOS"
elif sys.platform == "darwin":
    BASE_DIR = pathlib.Path.home() / "Library" / "Application Support" / "ShieldOS"
else:
    BASE_DIR = pathlib.Path.home() / ".config" / "shieldos"

QUARANTINE_DIR = BASE_DIR / "quarantine"
DB_PATH        = BASE_DIR / "shieldos.db"
RULES_DIR      = BASE_DIR / "rules"
LOG_PATH       = BASE_DIR / "shieldos.log"
CONFIG_PATH    = BASE_DIR / "config.json"
ICON_PATH      = pathlib.Path(__file__).parent / "assets" / "icon.png"

# ── Ensure directories exist ───────────────────────────────────────────────
for _d in [BASE_DIR, QUARANTINE_DIR, RULES_DIR]:
    _d.mkdir(parents=True, exist_ok=True)

# Copy bundled rules into BASE_DIR/rules if not already there
_BUNDLED_RULES = pathlib.Path(__file__).parent / "rules"
if _BUNDLED_RULES.exists():
    import shutil
    for _r in _BUNDLED_RULES.glob("*.yar"):
        _dest = RULES_DIR / _r.name
        if not _dest.exists():
            shutil.copy2(_r, _dest)

# ── Logging setup ──────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(name)s  %(message)s",
    handlers=[
        logging.FileHandler(LOG_PATH),
        logging.StreamHandler(sys.stdout),
    ],
)
log = logging.getLogger("shieldos.config")

# ── Default runtime configuration ─────────────────────────────────────────
DEFAULT_CONFIG: dict = {
    "realtime_enabled":         True,
    "virustotal_api_key":       "",
    "scan_archives":            True,
    "scan_hidden":              True,
    "max_file_size_mb":         512,
    "scheduled_scan_time":      "02:00",
    "scheduled_scan_enabled":   True,
    "quarantine_auto":          True,
    "heuristics_level":         "medium",   # low | medium | high | paranoid
    "excluded_paths":           [],
    "notifications_enabled":    True,
    "parallel_scan_workers":    4,
    "watch_paths":              [],
}

# ── Runtime config singleton ───────────────────────────────────────────────
_runtime_config: dict = dict(DEFAULT_CONFIG)

def get_config() -> dict:
    return dict(_runtime_config)

def update_config(partial: dict) -> dict:
    _runtime_config.update(partial)
    return dict(_runtime_config)

def load_config_from_db(db_get_fn) -> dict:
    """Load all config keys from DB into runtime config."""
    for key, default in DEFAULT_CONFIG.items():
        val = db_get_fn(key)
        if val is not None:
            if isinstance(default, bool):
                _runtime_config[key] = str(val).lower() in ("1", "true", "yes")
            elif isinstance(default, int):
                try:
                    _runtime_config[key] = int(val)
                except (ValueError, TypeError):
                    _runtime_config[key] = default
            elif isinstance(default, list):
                try:
                    _runtime_config[key] = json.loads(val)
                except (json.JSONDecodeError, TypeError):
                    _runtime_config[key] = default
            else:
                _runtime_config[key] = val
    return dict(_runtime_config)

# ── Dangerous file extensions ──────────────────────────────────────────────
DANGEROUS_EXTENSIONS: set[str] = {
    ".exe", ".dll", ".sys", ".bat", ".cmd", ".ps1", ".vbs",
    ".js",  ".jar", ".msi", ".scr", ".pif", ".com", ".lnk",
    ".hta", ".wsf", ".reg", ".inf", ".sh",  ".py",  ".rb",
    ".elf", ".so",  ".dylib", ".deb", ".rpm", ".dmg", ".pkg",
    ".cpl", ".ocx", ".gadget", ".application", ".workflow",
}

# ── Whitelist hashes (MD5) ─────────────────────────────────────────────────
WHITELIST_HASHES: set[str] = set()

# ── Scan client IDs ───────────────────────────────────────────────────────
SCAN_CLIENT_IDS = ["SC-01", "SC-02", "SC-03", "SC-04"]
