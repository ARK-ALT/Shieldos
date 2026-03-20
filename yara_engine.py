"""
ShieldOS Engine — YARA Rule Matching Engine
"""
import logging
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from config import RULES_DIR

log = logging.getLogger("shieldos.yara_engine")

try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    log.warning("yara-python not installed — YARA scanning disabled")
    YARA_AVAILABLE = False


@dataclass
class YaraMatch:
    rule_name:   str
    tags:        list[str]       = field(default_factory=list)
    meta:        dict            = field(default_factory=dict)
    strings:     list[tuple]    = field(default_factory=list)
    severity:    str             = "high"
    description: str            = ""

    def __post_init__(self):
        self.severity    = self.meta.get("severity", "high")
        self.description = self.meta.get("description", "")


class YaraEngine:
    """
    Compiles all .yar files from RULES_DIR and provides file scanning.
    Supports hot-reload and dynamic rule addition.
    """

    def __init__(self):
        self._rules: Optional[object] = None   # yara.Rules
        self._lock  = threading.Lock()
        self._rule_names: list[str] = []
        self._load_rules()

    def _load_rules(self) -> None:
        if not YARA_AVAILABLE:
            return

        yar_files = list(Path(RULES_DIR).glob("*.yar"))
        if not yar_files:
            log.warning("No .yar files found in %s", RULES_DIR)
            return

        filepaths: dict[str, str] = {}
        for yar in yar_files:
            # Use namespace = filename stem (e.g. "malware", "ransomware")
            filepaths[yar.stem] = str(yar)

        try:
            with self._lock:
                self._rules      = yara.compile(filepaths=filepaths)
                self._rule_names = [yar.stem for yar in yar_files]
            log.info("YARA rules compiled: %s", ", ".join(self._rule_names))
        except yara.SyntaxError as exc:
            log.error("YARA compile error: %s", exc)
        except Exception as exc:
            log.error("YARA load failed: %s", exc)

    def scan(self, file_path: str, timeout: int = 30) -> Optional[YaraMatch]:
        """
        Scan a file against all loaded YARA rules.
        Returns first match (highest priority / first in rule file), or None.
        """
        if not YARA_AVAILABLE or self._rules is None:
            return None

        try:
            with self._lock:
                matches = self._rules.match(file_path, timeout=timeout)
        except Exception as exc:
            log.debug("YARA scan error on %s: %s", file_path, exc)
            return None

        if not matches:
            return None

        m = matches[0]
        strings_info = []
        for string_match in m.strings:
            try:
                identifier = string_match.identifier
                instances  = string_match.instances
                offset     = instances[0].offset if instances else 0
                strings_info.append((identifier, offset))
            except Exception:
                pass

        return YaraMatch(
            rule_name = m.rule,
            tags      = list(m.tags),
            meta      = dict(m.meta),
            strings   = strings_info,
        )

    def scan_data(self, data: bytes, timeout: int = 30) -> Optional[YaraMatch]:
        """Scan raw bytes (for in-memory scanning)."""
        if not YARA_AVAILABLE or self._rules is None:
            return None
        try:
            with self._lock:
                matches = self._rules.match(data=data, timeout=timeout)
        except Exception:
            return None

        if not matches:
            return None

        m = matches[0]
        return YaraMatch(
            rule_name = m.rule,
            tags      = list(m.tags),
            meta      = dict(m.meta),
        )

    def reload_rules(self) -> bool:
        """Hot-reload all rules from disk without restarting."""
        log.info("Hot-reloading YARA rules...")
        try:
            self._load_rules()
            return True
        except Exception as exc:
            log.error("YARA reload failed: %s", exc)
            return False

    def add_rule(self, rule_content: str, rule_name: str) -> bool:
        """Write a new rule file and reload all rules."""
        rule_path = Path(RULES_DIR) / f"{rule_name}.yar"
        try:
            rule_path.write_text(rule_content, encoding="utf-8")
            return self.reload_rules()
        except Exception as exc:
            log.error("Cannot add rule %s: %s", rule_name, exc)
            return False

    def get_rule_names(self) -> list[str]:
        return list(self._rule_names)

    @property
    def available(self) -> bool:
        return YARA_AVAILABLE and self._rules is not None
