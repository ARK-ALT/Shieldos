"""
ShieldOS Engine — Heuristic Analysis Engine
Detects suspicious files without signatures using behavioral indicators.
"""
import math
import re
import struct
import collections
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from config import DANGEROUS_EXTENSIONS

log = logging.getLogger("shieldos.heuristics")

# Suspicious PE import names
SUSPICIOUS_PE_IMPORTS = [
    b"CreateRemoteThread",
    b"VirtualAllocEx",
    b"WriteProcessMemory",
    b"SetWindowsHookEx",
    b"RegCreateKey",
    b"InternetOpenUrl",
    b"URLDownloadToFile",
    b"ShellExecute",
    b"WinExec",
    b"CreateProcess",
    b"OpenProcess",
    b"AdjustTokenPrivileges",
    b"IsDebuggerPresent",
    b"CheckRemoteDebuggerPresent",
    b"NtUnmapViewOfSection",
]

# Regex patterns for suspicious strings
_RE_IP       = re.compile(rb"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}")
_RE_B64      = re.compile(rb"[A-Za-z0-9+/]{64,}={0,2}")
_RE_HEX_SC   = re.compile(rb"(?:\\x[0-9a-fA-F]{2}){8,}")
_RE_DYN_DNS  = re.compile(rb"(?:dyndns|no-ip|ddns|ngrok|serveo)\.", re.I)

# Obfuscation indicators for scripts
_OBFUSC_PATTERNS = [
    rb"chr\(",
    rb"charCodeAt",
    rb"\[char\]",
    rb"-join\s+",
    rb"\[string\]::Join",
    rb"%comspec%",
    rb"%temp%",
    rb"del\s+%0",
    rb'rm\s+--\s+"\$0"',
    rb"FromBase64String",
    rb"Convert\.ToInt32",
]

CREDENTIAL_KEYWORDS = [
    b"password", b"passwd", b"credential", b"token",
    b"apikey", b"api_key", b"secret", b"private_key",
]


@dataclass
class HeuristicResult:
    score:       int
    risk_level:  str          # 'clean' | 'suspicious' | 'threat'
    indicators:  list[str]    = field(default_factory=list)
    severity:    Optional[str] = None   # 'low' | 'med' | 'high' | 'crit'
    threat_name: str          = "Heuristic.Suspicious"


class HeuristicEngine:
    """
    Score-based heuristic analysis.
    Returns risk score 0–100 and list of triggered indicators.
    """

    def __init__(self, level: str = "medium"):
        self.level = level          # low | medium | high | paranoid
        self._thresholds = {
            "low":      (40, 70),   # (suspicious_threshold, threat_threshold)
            "medium":   (30, 55),
            "high":     (20, 40),
            "paranoid": (10, 25),
        }

    def analyze(self, file_path: str) -> HeuristicResult:
        score      = 0
        indicators = []
        path       = Path(file_path)
        ext        = path.suffix.lower()

        try:
            stat      = path.stat()
            file_size = stat.st_size
        except OSError:
            return HeuristicResult(score=0, risk_level="error",
                                   indicators=["Cannot stat file"])

        # ── Read file content ──────────────────────────────────────────────
        try:
            with open(file_path, "rb") as fh:
                data = fh.read(min(file_size, 8 * 1024 * 1024))  # cap at 8 MB
        except (OSError, PermissionError):
            return HeuristicResult(score=0, risk_level="error",
                                   indicators=["Permission denied"])

        # ── 1. Entropy analysis ────────────────────────────────────────────
        entropy = self._shannon_entropy(data)
        if entropy > 7.2:
            score += 30
            indicators.append(f"High entropy ({entropy:.2f}) — likely packed/encrypted")
        elif entropy > 6.8 and ext in DANGEROUS_EXTENSIONS:
            score += 20
            indicators.append(f"Elevated entropy ({entropy:.2f}) in executable file")

        # ── 2. PE header analysis ──────────────────────────────────────────
        if len(data) >= 2 and data[:2] == b"MZ":
            pe_score, pe_indicators = self._analyze_pe(data)
            score += pe_score
            indicators.extend(pe_indicators)

        # ── 3. String analysis ─────────────────────────────────────────────
        str_score, str_indicators = self._analyze_strings(data)
        score += str_score
        indicators.extend(str_indicators)

        # ── 4. Behavioral indicators (script files) ───────────────────────
        script_exts = {".ps1", ".vbs", ".js", ".bat", ".sh", ".py", ".rb",
                       ".hta", ".wsf", ".cmd"}
        if ext in script_exts:
            obf_score, obf_indicators = self._analyze_script_obfuscation(data)
            score += obf_score
            indicators.extend(obf_indicators)

        # ── 5. Extension / magic byte mismatch ────────────────────────────
        declared_as_image = ext in {".jpg", ".jpeg", ".png", ".gif", ".bmp"}
        starts_with_mz    = len(data) >= 2 and data[:2] == b"MZ"
        starts_with_elf   = len(data) >= 4 and data[:4] == b"\x7fELF"
        if declared_as_image and (starts_with_mz or starts_with_elf):
            score += 40
            indicators.append(f"Extension/magic mismatch: {ext} file is actually executable")

        declared_as_pdf = ext == ".pdf"
        if declared_as_pdf and not data.startswith(b"%PDF"):
            score += 15
            indicators.append("File declared as PDF but missing %PDF header")

        # ── 6. Size anomalies ─────────────────────────────────────────────
        if ext in DANGEROUS_EXTENSIONS:
            if file_size < 1024:
                score += 10
                indicators.append(f"Suspiciously small executable ({file_size} bytes)")
            elif file_size > 50 * 1024 * 1024 and b"PK" not in data[:4]:
                score += 10
                indicators.append("Large executable without archive signature")

        # ── Clamp and classify ─────────────────────────────────────────────
        score = min(score, 100)
        susp_t, threat_t = self._thresholds.get(self.level, (30, 55))

        if score < susp_t:
            risk_level = "clean"
            severity   = None
        elif score < threat_t:
            risk_level = "suspicious"
            severity   = "med"
        else:
            risk_level = "threat"
            severity   = "high" if score < 80 else "crit"

        return HeuristicResult(
            score=score,
            risk_level=risk_level,
            indicators=indicators,
            severity=severity,
        )

    # ── Helpers ────────────────────────────────────────────────────────────

    def _shannon_entropy(self, data: bytes) -> float:
        if not data:
            return 0.0
        counter = collections.Counter(data)
        length  = len(data)
        return -sum(
            (c / length) * math.log2(c / length)
            for c in counter.values()
        )

    def _analyze_pe(self, data: bytes) -> tuple[int, list[str]]:
        score      = 0
        indicators = []

        # Check for common PE packer strings
        packers = [b"UPX0", b"UPX1", b"UPX!", b"ASPack", b"PECompact",
                   b"Themida", b"VMProtect", b"Obsidium"]
        for packer in packers:
            if packer in data:
                score += 15
                indicators.append(f"PE packer detected: {packer.decode(errors='ignore')}")
                break

        # Suspicious import names
        hits = 0
        for imp in SUSPICIOUS_PE_IMPORTS:
            if imp in data:
                hits += 1
        if hits >= 3:
            score += hits * 5
            indicators.append(f"PE imports {hits} suspicious API calls")
        elif hits > 0:
            score += hits * 3

        # Check for abnormal section count (>8 suggests packing)
        # PE optional header offset is at MZ offset 0x3C
        try:
            if len(data) > 0x40:
                pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
                if pe_offset + 6 < len(data):
                    num_sections = struct.unpack_from("<H", data, pe_offset + 6)[0]
                    if num_sections == 0 or num_sections > 10:
                        score += 10
                        indicators.append(f"Unusual PE section count: {num_sections}")
        except struct.error:
            pass

        return score, indicators

    def _analyze_strings(self, data: bytes) -> tuple[int, list[str]]:
        score      = 0
        indicators = []

        # IP addresses
        ips = _RE_IP.findall(data)
        public_ips = [
            ip for ip in ips
            if not (ip.startswith(b"192.168.") or ip.startswith(b"10.")
                    or ip.startswith(b"127.") or ip.startswith(b"0."))
        ]
        if len(public_ips) > 3:
            score += 10
            indicators.append(f"Contains {len(public_ips)} embedded IP addresses")

        # Long base64 blobs
        b64_hits = _RE_B64.findall(data)
        if b64_hits:
            score += 10
            indicators.append(f"Contains {len(b64_hits)} large base64-encoded blob(s)")

        # Hex-encoded shellcode
        if _RE_HEX_SC.search(data):
            score += 15
            indicators.append("Hex-encoded shellcode pattern detected")

        # Dynamic DNS / C2 patterns
        if _RE_DYN_DNS.search(data):
            score += 15
            indicators.append("Dynamic DNS / common C2 domain pattern detected")

        # Credential keywords
        text_lower = data.lower()
        cred_hits = [kw for kw in CREDENTIAL_KEYWORDS if kw in text_lower]
        if len(cred_hits) >= 2:
            score += 10
            indicators.append(f"Credential-related keywords: {[k.decode() for k in cred_hits]}")

        return score, indicators

    def _analyze_script_obfuscation(self, data: bytes) -> tuple[int, list[str]]:
        score      = 0
        indicators = []
        hits       = 0

        for pattern in _OBFUSC_PATTERNS:
            if re.search(pattern, data, re.I):
                hits += 1

        if hits >= 3:
            score += 20
            indicators.append(f"Heavy script obfuscation detected ({hits} patterns)")
        elif hits > 0:
            score += hits * 5
            indicators.append(f"Script obfuscation indicators ({hits} patterns)")

        return score, indicators

    def set_level(self, level: str) -> None:
        if level in self._thresholds:
            self.level = level
            log.info("Heuristics level set to: %s", level)
