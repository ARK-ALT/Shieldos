"""
ShieldOS Engine — Local Signature Database
MD5/SHA256 hash-based detection + pattern signatures.
"""
import logging
from typing import Optional

log = logging.getLogger("shieldos.signatures")

# ── Known malware SHA256 hashes ────────────────────────────────────────────
# These are publicly documented malware sample hashes used for reference.
# In production this would be fetched from a signature update server.
KNOWN_MALWARE_HASHES: dict[str, dict] = {
    # WannaCry
    "24d004a104d4d54034dbcffc2a4b19a11f39008a575aa614ea04703480b1022c": {
        "name":     "WannaCry.Ransomware",
        "type":     "ransomware",
        "severity": "critical",
    },
    "ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa": {
        "name":     "WannaCry.Ransomware.B",
        "type":     "ransomware",
        "severity": "critical",
    },
    # Mirai
    "bf7f9bb9782cf3b67b3a95d16eeb7ef01bd78a7f3cf53ce3f03c8360e39ab53c": {
        "name":     "Mirai.Botnet",
        "type":     "botnet",
        "severity": "high",
    },
    # NotPetya
    "027cc450ef5f8c5f653329641ec1fed91f694e0d229928963b30f6b0d7d3a745": {
        "name":     "NotPetya.Wiper",
        "type":     "wiper",
        "severity": "critical",
    },
    # Emotet loader
    "a90a7b36afae69b47eab09c6e7a4fc60ece5bdb02e5d940f35027888da82d9cf": {
        "name":     "Emotet.Loader",
        "type":     "trojan",
        "severity": "critical",
    },
}

# ── Known clean (trusted) SHA256 hashes ────────────────────────────────────
KNOWN_CLEAN_HASHES: set[str] = {
    # Windows system files (well-known hashes)
    "4ae7e3b16e876f6e0d1e7c6ed7c01f0b498d4c9cda9e4d76f8cfa5da4bd5f7e2",
    # Add more trusted system file hashes here
}

# ── Byte-pattern signatures ────────────────────────────────────────────────
# List of (name, type, severity, bytes_pattern) tuples
# bytes_pattern is a bytes literal that must appear in the file
BYTE_SIGNATURES: list[tuple[str, str, str, bytes]] = [
    (
        "Cobalt.Strike.Beacon",
        "rat",
        "critical",
        b"\xfc\x48\x83\xe4\xf0\xe8\xc8\x00\x00\x00\x41\x51\x41\x50",
    ),
    (
        "Meterpreter.Shellcode",
        "rat",
        "critical",
        b"\xfc\xe8\x82\x00\x00\x00\x60\x89\xe5\x31\xc0\x64\x8b\x50\x30",
    ),
    (
        "EICAR.Test.Signature",
        "test",
        "low",
        b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*",
    ),
    (
        "Generic.Mirai.Dropper",
        "botnet",
        "high",
        b"/bin/busybox MIRAI",
    ),
    (
        "Generic.Shellcode.NOP.Sled",
        "exploit",
        "high",
        b"\x90" * 64,   # 64+ NOP instructions
    ),
    (
        "Suspicious.AutoRun.INF",
        "pup",
        "medium",
        b"[AutoRun]\r\nopen=",
    ),
    (
        "Generic.Ransomware.Note",
        "ransomware",
        "critical",
        b"YOUR FILES HAVE BEEN ENCRYPTED",
    ),
    (
        "Generic.Ransomware.Note.B",
        "ransomware",
        "critical",
        b"All your files are encrypted",
    ),
]

# ── String signatures ──────────────────────────────────────────────────────
STRING_SIGNATURES: list[tuple[str, str, str, str]] = [
    ("Generic.Reverse.Shell.NC",   "rat",        "critical", "nc -e /bin/sh"),
    ("Generic.Reverse.Shell.NC2",  "rat",        "critical", "nc.exe -e cmd"),
    ("Generic.Bind.Shell",         "rat",        "critical", "bind_shell"),
    ("Generic.Download.Execute",   "dropper",    "high",     "DownloadString"),
    ("Generic.Encoded.Command",    "obfuscated", "high",     "-EncodedCommand"),
    ("Generic.VBS.WScript.Shell",  "script",     "medium",   "WScript.Shell"),
    ("Suspicious.Shadow.Delete",   "ransomware", "critical", "vssadmin delete shadows"),
    ("Suspicious.BCDEdit",         "ransomware", "critical", "bcdedit /set {default} recoveryenabled no"),
    ("Suspicious.Mimikatz",        "credential", "critical", "sekurlsa::logonpasswords"),
    ("Suspicious.XMRig",           "miner",      "medium",   "stratum+tcp://"),
    ("Suspicious.PowerShell.IEX",  "script",     "high",     "IEX("),
    ("Suspicious.Base64.PS",       "obfuscated", "high",     "powershell -enc "),
    ("Suspicious.Cryptolocker.Ext","ransomware", "critical", ".CRYPTED"),
    ("Suspicious.Keylogger",       "spyware",    "critical", "GetAsyncKeyState"),
]


class SignatureEngine:
    """
    Fast local signature checking using:
    1. SHA256 hash lookup (known malware DB)
    2. Byte-pattern scanning (partial content match)
    3. String signature scanning
    """

    def __init__(self):
        self._hash_db   = KNOWN_MALWARE_HASHES
        self._clean_db  = KNOWN_CLEAN_HASHES
        self._byte_sigs = BYTE_SIGNATURES
        self._str_sigs  = STRING_SIGNATURES
        log.info(
            "Signature engine loaded: %d malware hashes, %d byte sigs, %d string sigs",
            len(self._hash_db), len(self._byte_sigs), len(self._str_sigs),
        )

    def check_hash(self, sha256: str) -> Optional[dict]:
        """Return threat info if hash matches known malware, else None."""
        return self._hash_db.get(sha256.lower())

    def is_known_clean(self, sha256: str) -> bool:
        return sha256.lower() in self._clean_db

    def scan_file(self, file_path: str, max_bytes: int = 10 * 1024 * 1024) -> Optional[dict]:
        """
        Scan file content for byte and string patterns.
        Reads at most max_bytes (default 10 MB) to avoid large file hangs.
        """
        try:
            with open(file_path, "rb") as fh:
                data = fh.read(max_bytes)
        except (OSError, PermissionError) as exc:
            log.debug("Cannot read %s: %s", file_path, exc)
            return None

        # Byte pattern check
        for name, threat_type, severity, pattern in self._byte_sigs:
            if pattern in data:
                log.info("Byte signature hit: %s → %s", file_path, name)
                return {"name": name, "type": threat_type, "severity": severity}

        # String signature check (try to decode as text)
        try:
            text = data.decode("utf-8", errors="ignore")
            for name, threat_type, severity, pattern in self._str_sigs:
                if pattern.lower() in text.lower():
                    log.info("String signature hit: %s → %s", file_path, name)
                    return {"name": name, "type": threat_type, "severity": severity}
        except Exception:
            pass

        return None

    def reload(self) -> None:
        """Reload signature databases (for future live update support)."""
        log.info("Signature database reloaded (%d hashes)", len(self._hash_db))

    def get_stats(self) -> dict:
        return {
            "malware_hashes":  len(self._hash_db),
            "clean_hashes":    len(self._clean_db),
            "byte_signatures": len(self._byte_sigs),
            "string_signatures": len(self._str_sigs),
        }
