"""
ShieldOS Engine — Quarantine Manager
XOR-encrypts threats to prevent accidental execution.
"""
import os
import logging
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import database as db
from config import QUARANTINE_DIR

log = logging.getLogger("shieldos.quarantine")

QUARANTINE_KEY = 0xAB   # Simple XOR key


def _xor_bytes(data: bytes, key: int = QUARANTINE_KEY) -> bytes:
    return bytes(b ^ key for b in data)


@dataclass
class QuarantineResult:
    success:         bool
    quarantine_id:   Optional[int]
    quarantine_path: Optional[str]
    error:           Optional[str] = None


class QuarantineManager:
    """
    Manages quarantine operations:
    - Move & XOR-encrypt detected threats
    - Restore files to original location
    - Permanent deletion
    """

    def __init__(self):
        self._lock = threading.Lock()
        QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)
        log.info("Quarantine manager ready: %s", QUARANTINE_DIR)

    def quarantine_file(
        self,
        file_path: str,
        threat_name: str,
        threat_type: str = "unknown",
        severity: str = "high",
        file_hash: str = "",
    ) -> QuarantineResult:
        """
        1. Read file bytes
        2. XOR-encrypt content
        3. Write to QUARANTINE_DIR/<hash16>.quar
        4. Delete original
        5. Record in DB
        """
        with self._lock:
            src = Path(file_path)
            if not src.exists():
                return QuarantineResult(
                    success=False,
                    quarantine_id=None,
                    quarantine_path=None,
                    error="File not found",
                )

            # Compute quarantine filename
            import hashlib
            if not file_hash:
                try:
                    data = src.read_bytes()
                    file_hash = hashlib.sha256(data).hexdigest()
                except OSError as exc:
                    return QuarantineResult(
                        success=False, quarantine_id=None,
                        quarantine_path=None, error=str(exc),
                    )
            else:
                try:
                    data = src.read_bytes()
                except OSError as exc:
                    return QuarantineResult(
                        success=False, quarantine_id=None,
                        quarantine_path=None, error=str(exc),
                    )

            qname = f"{file_hash[:16]}.quar"
            qdest = QUARANTINE_DIR / qname

            # Handle collision (different files, same first-16 chars)
            counter = 0
            while qdest.exists():
                counter += 1
                qdest = QUARANTINE_DIR / f"{file_hash[:16]}_{counter}.quar"

            # XOR encrypt & write
            encrypted = _xor_bytes(data)
            try:
                qdest.write_bytes(encrypted)
            except OSError as exc:
                return QuarantineResult(
                    success=False, quarantine_id=None,
                    quarantine_path=None, error=str(exc),
                )

            # Mark quarantine dir non-executable (best effort)
            try:
                qdest.chmod(0o400)
            except Exception:
                pass

            # Delete original
            try:
                src.unlink()
            except OSError as exc:
                log.warning("Could not delete original %s: %s", file_path, exc)
                # Still log quarantine — file is encrypted

            # Record in DB
            qid = db.add_quarantine_entry(
                original_path   = str(src),
                quarantine_path = str(qdest),
                filename        = src.name,
                file_hash       = file_hash,
                threat_name     = threat_name,
                threat_type     = threat_type,
                severity        = severity,
            )

            log.info("Quarantined: %s → %s (id=%d)", file_path, qdest.name, qid)
            return QuarantineResult(
                success         = True,
                quarantine_id   = qid,
                quarantine_path = str(qdest),
            )

    def restore_file(self, quarantine_id: int) -> bool:
        """
        1. Look up quarantine record
        2. XOR-decrypt .quar file
        3. Write to original path
        4. Mark restored in DB
        """
        with self._lock:
            entry = db.get_quarantine_entry(quarantine_id)
            if not entry:
                log.warning("Quarantine entry %d not found", quarantine_id)
                return False

            qpath = Path(entry["quarantine_path"])
            if not qpath.exists():
                log.warning("Quarantine file missing: %s", qpath)
                return False

            try:
                encrypted = qpath.read_bytes()
                decrypted = _xor_bytes(encrypted)
            except OSError as exc:
                log.error("Cannot read quarantine file: %s", exc)
                return False

            original = Path(entry["original_path"])
            original.parent.mkdir(parents=True, exist_ok=True)

            try:
                original.write_bytes(decrypted)
            except OSError as exc:
                log.error("Cannot restore file to %s: %s", original, exc)
                return False

            db.mark_quarantine_restored(quarantine_id)
            log.info("Restored quarantine %d to %s", quarantine_id, original)
            return True

    def delete_permanently(self, quarantine_id: int) -> bool:
        """Secure-delete quarantine file and remove DB record."""
        with self._lock:
            entry = db.get_quarantine_entry(quarantine_id)
            if not entry:
                return False

            qpath = Path(entry["quarantine_path"])
            if qpath.exists():
                try:
                    # Overwrite with zeros before deletion
                    size = qpath.stat().st_size
                    qpath.write_bytes(b"\x00" * size)
                    qpath.unlink()
                except OSError as exc:
                    log.error("Cannot delete quarantine file: %s", exc)
                    return False

            db.delete_quarantine_entry(quarantine_id)
            log.info("Permanently deleted quarantine entry %d", quarantine_id)
            return True

    def list_quarantined(self) -> list[dict]:
        return db.get_quarantine(include_restored=False)

    def get_quarantine_stats(self) -> dict:
        entries = db.get_quarantine(include_restored=False)
        total_size = 0
        for entry in entries:
            qpath = Path(entry.get("quarantine_path", ""))
            try:
                total_size += qpath.stat().st_size
            except Exception:
                pass
        stats = db.get_quarantine_stats()
        stats["total_size_bytes"] = total_size
        stats["total_size_mb"]    = round(total_size / (1024 * 1024), 2)
        return stats
