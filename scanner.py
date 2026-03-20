"""
ShieldOS Engine — Core Scan Engine
Parallel file scanning with full detection pipeline.
"""
import hashlib
import logging
import os
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import AsyncGenerator, Callable, Optional

import database as db
from config import (
    DANGEROUS_EXTENSIONS, DEFAULT_CONFIG, SCAN_CLIENT_IDS,
    WHITELIST_HASHES, get_config,
)
from heuristics   import HeuristicEngine
from quarantine   import QuarantineManager
from signatures   import SignatureEngine
from yara_engine  import YaraEngine

log = logging.getLogger("shieldos.scanner")

# ── Result dataclass ──────────────────────────────────────────────────────

@dataclass
class ScanResult:
    path:             str
    filename:         str
    file_hash_md5:    str
    file_hash_sha256: str
    file_size:        int
    result:           str               # 'clean' | 'threat' | 'suspicious' | 'error'
    threat_name:      Optional[str]
    threat_type:      Optional[str]
    severity:         Optional[str]
    engine:           Optional[str]     # 'yara' | 'virustotal' | 'heuristic' | 'signature'
    client_id:        str
    scan_duration_ms: int
    timestamp:        str
    indicators:       list[str]         = field(default_factory=list)
    scan_type:        str               = "manual"

    def to_dict(self) -> dict:
        return {
            "path":             self.path,
            "filename":         self.filename,
            "file_hash_md5":    self.file_hash_md5,
            "file_hash_sha256": self.file_hash_sha256,
            "file_size":        self.file_size,
            "result":           self.result,
            "threat_name":      self.threat_name,
            "threat_type":      self.threat_type,
            "severity":         self.severity,
            "engine":           self.engine,
            "client_id":        self.client_id,
            "scan_duration_ms": self.scan_duration_ms,
            "timestamp":        self.timestamp,
            "indicators":       self.indicators,
            "scan_type":        self.scan_type,
        }


# ── Active scan tracking ───────────────────────────────────────────────────

@dataclass
class ScanSession:
    scan_id:     str
    target_path: str
    total_files: int    = 0
    scanned:     int    = 0
    threats:     int    = 0
    running:     bool   = True
    cancelled:   bool   = False
    results:     list   = field(default_factory=list)


_active_scans: dict[str, ScanSession] = {}
_scan_lock     = threading.Lock()

# Result hash cache (sha256 → ScanResult) to skip re-scanning unchanged files
_result_cache: dict[str, ScanResult] = {}
_CACHE_MAX = 10_000


class ScanEngine:
    """
    Multi-threaded scan engine with full detection pipeline:
    Signature → YARA → Heuristics → VirusTotal
    """

    def __init__(
        self,
        yara_engine:      YaraEngine,
        sig_engine:       SignatureEngine,
        heuristic_engine: HeuristicEngine,
        quarantine_mgr:   QuarantineManager,
        vt_engine=None,       # Optional VirusTotalEngine
        event_emitter:    Optional[Callable] = None,
        workers:          int = 4,
    ):
        self.yara_engine      = yara_engine
        self.sig_engine       = sig_engine
        self.heuristic_engine = heuristic_engine
        self.quarantine_mgr   = quarantine_mgr
        self.vt_engine        = vt_engine
        self.event_emitter    = event_emitter   # callable(event_type, payload)
        self.workers          = workers
        self._pool            = ThreadPoolExecutor(
            max_workers=workers,
            thread_name_prefix="shieldos-sc",
        )
        self._client_map: dict[str, str] = {}   # thread_name → SC-xx
        self._fps_counter = 0
        self._fps_lock    = threading.Lock()
        log.info("ScanEngine started (%d workers)", workers)

    # ── Public API ─────────────────────────────────────────────────────────

    def scan_file(
        self,
        path: str,
        scan_type: str = "manual",
        client_id: Optional[str] = None,
    ) -> ScanResult:
        """Full detection pipeline for a single file."""
        start_ms  = time.monotonic()
        file_path = Path(path)
        client_id = client_id or self._get_client_id()
        cfg       = get_config()

        # ── Basic checks ──────────────────────────────────────────────────
        if not file_path.exists() or not file_path.is_file():
            return self._make_error(path, client_id, "File not found", scan_type)

        try:
            stat = file_path.stat()
        except OSError:
            return self._make_error(path, client_id, "Cannot stat file", scan_type)

        # Skip oversized files
        max_mb = cfg.get("max_file_size_mb", 512)
        if stat.st_size > max_mb * 1024 * 1024:
            return self._make_clean(path, stat.st_size, client_id, scan_type,
                                    note="Skipped — exceeds max file size")

        # Skip excluded paths
        excluded = cfg.get("excluded_paths", [])
        if any(path.startswith(excl) for excl in excluded):
            return self._make_clean(path, stat.st_size, client_id, scan_type,
                                    note="Excluded path")

        # ── Compute hashes ─────────────────────────────────────────────────
        try:
            md5_h    = hashlib.md5()
            sha256_h = hashlib.sha256()
            with open(path, "rb") as fh:
                for chunk in iter(lambda: fh.read(65536), b""):
                    md5_h.update(chunk)
                    sha256_h.update(chunk)
            md5_digest    = md5_h.hexdigest()
            sha256_digest = sha256_h.hexdigest()
        except (OSError, PermissionError) as exc:
            return self._make_error(path, client_id, str(exc), scan_type)

        # ── Whitelist check ────────────────────────────────────────────────
        if md5_digest in WHITELIST_HASHES or db.is_whitelisted(sha256_digest):
            return self._make_clean(path, stat.st_size, client_id, scan_type,
                                    md5=md5_digest, sha256=sha256_digest)

        # ── Cache check ────────────────────────────────────────────────────
        cache_key = f"{sha256_digest}:{stat.st_mtime_ns}"
        if cache_key in _result_cache:
            cached = _result_cache[cache_key]
            with self._fps_lock:
                self._fps_counter += 1
            return cached

        # ── 1. Known clean hash ────────────────────────────────────────────
        if self.sig_engine.is_known_clean(sha256_digest):
            return self._finalise(
                path, stat.st_size, md5_digest, sha256_digest,
                "clean", None, None, None, None, client_id,
                start_ms, scan_type, [],
            )

        # ── 2. Local signature (hash DB) ───────────────────────────────────
        hash_hit = self.sig_engine.check_hash(sha256_digest)
        if hash_hit:
            return self._finalise(
                path, stat.st_size, md5_digest, sha256_digest,
                "threat", hash_hit["name"], hash_hit["type"],
                hash_hit["severity"], "signature", client_id,
                start_ms, scan_type, [],
            )

        # ── 3. Byte/string signatures ──────────────────────────────────────
        sig_hit = self.sig_engine.scan_file(path)
        if sig_hit:
            return self._finalise(
                path, stat.st_size, md5_digest, sha256_digest,
                "threat", sig_hit["name"], sig_hit["type"],
                sig_hit["severity"], "signature", client_id,
                start_ms, scan_type, [],
            )

        # ── 4. YARA rules ──────────────────────────────────────────────────
        yara_hit = self.yara_engine.scan(path)
        if yara_hit:
            severity = yara_hit.severity or "high"
            return self._finalise(
                path, stat.st_size, md5_digest, sha256_digest,
                "threat", yara_hit.rule_name, "yara_rule",
                severity, "yara", client_id,
                start_ms, scan_type,
                [yara_hit.description] if yara_hit.description else [],
            )

        # ── 5. Heuristics ──────────────────────────────────────────────────
        level      = cfg.get("heuristics_level", "medium")
        self.heuristic_engine.set_level(level)
        heur_result = self.heuristic_engine.analyze(path)

        if heur_result.risk_level == "threat":
            return self._finalise(
                path, stat.st_size, md5_digest, sha256_digest,
                "threat", "Heuristic.Threat", "heuristic",
                heur_result.severity or "high", "heuristic", client_id,
                start_ms, scan_type, heur_result.indicators,
            )
        elif heur_result.risk_level == "suspicious":
            # Escalate to VirusTotal if configured
            if self.vt_engine and cfg.get("virustotal_api_key"):
                vt_result = self.vt_engine.scan_hash(sha256_digest)
                if vt_result and vt_result.is_threat:
                    name = vt_result.threat_names[0] if vt_result.threat_names \
                           else "VT.Detection"
                    return self._finalise(
                        path, stat.st_size, md5_digest, sha256_digest,
                        "threat", name, "virustotal",
                        "high", "virustotal", client_id,
                        start_ms, scan_type, [],
                    )
            return self._finalise(
                path, stat.st_size, md5_digest, sha256_digest,
                "suspicious", "Heuristic.Suspicious", "heuristic",
                "med", "heuristic", client_id,
                start_ms, scan_type, heur_result.indicators,
            )

        # ── 6. Optional VirusTotal lookup ──────────────────────────────────
        if self.vt_engine and cfg.get("virustotal_api_key"):
            vt_result = self.vt_engine.scan_hash(sha256_digest)
            if vt_result and vt_result.is_threat:
                name = vt_result.threat_names[0] if vt_result.threat_names \
                       else "VT.Detection"
                return self._finalise(
                    path, stat.st_size, md5_digest, sha256_digest,
                    "threat", name, "virustotal",
                    "high", "virustotal", client_id,
                    start_ms, scan_type, [],
                )

        # ── Clean ──────────────────────────────────────────────────────────
        return self._finalise(
            path, stat.st_size, md5_digest, sha256_digest,
            "clean", None, None, None, None, client_id,
            start_ms, scan_type, [],
        )

    def scan_directory(
        self,
        dir_path: str,
        recursive: bool = True,
        scan_type: str = "manual",
    ) -> str:
        """
        Enqueue a directory scan. Returns scan_id for progress tracking.
        Results emitted via SSE events and stored in ScanSession.
        """
        scan_id = str(uuid.uuid4())[:8]
        session = ScanSession(scan_id=scan_id, target_path=dir_path)

        with _scan_lock:
            _active_scans[scan_id] = session

        # Collect files
        all_files = self._collect_files(dir_path, recursive)
        session.total_files = len(all_files)

        if self.event_emitter:
            self.event_emitter("scan_progress", {
                "scan_id": scan_id,
                "scanned": 0,
                "total":   len(all_files),
                "percent": 0,
                "threats": 0,
            })

        threading.Thread(
            target  = self._run_directory_scan,
            args    = (scan_id, session, all_files, scan_type),
            daemon  = True,
            name    = f"dir-scan-{scan_id}",
        ).start()

        return scan_id

    def get_scan_progress(self, scan_id: str) -> Optional[dict]:
        session = _active_scans.get(scan_id)
        if not session:
            return None
        pct = int(session.scanned / session.total_files * 100) \
              if session.total_files else 100
        return {
            "scan_id": scan_id,
            "scanned": session.scanned,
            "total":   session.total_files,
            "threats": session.threats,
            "percent": pct,
            "running": session.running,
        }

    def cancel_scan(self, scan_id: str) -> bool:
        session = _active_scans.get(scan_id)
        if session:
            session.cancelled = True
            return True
        return False

    def scan_running_processes(self) -> list[ScanResult]:
        """Scan all running process executables."""
        try:
            import psutil
        except ImportError:
            log.warning("psutil not installed — process scanning unavailable")
            return []

        results = []
        seen: set[str] = set()

        for proc in psutil.process_iter(["pid", "name", "exe"]):
            try:
                exe = proc.info.get("exe")
                if exe and exe not in seen:
                    seen.add(exe)
                    result = self.scan_file(exe, scan_type="process")
                    results.append(result)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

        return results

    def get_fps(self) -> int:
        """Return approximate files-per-second rate."""
        with self._fps_lock:
            fps = self._fps_counter
            self._fps_counter = 0
        return fps

    def shutdown(self) -> None:
        self._pool.shutdown(wait=False)

    # ── Internals ──────────────────────────────────────────────────────────

    def _run_directory_scan(
        self,
        scan_id:  str,
        session:  ScanSession,
        files:    list[str],
        scan_type: str,
    ) -> None:
        futures = {}
        client_cycle = {f: SCAN_CLIENT_IDS[i % len(SCAN_CLIENT_IDS)]
                        for i, f in enumerate(files)}

        for fpath in files:
            if session.cancelled:
                break
            cid = client_cycle[fpath]
            fut = self._pool.submit(self.scan_file, fpath, scan_type, cid)
            futures[fut] = fpath

        for fut in as_completed(futures):
            if session.cancelled:
                break
            try:
                result = fut.result()
            except Exception as exc:
                log.debug("Worker exception: %s", exc)
                continue

            session.scanned += 1
            if result.result in ("threat", "suspicious"):
                session.threats += 1

            session.results.append(result.to_dict())

            pct = int(session.scanned / session.total_files * 100) \
                  if session.total_files else 100

            if self.event_emitter:
                self.event_emitter("scan_result", result.to_dict())
                if session.scanned % 10 == 0:
                    self.event_emitter("scan_progress", {
                        "scan_id": scan_id,
                        "scanned": session.scanned,
                        "total":   session.total_files,
                        "percent": pct,
                        "threats": session.threats,
                    })

            with self._fps_lock:
                self._fps_counter += 1

        session.running = False
        if self.event_emitter:
            self.event_emitter("scan_progress", {
                "scan_id": scan_id,
                "scanned": session.scanned,
                "total":   session.total_files,
                "percent": 100,
                "threats": session.threats,
                "done":    True,
            })

        log.info(
            "Scan %s complete: %d files, %d threats",
            scan_id, session.scanned, session.threats,
        )

    def _collect_files(self, dir_path: str, recursive: bool) -> list[str]:
        cfg       = get_config()
        excluded  = cfg.get("excluded_paths", [])
        max_mb    = cfg.get("max_file_size_mb", 512)
        scan_hidden = cfg.get("scan_hidden", True)
        files: list[str] = []

        try:
            root = Path(dir_path)
            iterator = root.rglob("*") if recursive else root.glob("*")
            for entry in iterator:
                try:
                    if not entry.is_file():
                        continue
                    if not scan_hidden and entry.name.startswith("."):
                        continue
                    if any(str(entry).startswith(excl) for excl in excluded):
                        continue
                    if entry.stat().st_size > max_mb * 1024 * 1024:
                        continue
                    files.append(str(entry))
                except (OSError, PermissionError):
                    pass
        except (OSError, PermissionError) as exc:
            log.warning("Cannot walk %s: %s", dir_path, exc)

        return files

    def _get_client_id(self) -> str:
        import threading as _t
        name = _t.current_thread().name
        if name not in self._client_map:
            idx = len(self._client_map) % len(SCAN_CLIENT_IDS)
            self._client_map[name] = SCAN_CLIENT_IDS[idx]
        return self._client_map[name]

    def _finalise(
        self,
        path: str, size: int, md5: str, sha256: str,
        result: str, threat_name, threat_type, severity, engine,
        client_id: str, start_ms: float, scan_type: str,
        indicators: list[str],
    ) -> ScanResult:
        duration = int((time.monotonic() - start_ms) * 1000)
        ts       = datetime.now(timezone.utc).isoformat()
        filename = Path(path).name
        cfg      = get_config()

        # Quarantine if threat and auto-quarantine enabled
        action = "allowed"
        if result == "threat" and cfg.get("quarantine_auto", True):
            q = self.quarantine_mgr.quarantine_file(
                path, threat_name or "Unknown", threat_type or "unknown",
                severity or "high", sha256,
            )
            action = "quarantined" if q.success else "allowed"

        # Emit threat event
        if result in ("threat", "suspicious") and self.event_emitter:
            self.event_emitter("threat_detected", {
                "path":        path,
                "threat_name": threat_name,
                "severity":    severity,
                "engine":      engine,
                "action":      action,
            })

        # Log to DB
        db.log_scan(
            path=path, filename=filename, result=result,
            file_size=size, file_hash=sha256, scan_type=scan_type,
            threat_name=threat_name, threat_type=threat_type,
            severity=severity, action=action, client_id=client_id,
            engine=engine,
        )

        sr = ScanResult(
            path=path, filename=filename,
            file_hash_md5=md5, file_hash_sha256=sha256,
            file_size=size, result=result,
            threat_name=threat_name, threat_type=threat_type,
            severity=severity, engine=engine,
            client_id=client_id, scan_duration_ms=duration,
            timestamp=ts, indicators=indicators, scan_type=scan_type,
        )

        # Cache clean results
        if result == "clean" and len(_result_cache) < _CACHE_MAX:
            cache_key = f"{sha256}:{Path(path).stat().st_mtime_ns}" \
                        if Path(path).exists() else sha256
            _result_cache[cache_key] = sr

        return sr

    def _make_clean(self, path, size, client_id, scan_type,
                    md5="", sha256="", note="") -> ScanResult:
        return self._finalise(
            path, size, md5, sha256, "clean",
            None, None, None, None, client_id,
            time.monotonic(), scan_type, [note] if note else [],
        )

    def _make_error(self, path, client_id, msg, scan_type) -> ScanResult:
        ts = datetime.now(timezone.utc).isoformat()
        return ScanResult(
            path=path, filename=Path(path).name,
            file_hash_md5="", file_hash_sha256="",
            file_size=0, result="error",
            threat_name=None, threat_type=None,
            severity=None, engine=None,
            client_id=client_id, scan_duration_ms=0,
            timestamp=ts, indicators=[msg], scan_type=scan_type,
        )
