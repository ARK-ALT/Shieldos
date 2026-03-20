"""
ShieldOS Engine — FastAPI Server & Application Entry Point
Exposes REST API on localhost:7734 and manages all subsystems.
"""
import asyncio
import json
import logging
import os
import signal
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from queue import Empty, Queue
from typing import Optional

import uvicorn
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

# ── Internal modules ───────────────────────────────────────────────────────
import config as cfg_module
import database as db
from config import (
    API_HOST, API_PORT, APP_NAME, VERSION,
    get_config, update_config, load_config_from_db,
)
from heuristics      import HeuristicEngine
from notifications   import notify_engine_ready, notify_threat
from process_monitor import get_running_processes, scan_processes
from quarantine      import QuarantineManager
from realtime        import RealTimeGuard
from scanner         import ScanEngine, ScanResult
from scheduler       import ScanScheduler
from signatures      import SignatureEngine
from tray            import TrayManager
from virustotal      import VirusTotalEngine
from yara_engine     import YaraEngine

log = logging.getLogger("shieldos.main")

# ── Application globals ────────────────────────────────────────────────────
app = FastAPI(title=APP_NAME, version=VERSION)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

_start_time      = time.time()
_sse_queues: list[Queue] = []   # SSE subscriber queues

# Subsystem handles
_yara_engine:     Optional[YaraEngine]     = None
_sig_engine:      Optional[SignatureEngine] = None
_heur_engine:     Optional[HeuristicEngine] = None
_quarantine_mgr:  Optional[QuarantineManager] = None
_vt_engine:       Optional[VirusTotalEngine] = None
_scan_engine:     Optional[ScanEngine]     = None
_realtime_guard:  Optional[RealTimeGuard]  = None
_scheduler:       Optional[ScanScheduler]  = None
_tray_mgr:        Optional[TrayManager]    = None


# ── SSE helpers ────────────────────────────────────────────────────────────

def emit_event(event_type: str, payload: dict) -> None:
    """Broadcast an SSE event to all connected clients."""
    msg = {"type": event_type, **payload}
    data = json.dumps(msg)
    dead: list[Queue] = []
    for q in list(_sse_queues):
        try:
            q.put_nowait(data)
        except Exception:
            dead.append(q)
    for q in dead:
        try:
            _sse_queues.remove(q)
        except ValueError:
            pass


# ── Startup / shutdown ─────────────────────────────────────────────────────

@app.on_event("startup")
async def startup() -> None:
    global _yara_engine, _sig_engine, _heur_engine, _quarantine_mgr
    global _vt_engine, _scan_engine, _realtime_guard, _scheduler, _tray_mgr

    log.info("Starting %s Engine v%s", APP_NAME, VERSION)

    # 1. Database
    db.init_db()

    # 2. Load config from DB
    load_config_from_db(db.get_config)
    runtime_cfg = get_config()

    # 3. Subsystems
    _yara_engine    = YaraEngine()
    _sig_engine     = SignatureEngine()
    _heur_engine    = HeuristicEngine(
        level=runtime_cfg.get("heuristics_level", "medium")
    )
    _quarantine_mgr = QuarantineManager()

    # 4. VirusTotal (optional)
    vt_key = runtime_cfg.get("virustotal_api_key", "")
    if vt_key:
        _vt_engine = VirusTotalEngine(vt_key)

    # 5. Scan engine
    workers = runtime_cfg.get("parallel_scan_workers", 4)
    _scan_engine = ScanEngine(
        yara_engine      = _yara_engine,
        sig_engine       = _sig_engine,
        heuristic_engine = _heur_engine,
        quarantine_mgr   = _quarantine_mgr,
        vt_engine        = _vt_engine,
        event_emitter    = emit_event,
        workers          = workers,
    )

    # 6. Real-time guard
    _realtime_guard = RealTimeGuard(scan_fn=_scan_engine.scan_file)
    if runtime_cfg.get("realtime_enabled", True):
        _realtime_guard.start()

    # 7. Scheduler
    _scheduler = ScanScheduler(
        scan_directory_fn=_scan_engine.scan_directory
    )
    _scheduler.start()

    # 8. System tray
    _tray_mgr = TrayManager(
        on_quit             = _initiate_shutdown,
        get_quarantine_count= lambda: db.get_quarantine_stats().get("count", 0),
    )
    _tray_mgr.start()

    # 9. Notify
    notify_engine_ready()
    log.info("%s Engine ready on %s:%d", APP_NAME, API_HOST, API_PORT)


@app.on_event("shutdown")
async def shutdown() -> None:
    log.info("Shutting down %s Engine...", APP_NAME)
    if _realtime_guard:
        _realtime_guard.stop()
    if _scheduler:
        _scheduler.stop()
    if _scan_engine:
        _scan_engine.shutdown()
    if _tray_mgr:
        _tray_mgr.stop()
    db.close_db()


def _initiate_shutdown() -> None:
    os.kill(os.getpid(), signal.SIGTERM)


# ── Pydantic models ────────────────────────────────────────────────────────

class ScanFileRequest(BaseModel):
    path: str

class ScanDirectoryRequest(BaseModel):
    path: str
    recursive: bool = True

class ConfigUpdateRequest(BaseModel):
    config: dict

class AddPathRequest(BaseModel):
    path: str

class WhitelistAddRequest(BaseModel):
    hash: str
    path: str = ""

class AddRuleRequest(BaseModel):
    rule_content: str
    rule_name: str


# ── REST Endpoints ─────────────────────────────────────────────────────────

@app.get("/status")
async def status():
    cfg  = get_config()
    stat = db.get_stats()
    return {
        "version":          VERSION,
        "app_name":         APP_NAME,
        "realtime_enabled": _realtime_guard.running if _realtime_guard else False,
        "scan_running":     False,   # extended by frontend
        "uptime_seconds":   int(time.time() - _start_time),
        "stats":            stat,
        "protection_layers": {
            "signatures":  True,
            "yara":        _yara_engine.available if _yara_engine else False,
            "heuristics":  True,
            "virustotal":  bool(cfg.get("virustotal_api_key")),
            "realtime":    _realtime_guard.running if _realtime_guard else False,
            "quarantine":  True,
            "scheduler":   True,
            "network":     True,
        },
    }


@app.get("/stats")
async def stats():
    s   = db.get_stats()
    fps = _scan_engine.get_fps() if _scan_engine else 0
    return {**s, "files_per_second": fps}


@app.post("/scan/file")
async def scan_file(req: ScanFileRequest):
    if not _scan_engine:
        raise HTTPException(503, "Engine not ready")
    result = _scan_engine.scan_file(req.path)
    return result.to_dict()


@app.post("/scan/directory")
async def scan_directory(req: ScanDirectoryRequest):
    if not _scan_engine:
        raise HTTPException(503, "Engine not ready")
    if not Path(req.path).exists():
        raise HTTPException(404, "Path not found")

    # Count files (fast estimate)
    total = sum(1 for _ in Path(req.path).rglob("*")
                if Path(req.path, _).is_file()) if Path(req.path).is_dir() else 1

    scan_id = _scan_engine.scan_directory(
        req.path, recursive=req.recursive, scan_type="manual"
    )
    return {"scan_id": scan_id, "total_files": total}


@app.get("/scan/progress/{scan_id}")
async def scan_progress(scan_id: str):
    if not _scan_engine:
        raise HTTPException(503, "Engine not ready")
    progress = _scan_engine.get_scan_progress(scan_id)
    if not progress:
        raise HTTPException(404, "Scan not found")
    return progress


@app.post("/scan/cancel/{scan_id}")
async def cancel_scan(scan_id: str):
    if _scan_engine:
        _scan_engine.cancel_scan(scan_id)
    return {"cancelled": True}


@app.get("/threats")
async def get_threats(limit: int = 50, offset: int = 0):
    return db.get_threats(limit=limit)


@app.get("/quarantine")
async def get_quarantine():
    return db.get_quarantine()


@app.post("/quarantine/restore/{qid}")
async def restore_quarantine(qid: int):
    if not _quarantine_mgr:
        raise HTTPException(503, "Engine not ready")
    ok = _quarantine_mgr.restore_file(qid)
    if not ok:
        raise HTTPException(404, "Quarantine entry not found")
    return {"restored": True}


@app.delete("/quarantine/{qid}")
async def delete_quarantine(qid: int):
    if not _quarantine_mgr:
        raise HTTPException(503, "Engine not ready")
    ok = _quarantine_mgr.delete_permanently(qid)
    if not ok:
        raise HTTPException(404, "Quarantine entry not found")
    return {"deleted": True}


@app.get("/history")
async def get_history(limit: int = 100, offset: int = 0):
    return db.get_scan_history(limit=limit, offset=offset)


@app.get("/config")
async def get_cfg():
    return get_config()


@app.post("/config")
async def update_cfg(req: ConfigUpdateRequest):
    new_cfg = update_config(req.config)
    db.save_full_config(req.config)

    # Apply VT key change
    vt_key = req.config.get("virustotal_api_key")
    if vt_key is not None and _vt_engine:
        _vt_engine.update_api_key(vt_key)
    elif vt_key and not _vt_engine:
        globals()["_vt_engine"] = VirusTotalEngine(vt_key)
        if _scan_engine:
            _scan_engine.vt_engine = globals()["_vt_engine"]

    # Apply heuristics level change
    if "heuristics_level" in req.config and _heur_engine:
        _heur_engine.set_level(req.config["heuristics_level"])

    # Apply scheduler change
    if any(k in req.config for k in
           ("scheduled_scan_enabled", "scheduled_scan_time")):
        if _scheduler:
            _scheduler.update_schedule()

    return new_cfg


@app.post("/realtime/start")
async def realtime_start():
    if not _realtime_guard:
        raise HTTPException(503, "Engine not ready")
    ok = _realtime_guard.start()
    update_config({"realtime_enabled": True})
    db.set_config("realtime_enabled", "true")
    if _tray_mgr:
        _tray_mgr.set_state("protected")
    return {"running": ok}


@app.post("/realtime/stop")
async def realtime_stop():
    if _realtime_guard:
        _realtime_guard.stop()
    update_config({"realtime_enabled": False})
    db.set_config("realtime_enabled", "false")
    if _tray_mgr:
        _tray_mgr.set_state("paused")
    return {"running": False}


@app.post("/realtime/add-path")
async def realtime_add_path(req: AddPathRequest):
    if not _realtime_guard:
        raise HTTPException(503, "Engine not ready")
    ok = _realtime_guard.add_watch_path(req.path)
    return {"added": ok, "paths": _realtime_guard.get_watch_paths()}


@app.post("/realtime/remove-path")
async def realtime_remove_path(req: AddPathRequest):
    if not _realtime_guard:
        raise HTTPException(503, "Engine not ready")
    _realtime_guard.remove_watch_path(req.path)
    return {"paths": _realtime_guard.get_watch_paths()}


@app.get("/processes")
async def get_processes():
    if not _scan_engine:
        return get_running_processes()
    procs = scan_processes(lambda p: _scan_engine.scan_file(p).to_dict())
    return procs


@app.get("/events")
async def sse_events():
    """Server-Sent Events stream for live scan results."""
    q: Queue = Queue()
    _sse_queues.append(q)

    async def event_generator():
        try:
            # Send initial connected message
            yield f"data: {json.dumps({'type': 'connected', 'version': VERSION})}\n\n"
            while True:
                try:
                    data = q.get(timeout=1)
                    yield f"data: {data}\n\n"
                except Empty:
                    # Heartbeat to keep connection alive
                    yield ": heartbeat\n\n"
                await asyncio.sleep(0)
        except asyncio.CancelledError:
            pass
        finally:
            try:
                _sse_queues.remove(q)
            except ValueError:
                pass

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control":    "no-cache",
            "X-Accel-Buffering":"no",
        },
    )


@app.post("/whitelist/add")
async def whitelist_add(req: WhitelistAddRequest):
    db.add_to_whitelist(req.hash, req.path)
    return {"added": True}


@app.get("/whitelist")
async def get_whitelist():
    return db.get_whitelist()


@app.get("/rules")
async def get_rules():
    if not _yara_engine:
        return []
    return _yara_engine.get_rule_names()


@app.post("/rules/reload")
async def reload_rules():
    if not _yara_engine:
        raise HTTPException(503, "YARA engine not available")
    ok = _yara_engine.reload_rules()
    return {"reloaded": ok, "rules": _yara_engine.get_rule_names()}


@app.post("/rules/add")
async def add_rule(req: AddRuleRequest):
    if not _yara_engine:
        raise HTTPException(503, "YARA engine not available")
    ok = _yara_engine.add_rule(req.rule_content, req.rule_name)
    return {"added": ok}


@app.delete("/history")
async def clear_history():
    db.clear_scan_history()
    return {"cleared": True}


@app.get("/network")
async def get_network():
    from network_monitor import get_connections
    return get_connections()


# ── Entry point ────────────────────────────────────────────────────────────

if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host    = API_HOST,
        port    = API_PORT,
        log_level="warning",
        reload  = False,
    )
