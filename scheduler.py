"""
ShieldOS Engine — Scan Scheduler
Runs scheduled scans using the schedule library.
"""
import logging
import sys
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Callable, Optional

import database as db
from config import get_config

log = logging.getLogger("shieldos.scheduler")

try:
    import schedule
    SCHEDULE_AVAILABLE = True
except ImportError:
    log.warning("schedule not installed — scheduled scans disabled")
    SCHEDULE_AVAILABLE = False


class ScanScheduler:
    """
    Checks config every minute and runs scheduled directory scans.
    Uses the `schedule` library for cron-like scheduling.
    """

    def __init__(self, scan_directory_fn: Callable[[str, bool, str], str]):
        """
        scan_directory_fn: callable(path, recursive, scan_type) → scan_id
        """
        self._scan_fn = scan_directory_fn
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._scheduled_job = None

    def start(self) -> None:
        if not SCHEDULE_AVAILABLE:
            return
        self._stop_event.clear()
        self._thread = threading.Thread(
            target  = self._run,
            daemon  = True,
            name    = "shieldos-scheduler",
        )
        self._thread.start()
        self._register_from_config()
        log.info("Scan scheduler started")

    def stop(self) -> None:
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=5)
        log.info("Scan scheduler stopped")

    def _register_from_config(self) -> None:
        """Load schedule from config and register with schedule library."""
        if not SCHEDULE_AVAILABLE:
            return
        cfg = get_config()
        enabled = cfg.get("scheduled_scan_enabled", True)
        scan_time = cfg.get("scheduled_scan_time", "02:00")   # "HH:MM"

        if self._scheduled_job:
            try:
                schedule.cancel_job(self._scheduled_job)
            except Exception:
                pass

        if not enabled:
            log.info("Scheduled scans disabled in config")
            return

        target_path = str(Path.home())

        self._scheduled_job = (
            schedule.every().day.at(scan_time).do(
                self._run_scheduled_scan, target_path
            )
        )
        log.info("Scheduled scan set for %s on %s", scan_time, target_path)

    def update_schedule(self) -> None:
        """Re-read config and update schedule (call after config changes)."""
        if SCHEDULE_AVAILABLE:
            schedule.clear()
            self._register_from_config()

    def _run_scheduled_scan(self, path: str) -> None:
        log.info("Starting scheduled scan: %s", path)
        try:
            scan_id = self._scan_fn(path, True, "scheduled")
            log.info("Scheduled scan launched: scan_id=%s", scan_id)
        except Exception as exc:
            log.error("Scheduled scan error: %s", exc)

    def _run(self) -> None:
        while not self._stop_event.is_set():
            if SCHEDULE_AVAILABLE:
                try:
                    schedule.run_pending()
                except Exception as exc:
                    log.error("Scheduler error: %s", exc)
            self._stop_event.wait(timeout=60)   # check every minute
