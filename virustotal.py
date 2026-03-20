"""
ShieldOS Engine — VirusTotal API v3 Integration
"""
import time
import logging
import threading
from dataclasses import dataclass, field
from typing import Optional

import requests

import database as db

log = logging.getLogger("shieldos.virustotal")

BASE_URL = "https://www.virustotal.com/api/v3"


@dataclass
class VTResult:
    sha256:           str
    malicious:        int
    suspicious:       int
    harmless:         int
    undetected:       int
    total_engines:    int
    detection_ratio:  float
    threat_names:     list[str]    = field(default_factory=list)
    scan_date:        str          = ""
    permalink:        str          = ""
    is_threat:        bool         = False

    def __post_init__(self):
        if self.total_engines > 0:
            self.detection_ratio = self.malicious / self.total_engines
        self.is_threat = self.detection_ratio > 0.05


def _parse_vt_response(data: dict) -> VTResult:
    attrs  = data.get("data", {}).get("attributes", {})
    stats  = attrs.get("last_analysis_stats", {})
    results = attrs.get("last_analysis_results", {})
    total  = sum(stats.values()) or 1

    # Collect unique threat names (non-empty, non-clean)
    threat_names: list[str] = list({
        v.get("result", "")
        for v in results.values()
        if v.get("category") in ("malicious", "suspicious")
        and v.get("result")
    })

    sha256 = attrs.get("sha256", data.get("data", {}).get("id", ""))

    return VTResult(
        sha256          = sha256,
        malicious       = stats.get("malicious", 0),
        suspicious      = stats.get("suspicious", 0),
        harmless        = stats.get("harmless", 0),
        undetected      = stats.get("undetected", 0),
        total_engines   = total,
        detection_ratio = stats.get("malicious", 0) / total,
        threat_names    = threat_names[:5],   # top 5
        scan_date       = attrs.get("last_analysis_date", ""),
        permalink       = f"https://www.virustotal.com/gui/file/{sha256}",
    )


class VirusTotalEngine:
    """
    Wraps VirusTotal API v3.
    Uses hash lookup first (no quota cost), falls back to file upload.
    """

    def __init__(self, api_key: str):
        self.api_key           = api_key
        self.headers           = {"x-apikey": api_key}
        self.rate_limit_delay  = 15   # free tier: 4 req/min → ~15s gap
        self._last_request     = 0.0
        self._lock             = threading.Lock()

    def _wait_rate_limit(self) -> None:
        """Enforce minimum delay between API calls."""
        with self._lock:
            elapsed = time.time() - self._last_request
            if elapsed < self.rate_limit_delay:
                time.sleep(self.rate_limit_delay - elapsed)
            self._last_request = time.time()

    # ── Hash lookup (FREE, no quota) ───────────────────────────────────────

    def scan_hash(self, sha256: str) -> Optional[VTResult]:
        """
        Look up a file hash on VirusTotal.
        Checks local 24-hour cache first to avoid redundant API calls.
        """
        if not self.api_key:
            return None

        # Check cache
        cached = db.vt_cache_get(sha256)
        if cached:
            log.debug("VT cache hit for %s", sha256[:16])
            return VTResult(**cached)

        self._wait_rate_limit()

        try:
            response = requests.get(
                f"{BASE_URL}/files/{sha256}",
                headers=self.headers,
                timeout=15,
            )
        except requests.RequestException as exc:
            log.warning("VT hash lookup network error: %s", exc)
            return None

        if response.status_code == 404:
            return None   # File not in VT database
        if response.status_code == 429:
            log.warning("VT rate limit hit — backing off 60s")
            time.sleep(60)
            return None
        if response.status_code != 200:
            log.warning("VT API error %d for hash %s", response.status_code, sha256[:16])
            return None

        result = _parse_vt_response(response.json())

        # Cache result
        import dataclasses
        db.vt_cache_set(sha256, dataclasses.asdict(result))

        return result

    # ── File upload (quota cost) ───────────────────────────────────────────

    def scan_file(self, file_path: str) -> Optional[VTResult]:
        """
        Upload an unknown file to VirusTotal and wait for analysis.
        Only called when hash lookup returns 404.
        """
        if not self.api_key:
            return None

        self._wait_rate_limit()

        # Upload file
        try:
            with open(file_path, "rb") as fh:
                response = requests.post(
                    f"{BASE_URL}/files",
                    headers=self.headers,
                    files={"file": fh},
                    timeout=60,
                )
        except (OSError, requests.RequestException) as exc:
            log.warning("VT file upload error: %s", exc)
            return None

        if response.status_code != 200:
            log.warning("VT upload failed: %d", response.status_code)
            return None

        analysis_id = response.json().get("data", {}).get("id", "")
        if not analysis_id:
            return None

        log.info("VT file uploaded, analysis id: %s", analysis_id)

        # Poll for completion
        deadline = time.time() + 60
        while time.time() < deadline:
            time.sleep(5)
            self._wait_rate_limit()
            try:
                poll = requests.get(
                    f"{BASE_URL}/analyses/{analysis_id}",
                    headers=self.headers,
                    timeout=15,
                )
                if poll.status_code == 200:
                    data = poll.json()
                    status = data.get("data", {}).get("attributes", {}).get("status")
                    if status == "completed":
                        # Get the file report
                        sha256 = (
                            data.get("meta", {})
                            .get("file_info", {})
                            .get("sha256", "")
                        )
                        if sha256:
                            return self.scan_hash(sha256)
            except requests.RequestException:
                pass

        log.warning("VT analysis timed out for %s", file_path)
        return None

    # ── URL report ─────────────────────────────────────────────────────────

    def get_url_report(self, url: str) -> Optional[VTResult]:
        """Check a URL against VT database."""
        if not self.api_key:
            return None

        import base64
        # VT API requires base64url-encoded URL (no padding)
        url_id = base64.urlsafe_b64encode(url.encode()).rstrip(b"=").decode()

        self._wait_rate_limit()
        try:
            response = requests.get(
                f"{BASE_URL}/urls/{url_id}",
                headers=self.headers,
                timeout=15,
            )
        except requests.RequestException as exc:
            log.warning("VT URL report error: %s", exc)
            return None

        if response.status_code != 200:
            return None

        return _parse_vt_response(response.json())

    def update_api_key(self, new_key: str) -> None:
        self.api_key  = new_key
        self.headers  = {"x-apikey": new_key}
