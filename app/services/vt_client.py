"""VirusTotal v3 API wrapper (minimal).

Only the endpoints required for this MVP are implemented.
"""
from __future__ import annotations

import logging
from time import sleep
from typing import Any, Optional

import httpx

from app.core.config import VT_API_KEY

logger = logging.getLogger(__name__)

BASE_URL = "https://www.virustotal.com/api/v3"
RATE_LIMIT_SLEEP = 16  # secs (public API: 4 requests per minute)


class VirusTotalDisabled(RuntimeError):
    """Raised when VT integration is disabled via config."""


class VTClient:
    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or VT_API_KEY
        if not self.api_key:
            raise VirusTotalDisabled("VirusTotal API key not set")
        self.headers = {"x-apikey": self.api_key}
        self.client = httpx.Client(timeout=30)

    def _get(self, path: str) -> Any:
        url = f"{BASE_URL}{path}"
        response = self.client.get(url, headers=self.headers)
        if response.status_code == 429:
            logger.warning("VT rate limit reached; sleeping %s sec", RATE_LIMIT_SLEEP)
            sleep(RATE_LIMIT_SLEEP)
            return self._get(path)
        response.raise_for_status()
        return response.json()

    def _post(self, path: str, files: dict[str, tuple[str, bytes]]) -> Any:
        url = f"{BASE_URL}{path}"
        response = self.client.post(url, headers=self.headers, files=files)
        if response.status_code == 429:
            logger.warning("VT rate limit reached; sleeping %s sec", RATE_LIMIT_SLEEP)
            sleep(RATE_LIMIT_SLEEP)
            return self._post(path, files)
        response.raise_for_status()
        return response.json()

    # Public helpers --------------------------------------------------

    def get_file_report(self, sha256: str) -> Optional[dict[str, Any]]:
        """Return VT file analysis if exists, else None."""
        try:
            res = self._get(f"/files/{sha256}")
            return res
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code == 404:
                return None
            raise

    def upload_file(self, filename: str, data: bytes) -> str:
        """Upload file for analysis; returns analysis ID."""
        res = self._post("/files", {"file": (filename, data)})
        return res["data"]["id"]

    def get_analysis_report(self, analysis_id: str) -> dict[str, Any]:
        return self._get(f"/analyses/{analysis_id}")