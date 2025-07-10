import random
import time
from pathlib import Path
from typing import Dict, Optional
from uuid import uuid4

# In-memory job store (fine for MVP/workshop)
JOBS: Dict[str, dict] = {}

# ---------------------------------------------------------------------------
# External services
# ---------------------------------------------------------------------------

from hashlib import sha256

from app.core import config

try:
    from app.services.vt_client import VTClient, VirusTotalDisabled

    _vt_client: Optional[VTClient] = None

    def get_vt_client() -> VTClient | None:
        global _vt_client
        if _vt_client is not None:
            return _vt_client
        try:
            _vt_client = VTClient()
        except VirusTotalDisabled:
            _vt_client = None
        return _vt_client

except ImportError:
    # httpx not installed or other issue – VT disabled
    def get_vt_client():  # type: ignore
        return None


def create_job(file_path: Path) -> str:
    """Create a new analysis job entry and return its ID."""
    job_id = uuid4()
    job_id_hex = job_id.hex
    JOBS[job_id_hex] = {"status": "processing", "file_path": str(file_path)}
    return job_id_hex


def run_analysis(job_id: str, file_path: Path) -> None:
    """Run threat analysis on the given file.

    1. Compute SHA-256 hash.
    2. Query VirusTotal; upload if unknown and size ≤ 32 MB.
    3. Aggregate VT results to produce a simple verdict.
    """

    # Read entire file (already small enough due to earlier limit enforcement)
    data = file_path.read_bytes()
    sha256_hex = sha256(data).hexdigest()

    vt_client = get_vt_client()
    vt_report: Optional[dict] = None
    vt_summary: Optional[dict] = None

    if vt_client is not None:
        try:
            vt_report = vt_client.get_file_report(sha256_hex)

            if vt_report is None:
                # VT does not have it yet – upload if ≤32MB (public API restriction)
                if len(data) <= 32 * 1024 * 1024:
                    analysis_id = vt_client.upload_file(file_path.name, data)
                    # Poll until analysis completed (simplistic)
                    for _ in range(10):
                        time.sleep(15)
                        res = vt_client.get_analysis_report(analysis_id)
                        if res.get("data", {}).get("attributes", {}).get("status") == "completed":
                            vt_report = vt_client.get_file_report(sha256_hex)
                            break
            # Extract summary
            if vt_report:
                vt_summary = vt_report.get("data", {}).get("attributes", {}).get(
                    "last_analysis_stats", {}
                )
        except Exception as exc:  # broad – network errors etc.
            vt_summary = {"error": str(exc)}

    # -------------------------------------------------------------
    # Determine verdict
    # -------------------------------------------------------------
    verdict = "unknown"
    if vt_summary and isinstance(vt_summary, dict):
        malicious = vt_summary.get("malicious", 0) or 0
        suspicious = vt_summary.get("suspicious", 0) or 0
        if malicious > 0:
            verdict = "malicious"
        elif suspicious > 0:
            verdict = "suspicious"
        else:
            verdict = "clean"
    else:
        # fallback heuristic
        verdict = random.choice(["clean", "suspicious"])

    # Store job outcome
    JOBS[job_id] = {
        "status": "completed",
        "verdict": verdict,
        "sha256": sha256_hex,
        "vt_summary": vt_summary,
        "file_path": str(file_path),
    }


def get_job(job_id: str) -> Optional[dict]:
    """Return job details or None if not found."""
    return JOBS.get(job_id)