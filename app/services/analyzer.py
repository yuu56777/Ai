import random
import time
from pathlib import Path
from typing import Dict, Optional
from uuid import uuid4

# In-memory job store (fine for MVP/workshop)
JOBS: Dict[str, dict] = {}


def create_job(file_path: Path) -> str:
    """Create a new analysis job entry and return its ID."""
    job_id = uuid4()
    job_id_hex = job_id.hex
    JOBS[job_id_hex] = {"status": "processing", "file_path": str(file_path)}
    return job_id_hex


def run_analysis(job_id: str, file_path: Path) -> None:
    """Very naive placeholder analysis – replace with real scanners later."""
    # Simulate a time-consuming task
    time.sleep(3)
    verdict = random.choice(["clean", "suspicious", "malicious"])
    JOBS[job_id] = {
        "status": "completed",
        "verdict": verdict,
        "file_path": str(file_path),
    }


def get_job(job_id: str) -> Optional[dict]:
    """Return job details or None if not found."""
    return JOBS.get(job_id)