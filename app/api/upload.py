from pathlib import Path
import hashlib

from fastapi import APIRouter, BackgroundTasks, File, HTTPException, UploadFile

from app.services import analyzer
from app.core import config

router = APIRouter()


@router.post("/upload")
async def upload_file(
    file: UploadFile = File(...), background_tasks: BackgroundTasks = BackgroundTasks()
):
    """Receive a file, persist it temporarily, and launch background analysis."""
    if not file.filename:
        raise HTTPException(status_code=400, detail="Filename not provided")

    # Validate file extension
    ext = Path(file.filename).suffix.lower()
    if ext not in config.ALLOWED_EXT:
        raise HTTPException(status_code=400, detail=f"Extension '{ext}' not allowed")

    # Read the entire file into memory (fine for workshop-sized files)
    data = await file.read()

    if len(data) > config.MAX_FILE_SIZE:
        mb = config.MAX_FILE_SIZE / (1024 * 1024)
        raise HTTPException(status_code=400, detail=f"Max file size exceeded ({mb} MB)")

    # Compute hash & build deterministic filename
    sha256 = hashlib.sha256(data).hexdigest()
    file_path = config.TMP_DIR / f"{sha256}_{file.filename}"

    with file_path.open("wb") as dst:
        dst.write(data)

    # Register a new analysis job and launch it asynchronously
    job_id = analyzer.create_job(file_path)
    background_tasks.add_task(analyzer.run_analysis, job_id, file_path)

    return {"job_id": job_id, "status": "processing"}


@router.get("/report/{job_id}")
def get_report(job_id: str):
    """Retrieve analysis results for a given job ID."""
    job = analyzer.get_job(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Job not found")
    return job