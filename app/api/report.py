from fastapi import APIRouter, HTTPException, Response

from app.services import analyzer, reporting

router = APIRouter()


@router.get("/report/{job_id}")
def report_json(job_id: str):
    job = analyzer.get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    return job


@router.get("/report/{job_id}/html", response_class=Response)
def report_html(job_id: str):
    job = analyzer.get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    html = reporting.render_html(job)
    return Response(content=html, media_type="text/html")