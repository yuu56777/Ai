import json
from pathlib import Path
from datetime import datetime
from typing import Literal

from fastapi import APIRouter
from pydantic import BaseModel, Field

# Where to store feedback JSONL
FEEDBACK_STORE = Path("/tmp/analyzer_feedback.jsonl")

router = APIRouter()


class FeedbackIn(BaseModel):
    job_id: str = Field(..., description="ID returned when file uploaded")
    user_verdict: Literal["false_positive", "false_negative", "correct"]
    comments: str | None = None


def _write_feedback(entry: dict) -> None:
    with FEEDBACK_STORE.open("a") as fp:
        fp.write(json.dumps(entry) + "\n")


@router.post("/feedback")
async def submit_feedback(body: FeedbackIn):
    entry = body.dict()
    entry["timestamp"] = datetime.utcnow().isoformat()
    _write_feedback(entry)
    return {"status": "accepted"}