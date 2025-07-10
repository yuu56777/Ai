from pydantic import BaseModel
from typing import Optional, List, Dict, Any
from datetime import datetime
from enum import Enum

class FeedbackType(str, Enum):
    FALSE_POSITIVE = "FALSE_POSITIVE"
    FALSE_NEGATIVE = "FALSE_NEGATIVE"
    CORRECT = "CORRECT"

class ThreatLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

class FileUploadResponse(BaseModel):
    analysis_id: int
    filename: str
    file_hash: str
    status: str
    message: str

class AnalysisResponse(BaseModel):
    analysis_id: int
    filename: str
    file_hash: str
    status: str
    is_malicious: Optional[bool] = None
    threat_level: Optional[str] = None
    confidence_score: Optional[float] = None
    summary: Optional[str] = None
    detailed_results: Optional[Dict[str, Any]] = None
    upload_time: datetime

class FeedbackSubmission(BaseModel):
    analysis_id: int
    feedback_type: FeedbackType
    user_comment: Optional[str] = None

class FeedbackResponse(BaseModel):
    feedback_id: int
    status: str
    message: str

class WorkshopModule(BaseModel):
    title: str
    description: str
    duration: str
    content: Dict[str, str]
    quiz: List[Dict[str, Any]]

class WorkshopProgressResponse(BaseModel):
    module_id: str
    title: str
    completed: bool
    score: Optional[float] = None
    completion_time: Optional[datetime] = None

class APIStatus(BaseModel):
    service: str
    status: str
    response_time: Optional[float] = None
    last_check: datetime

class SystemHealth(BaseModel):
    overall_status: str
    components: List[APIStatus]
    uptime: str
    version: str