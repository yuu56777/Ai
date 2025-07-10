from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import Optional
from datetime import datetime

from app.database import get_db
from app.models import UserFeedback, FileAnalysis
from app.schemas import FeedbackSubmission, FeedbackResponse

router = APIRouter()

@router.post("/submit", response_model=FeedbackResponse)
async def submit_feedback(
    feedback: FeedbackSubmission,
    db: Session = Depends(get_db)
):
    """Submit user feedback on analysis results"""
    
    # Verify analysis exists
    analysis = db.query(FileAnalysis).filter(FileAnalysis.id == feedback.analysis_id).first()
    if not analysis:
        raise HTTPException(status_code=404, detail="Analysis not found")
    
    # Create feedback entry
    feedback_entry = UserFeedback(
        analysis_id=feedback.analysis_id,
        feedback_type=feedback.feedback_type,
        user_comment=feedback.user_comment,
        submitted_at=datetime.utcnow()
    )
    
    db.add(feedback_entry)
    db.commit()
    db.refresh(feedback_entry)
    
    # Update system learning based on feedback
    await process_feedback_for_learning(feedback_entry, analysis, db)
    
    return FeedbackResponse(
        feedback_id=feedback_entry.id,
        status="success",
        message="Thank you for your feedback! This helps improve our detection accuracy."
    )

async def process_feedback_for_learning(feedback: UserFeedback, analysis: FileAnalysis, db: Session):
    """Process feedback to improve ML model"""
    try:
        # This would trigger model retraining in a production system
        # For now, we'll log the feedback for future use
        
        feedback_data = {
            "file_hash": analysis.file_hash,
            "original_prediction": analysis.is_malicious,
            "original_confidence": analysis.confidence_score,
            "feedback_type": feedback.feedback_type,
            "should_be_malicious": feedback.feedback_type == "FALSE_NEGATIVE",
            "should_be_clean": feedback.feedback_type == "FALSE_POSITIVE"
        }
        
        # In a production system, this would:
        # 1. Add to training dataset
        # 2. Trigger model retraining
        # 3. Update model weights
        # 4. Validate new model performance
        
        print(f"Feedback logged for learning: {feedback_data}")
        
    except Exception as e:
        print(f"Error processing feedback for learning: {str(e)}")

@router.get("/analysis/{analysis_id}")
async def get_analysis_feedback(analysis_id: int, db: Session = Depends(get_db)):
    """Get all feedback for a specific analysis"""
    
    feedback_entries = db.query(UserFeedback).filter(
        UserFeedback.analysis_id == analysis_id
    ).order_by(UserFeedback.submitted_at.desc()).all()
    
    return [
        {
            "feedback_id": entry.id,
            "feedback_type": entry.feedback_type,
            "user_comment": entry.user_comment,
            "submitted_at": entry.submitted_at
        }
        for entry in feedback_entries
    ]

@router.get("/stats")
async def get_feedback_stats(db: Session = Depends(get_db)):
    """Get feedback statistics for system improvement"""
    
    total_feedback = db.query(UserFeedback).count()
    false_positives = db.query(UserFeedback).filter(
        UserFeedback.feedback_type == "FALSE_POSITIVE"
    ).count()
    false_negatives = db.query(UserFeedback).filter(
        UserFeedback.feedback_type == "FALSE_NEGATIVE"
    ).count()
    correct_predictions = db.query(UserFeedback).filter(
        UserFeedback.feedback_type == "CORRECT"
    ).count()
    
    accuracy = correct_predictions / total_feedback if total_feedback > 0 else 0
    false_positive_rate = false_positives / total_feedback if total_feedback > 0 else 0
    false_negative_rate = false_negatives / total_feedback if total_feedback > 0 else 0
    
    return {
        "total_feedback": total_feedback,
        "accuracy": accuracy,
        "false_positive_rate": false_positive_rate,
        "false_negative_rate": false_negative_rate,
        "breakdown": {
            "correct": correct_predictions,
            "false_positives": false_positives,
            "false_negatives": false_negatives
        }
    }