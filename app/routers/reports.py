from fastapi import APIRouter, Depends, HTTPException, Response
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session
from io import BytesIO
from datetime import datetime, timedelta
import json
from typing import Optional, List

from app.database import get_db
from app.models import FileAnalysis, UserFeedback, SystemMetrics
from app.services.report_generator import ReportGenerator

router = APIRouter()
report_generator = ReportGenerator()

@router.get("/analysis/{analysis_id}")
async def get_detailed_report(analysis_id: int, db: Session = Depends(get_db)):
    """Get detailed analysis report"""
    
    analysis = db.query(FileAnalysis).filter(FileAnalysis.id == analysis_id).first()
    if not analysis:
        raise HTTPException(status_code=404, detail="Analysis not found")
    
    # Get associated feedback
    feedback = db.query(UserFeedback).filter(
        UserFeedback.analysis_id == analysis_id
    ).all()
    
    return {
        "analysis_id": analysis.id,
        "file_info": {
            "filename": analysis.filename,
            "file_hash": analysis.file_hash,
            "file_size": analysis.file_size,
            "file_type": analysis.file_type,
            "upload_time": analysis.upload_time
        },
        "threat_assessment": {
            "is_malicious": analysis.is_malicious,
            "threat_level": analysis.threat_level,
            "confidence_score": analysis.confidence_score,
            "summary": analysis.analysis_summary
        },
        "detailed_analysis": analysis.detailed_results,
        "api_results": {
            "virustotal": analysis.virustotal_results,
            "hybrid_analysis": analysis.hybrid_analysis_results
        },
        "ml_analysis": analysis.ml_analysis_results,
        "feedback": [
            {
                "type": f.feedback_type,
                "comment": f.user_comment,
                "submitted_at": f.submitted_at
            }
            for f in feedback
        ],
        "recommendations": generate_recommendations(analysis),
        "next_steps": generate_next_steps(analysis)
    }

@router.get("/analysis/{analysis_id}/pdf")
async def download_pdf_report(analysis_id: int, db: Session = Depends(get_db)):
    """Download PDF report for analysis"""
    
    analysis = db.query(FileAnalysis).filter(FileAnalysis.id == analysis_id).first()
    if not analysis:
        raise HTTPException(status_code=404, detail="Analysis not found")
    
    # Generate PDF report
    pdf_buffer = await report_generator.generate_pdf_report(analysis)
    
    return StreamingResponse(
        BytesIO(pdf_buffer),
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename=analysis_report_{analysis_id}.pdf"}
    )

@router.get("/summary")
async def get_system_summary(
    days: int = 7,
    db: Session = Depends(get_db)
):
    """Get system summary report"""
    
    end_date = datetime.utcnow()
    start_date = end_date - timedelta(days=days)
    
    # Get analysis statistics
    total_analyses = db.query(FileAnalysis).filter(
        FileAnalysis.upload_time >= start_date
    ).count()
    
    malicious_files = db.query(FileAnalysis).filter(
        FileAnalysis.upload_time >= start_date,
        FileAnalysis.is_malicious == True
    ).count()
    
    # Threat level breakdown
    threat_levels = db.query(FileAnalysis.threat_level, db.func.count(FileAnalysis.id)).filter(
        FileAnalysis.upload_time >= start_date
    ).group_by(FileAnalysis.threat_level).all()
    
    # File type breakdown
    file_types = db.query(FileAnalysis.file_type, db.func.count(FileAnalysis.id)).filter(
        FileAnalysis.upload_time >= start_date
    ).group_by(FileAnalysis.file_type).all()
    
    # Average confidence score
    avg_confidence = db.query(db.func.avg(FileAnalysis.confidence_score)).filter(
        FileAnalysis.upload_time >= start_date
    ).scalar() or 0
    
    return {
        "period": {
            "start_date": start_date,
            "end_date": end_date,
            "days": days
        },
        "statistics": {
            "total_analyses": total_analyses,
            "malicious_files": malicious_files,
            "clean_files": total_analyses - malicious_files,
            "malicious_rate": malicious_files / total_analyses if total_analyses > 0 else 0,
            "average_confidence": round(avg_confidence, 3)
        },
        "threat_levels": dict(threat_levels),
        "file_types": dict(file_types),
        "trends": await calculate_trends(start_date, end_date, db)
    }

async def calculate_trends(start_date: datetime, end_date: datetime, db: Session):
    """Calculate trends over the specified period"""
    
    # Daily analysis counts
    daily_analyses = db.query(
        db.func.date(FileAnalysis.upload_time).label('date'),
        db.func.count(FileAnalysis.id).label('count')
    ).filter(
        FileAnalysis.upload_time >= start_date,
        FileAnalysis.upload_time <= end_date
    ).group_by(db.func.date(FileAnalysis.upload_time)).all()
    
    # Daily malicious file counts
    daily_malicious = db.query(
        db.func.date(FileAnalysis.upload_time).label('date'),
        db.func.count(FileAnalysis.id).label('count')
    ).filter(
        FileAnalysis.upload_time >= start_date,
        FileAnalysis.upload_time <= end_date,
        FileAnalysis.is_malicious == True
    ).group_by(db.func.date(FileAnalysis.upload_time)).all()
    
    return {
        "daily_analyses": [{"date": str(date), "count": count} for date, count in daily_analyses],
        "daily_malicious": [{"date": str(date), "count": count} for date, count in daily_malicious]
    }

def generate_recommendations(analysis: FileAnalysis) -> List[str]:
    """Generate security recommendations based on analysis"""
    recommendations = []
    
    if analysis.is_malicious:
        recommendations.extend([
            "🚨 IMMEDIATE ACTION REQUIRED: This file contains malicious content",
            "🗑️ Delete the file immediately if it's still on your system",
            "🔍 Run a full system scan with updated antivirus software",
            "🔒 Change any passwords that might have been exposed",
            "📱 Check for suspicious network activity or unauthorized access"
        ])
        
        if analysis.threat_level == "CRITICAL":
            recommendations.extend([
                "⚠️ CRITICAL THREAT: Disconnect from the internet immediately",
                "🖥️ Consider rebuilding the affected system from clean backups",
                "📞 Contact your IT security team or cybersecurity professional"
            ])
    else:
        recommendations.extend([
            "✅ File appears to be safe based on current analysis",
            "🔄 Keep your antivirus software updated for ongoing protection",
            "🛡️ Continue following safe file handling practices"
        ])
    
    # Add file-type specific recommendations
    if analysis.file_type in ['.exe', '.bat', '.cmd', '.scr']:
        recommendations.append("⚠️ Be extra cautious with executable files - only run if from trusted sources")
    elif analysis.file_type in ['.pdf', '.docx', '.doc']:
        recommendations.append("📄 Office documents can contain macros - disable if not needed")
    elif analysis.file_type in ['.zip', '.rar', '.7z']:
        recommendations.append("📦 Scan extracted contents before opening any files")
    
    return recommendations

def generate_next_steps(analysis: FileAnalysis) -> List[str]:
    """Generate next steps based on analysis results"""
    next_steps = []
    
    if analysis.is_malicious:
        next_steps.extend([
            "1. Isolate the affected system from the network",
            "2. Document the incident (when, how, what)",
            "3. Perform forensic analysis if required",
            "4. Update security policies and training",
            "5. Monitor for signs of lateral movement"
        ])
    else:
        next_steps.extend([
            "1. File is safe to use based on current analysis",
            "2. Consider submitting to additional scanning services for verification",
            "3. Monitor system behavior after file usage",
            "4. Report any suspicious activity if it occurs later"
        ])
    
    # Always add general next steps
    next_steps.extend([
        "5. Review and update cybersecurity training",
        "6. Ensure backup systems are functioning properly",
        "7. Consider implementing additional security controls"
    ])
    
    return next_steps