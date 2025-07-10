from fastapi import APIRouter, File, UploadFile, HTTPException, Depends, BackgroundTasks
from sqlalchemy.orm import Session
from typing import List
import hashlib
import os
import aiofiles
from datetime import datetime

from app.database import get_db
from app.models import FileAnalysis
from app.core.config import settings
from app.services.file_processor import FileProcessor
from app.services.api_integrator import APIIntegrator
from app.services.ml_detector import MLFraudDetector
from app.schemas import AnalysisResponse, FileUploadResponse

router = APIRouter()

file_processor = FileProcessor()
api_integrator = APIIntegrator()
ml_detector = MLFraudDetector()

@router.post("/upload", response_model=FileUploadResponse)
async def upload_file(
    file: UploadFile = File(...),
    background_tasks: BackgroundTasks = BackgroundTasks(),
    db: Session = Depends(get_db)
):
    """Upload a file for analysis"""
    
    # Validate file
    if not file.filename:
        raise HTTPException(status_code=400, detail="No file selected")
    
    # Check file extension
    file_ext = os.path.splitext(file.filename)[1].lower()
    if file_ext not in settings.allowed_extensions:
        raise HTTPException(
            status_code=400, 
            detail=f"File type not allowed. Allowed types: {', '.join(settings.allowed_extensions)}"
        )
    
    # Read file content
    content = await file.read()
    
    # Check file size
    if len(content) > settings.max_file_size:
        raise HTTPException(
            status_code=413, 
            detail=f"File too large. Maximum size: {settings.max_file_size / 1024 / 1024} MB"
        )
    
    # Calculate file hash
    file_hash = hashlib.sha256(content).hexdigest()
    
    # Check if file already exists in database
    existing_analysis = db.query(FileAnalysis).filter(FileAnalysis.file_hash == file_hash).first()
    if existing_analysis:
        return FileUploadResponse(
            analysis_id=existing_analysis.id,
            filename=file.filename,
            file_hash=file_hash,
            status="exists",
            message="File already analyzed. Returning existing results."
        )
    
    # Save file
    file_path = os.path.join(settings.upload_dir, f"{file_hash}_{file.filename}")
    async with aiofiles.open(file_path, 'wb') as f:
        await f.write(content)
    
    # Create database entry
    analysis = FileAnalysis(
        filename=file.filename,
        file_hash=file_hash,
        file_size=len(content),
        file_type=file_ext,
        upload_time=datetime.utcnow()
    )
    db.add(analysis)
    db.commit()
    db.refresh(analysis)
    
    # Start background analysis
    background_tasks.add_task(analyze_file, analysis.id, file_path, db)
    
    return FileUploadResponse(
        analysis_id=analysis.id,
        filename=file.filename,
        file_hash=file_hash,
        status="uploaded",
        message="File uploaded successfully. Analysis in progress."
    )

async def analyze_file(analysis_id: int, file_path: str, db: Session):
    """Background task to analyze uploaded file"""
    try:
        analysis = db.query(FileAnalysis).filter(FileAnalysis.id == analysis_id).first()
        if not analysis:
            return
        
        # File processing
        file_info = await file_processor.process_file(file_path)
        
        # API integrations
        api_results = await api_integrator.analyze_file(file_path, analysis.file_hash)
        
        # ML analysis
        ml_results = await ml_detector.analyze_file(file_path, file_info)
        
        # Combine results and determine threat level
        threat_assessment = combine_analysis_results(file_info, api_results, ml_results)
        
        # Update database
        analysis.is_malicious = threat_assessment['is_malicious']
        analysis.threat_level = threat_assessment['threat_level']
        analysis.confidence_score = threat_assessment['confidence_score']
        analysis.analysis_summary = threat_assessment['summary']
        analysis.detailed_results = threat_assessment['details']
        analysis.virustotal_results = api_results.get('virustotal', {})
        analysis.hybrid_analysis_results = api_results.get('hybrid_analysis', {})
        analysis.ml_analysis_results = ml_results
        
        db.commit()
        
        # Clean up temporary file
        if os.path.exists(file_path):
            os.remove(file_path)
            
    except Exception as e:
        # Log error and update analysis with error status
        print(f"Analysis error for {analysis_id}: {str(e)}")
        if analysis:
            analysis.analysis_summary = f"Analysis failed: {str(e)}"
            db.commit()

def combine_analysis_results(file_info: dict, api_results: dict, ml_results: dict) -> dict:
    """Combine results from different analysis methods"""
    
    is_malicious = False
    threat_level = "LOW"
    confidence_scores = []
    findings = []
    
    # Analyze API results
    vt_results = api_results.get('virustotal', {})
    if vt_results.get('malicious_count', 0) > 0:
        is_malicious = True
        threat_level = "HIGH"
        confidence_scores.append(0.9)
        findings.append(f"VirusTotal detected {vt_results.get('malicious_count')} threats")
    
    # Analyze ML results
    ml_confidence = ml_results.get('confidence', 0)
    if ml_confidence > 0.7:
        is_malicious = True
        if ml_confidence > 0.9:
            threat_level = "CRITICAL"
        elif threat_level == "LOW":
            threat_level = "MEDIUM"
        confidence_scores.append(ml_confidence)
        findings.append(f"ML model detected suspicious patterns (confidence: {ml_confidence:.2f})")
    
    # File type analysis
    if file_info.get('is_executable', False):
        confidence_scores.append(0.3)  # Executables are inherently riskier
        findings.append("File is executable")
    
    # Calculate overall confidence
    overall_confidence = max(confidence_scores) if confidence_scores else 0.1
    
    # Generate summary
    if is_malicious:
        summary = f"THREAT DETECTED - {threat_level} risk level. " + "; ".join(findings)
    else:
        summary = "No threats detected. File appears to be safe."
    
    return {
        'is_malicious': is_malicious,
        'threat_level': threat_level,
        'confidence_score': overall_confidence,
        'summary': summary,
        'details': {
            'file_info': file_info,
            'api_results': api_results,
            'ml_results': ml_results,
            'findings': findings
        }
    }

@router.get("/status/{analysis_id}", response_model=AnalysisResponse)
async def get_analysis_status(analysis_id: int, db: Session = Depends(get_db)):
    """Get analysis status and results"""
    analysis = db.query(FileAnalysis).filter(FileAnalysis.id == analysis_id).first()
    if not analysis:
        raise HTTPException(status_code=404, detail="Analysis not found")
    
    # Determine status
    if analysis.analysis_summary is None:
        status = "processing"
    elif "failed" in analysis.analysis_summary.lower():
        status = "failed"
    else:
        status = "completed"
    
    return AnalysisResponse(
        analysis_id=analysis.id,
        filename=analysis.filename,
        file_hash=analysis.file_hash,
        status=status,
        is_malicious=analysis.is_malicious,
        threat_level=analysis.threat_level,
        confidence_score=analysis.confidence_score,
        summary=analysis.analysis_summary,
        detailed_results=analysis.detailed_results,
        upload_time=analysis.upload_time
    )

@router.get("/history")
async def get_analysis_history(limit: int = 50, db: Session = Depends(get_db)):
    """Get recent analysis history"""
    analyses = db.query(FileAnalysis).order_by(FileAnalysis.upload_time.desc()).limit(limit).all()
    
    return [
        {
            "analysis_id": analysis.id,
            "filename": analysis.filename,
            "threat_level": analysis.threat_level,
            "is_malicious": analysis.is_malicious,
            "upload_time": analysis.upload_time,
            "confidence_score": analysis.confidence_score
        }
        for analysis in analyses
    ]