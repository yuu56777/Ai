from fastapi import FastAPI, File, UploadFile, HTTPException, Depends, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, JSONResponse
from sqlalchemy.orm import Session
import os
import logging
from typing import List
import asyncio

from app.database import engine, get_db
from app.models import Base
from app.routers import analysis, workshop, feedback, reports
from app.core.config import settings
from app.services.file_processor import FileProcessor
from app.services.ml_detector import MLFraudDetector

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Create tables
Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="AI Cybersecurity Fraud Detection System",
    description="Advanced AI-driven tool for detecting fraudulent activities through file analysis",
    version="1.0.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc"
)

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],  # React development server
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(analysis.router, prefix="/api/analysis", tags=["analysis"])
app.include_router(workshop.router, prefix="/api/workshop", tags=["workshop"])
app.include_router(feedback.router, prefix="/api/feedback", tags=["feedback"])
app.include_router(reports.router, prefix="/api/reports", tags=["reports"])

# Initialize services
file_processor = FileProcessor()
ml_detector = MLFraudDetector()

@app.on_event("startup")
async def startup_event():
    """Initialize services on startup"""
    logger.info("Starting AI Cybersecurity Fraud Detection System")
    await ml_detector.initialize()
    logger.info("ML Fraud Detector initialized")

@app.get("/", response_class=HTMLResponse)
async def root():
    """Serve the main application page"""
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <title>AI Cybersecurity Fraud Detection System</title>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <style>
            body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }
            .container { max-width: 800px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }
            .header { text-align: center; margin-bottom: 30px; }
            .upload-area { border: 2px dashed #007bff; padding: 30px; text-align: center; border-radius: 10px; margin: 20px 0; }
            .btn { background: #007bff; color: white; padding: 12px 24px; border: none; border-radius: 5px; cursor: pointer; font-size: 16px; }
            .btn:hover { background: #0056b3; }
            .features { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; margin-top: 30px; }
            .feature { padding: 20px; background: #f8f9fa; border-radius: 8px; }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>🛡️ AI Cybersecurity Fraud Detection System</h1>
                <p>Advanced AI-driven tool for detecting fraudulent activities through file analysis</p>
            </div>
            
            <div class="upload-area">
                <h3>Upload File for Analysis</h3>
                <p>Drag and drop your file here or click to browse</p>
                <input type="file" id="fileInput" style="display: none;" multiple>
                <button class="btn" onclick="document.getElementById('fileInput').click()">Choose Files</button>
            </div>
            
            <div class="features">
                <div class="feature">
                    <h4>🔍 Malware Detection</h4>
                    <p>Advanced scanning using multiple threat intelligence APIs</p>
                </div>
                <div class="feature">
                    <h4>🎣 Phishing Analysis</h4>
                    <p>Identify suspicious patterns and phishing indicators</p>
                </div>
                <div class="feature">
                    <h4>🤖 AI-Powered Analysis</h4>
                    <p>Machine learning models for fraud pattern recognition</p>
                </div>
                <div class="feature">
                    <h4>📊 Detailed Reports</h4>
                    <p>Comprehensive analysis reports with actionable insights</p>
                </div>
            </div>
            
            <div style="text-align: center; margin-top: 30px;">
                <a href="/api/docs" class="btn">API Documentation</a>
                <a href="/api/workshop" class="btn" style="margin-left: 10px;">Security Workshop</a>
            </div>
        </div>
        
        <script>
            document.getElementById('fileInput').addEventListener('change', function(e) {
                const files = e.target.files;
                if (files.length > 0) {
                    alert(`Selected ${files.length} file(s) for analysis. This will redirect to the React app for full functionality.`);
                    // In production, this would redirect to the React app
                    window.location.href = '/api/docs';
                }
            });
        </script>
    </body>
    </html>
    """

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy", "service": "AI Cybersecurity Fraud Detection System"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)