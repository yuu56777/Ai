#!/usr/bin/env python3
"""
AI Cybersecurity Fraud Detection System - Simple Demo Server
A lightweight demonstration version for quick deployment
"""

from fastapi import FastAPI, UploadFile, File, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
import uvicorn
import os
import hashlib
import json
from datetime import datetime
import aiofiles

# Initialize FastAPI app
app = FastAPI(
    title="AI Cybersecurity Fraud Detection System",
    description="An intelligent system for detecting malicious files and cybersecurity threats",
    version="1.0.0"
)

# Create necessary directories
os.makedirs("uploads", exist_ok=True)
os.makedirs("static", exist_ok=True)

# In-memory storage for demo
analysis_results = {}

@app.get("/", response_class=HTMLResponse)
async def home():
    """Main dashboard"""
    html_content = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>🛡️ AI Cybersecurity Fraud Detection System</title>
        <style>
            * { margin: 0; padding: 0; box-sizing: border-box; }
            body { 
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                min-height: 100vh;
                color: #333;
            }
            .container { max-width: 1200px; margin: 0 auto; padding: 20px; }
            .header { 
                background: white; 
                border-radius: 15px; 
                padding: 30px; 
                margin-bottom: 30px;
                box-shadow: 0 10px 30px rgba(0,0,0,0.1);
                text-align: center;
            }
            .header h1 { color: #2c3e50; margin-bottom: 10px; }
            .header p { color: #7f8c8d; font-size: 18px; }
            .card { 
                background: white; 
                border-radius: 15px; 
                padding: 25px; 
                margin-bottom: 20px;
                box-shadow: 0 5px 15px rgba(0,0,0,0.1);
            }
            .upload-area {
                border: 3px dashed #3498db;
                border-radius: 10px;
                padding: 40px;
                text-align: center;
                background: #f8f9fa;
                transition: all 0.3s ease;
                cursor: pointer;
            }
            .upload-area:hover { background: #e9ecef; border-color: #2980b9; }
            .btn { 
                background: #3498db; 
                color: white; 
                border: none; 
                padding: 12px 25px; 
                border-radius: 8px; 
                cursor: pointer;
                font-size: 16px;
                transition: background 0.3s ease;
            }
            .btn:hover { background: #2980b9; }
            .features { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; }
            .feature { padding: 20px; text-align: center; }
            .feature h3 { color: #2c3e50; margin-bottom: 10px; }
            .results { margin-top: 20px; }
            .threat-low { color: #27ae60; }
            .threat-medium { color: #f39c12; }
            .threat-high { color: #e74c3c; }
            .threat-critical { color: #8e44ad; }
            .status { padding: 10px; border-radius: 5px; margin: 10px 0; }
            .status.success { background: #d4edda; color: #155724; }
            .status.warning { background: #fff3cd; color: #856404; }
            .status.error { background: #f8d7da; color: #721c24; }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>🛡️ AI Cybersecurity Fraud Detection System</h1>
                <p>Advanced threat detection powered by artificial intelligence</p>
            </div>
            
            <div class="card">
                <h2>File Analysis</h2>
                <div class="upload-area" onclick="document.getElementById('fileInput').click()">
                    <h3>📁 Drop files here or click to upload</h3>
                    <p>Supported formats: PDF, DOCX, ZIP, EXE, Images, and more</p>
                    <input type="file" id="fileInput" style="display: none;" multiple onchange="uploadFiles()">
                </div>
                <div id="uploadStatus"></div>
                <div id="results" class="results"></div>
            </div>
            
            <div class="card">
                <h2>🎓 Cybersecurity Workshop</h2>
                <div class="features">
                    <div class="feature">
                        <h3>🦠 Malware Detection</h3>
                        <p>Learn to identify suspicious files and malicious software</p>
                        <button class="btn" onclick="startWorkshop('malware')">Start Module</button>
                    </div>
                    <div class="feature">
                        <h3>🎣 Phishing Awareness</h3>
                        <p>Understand social engineering and email threats</p>
                        <button class="btn" onclick="startWorkshop('phishing')">Start Module</button>
                    </div>
                    <div class="feature">
                        <h3>🔒 File Security</h3>
                        <p>Best practices for secure file handling</p>
                        <button class="btn" onclick="startWorkshop('security')">Start Module</button>
                    </div>
                </div>
            </div>
            
            <div class="card">
                <h2>📊 System Status</h2>
                <div class="status success">✅ AI Detection Engine: Active</div>
                <div class="status success">✅ Threat Intelligence: Connected</div>
                <div class="status success">✅ File Processing: Ready</div>
                <div class="status warning">⚠️ API Keys: Configure for full functionality</div>
            </div>
        </div>
        
        <script>
            async function uploadFiles() {
                const fileInput = document.getElementById('fileInput');
                const statusDiv = document.getElementById('uploadStatus');
                const resultsDiv = document.getElementById('results');
                
                if (fileInput.files.length === 0) return;
                
                statusDiv.innerHTML = '<div class="status">📤 Uploading and analyzing files...</div>';
                resultsDiv.innerHTML = '';
                
                for (let file of fileInput.files) {
                    const formData = new FormData();
                    formData.append('file', file);
                    
                    try {
                        const response = await fetch('/api/analyze', {
                            method: 'POST',
                            body: formData
                        });
                        
                        const result = await response.json();
                        displayResult(file.name, result);
                    } catch (error) {
                        console.error('Upload error:', error);
                        statusDiv.innerHTML = '<div class="status error">❌ Upload failed</div>';
                    }
                }
                
                statusDiv.innerHTML = '<div class="status success">✅ Analysis complete</div>';
            }
            
            function displayResult(filename, result) {
                const resultsDiv = document.getElementById('results');
                const threatClass = `threat-${result.threat_level.toLowerCase()}`;
                
                const resultHTML = `
                    <div class="card">
                        <h3>📄 ${filename}</h3>
                        <p><strong>Threat Level:</strong> <span class="${threatClass}">${result.threat_level}</span></p>
                        <p><strong>Confidence:</strong> ${(result.confidence_score * 100).toFixed(1)}%</p>
                        <p><strong>File Hash:</strong> ${result.file_hash}</p>
                        <p><strong>Summary:</strong> ${result.analysis_summary}</p>
                        ${result.recommendations ? `<p><strong>Recommendations:</strong> ${result.recommendations}</p>` : ''}
                    </div>
                `;
                
                resultsDiv.innerHTML += resultHTML;
            }
            
            function startWorkshop(type) {
                alert(`🎓 Starting ${type} workshop module! This feature is available in the full API version.`);
            }
        </script>
    </body>
    </html>
    """
    return HTMLResponse(content=html_content)

@app.post("/api/analyze")
async def analyze_file(file: UploadFile = File(...)):
    """Analyze uploaded file for threats"""
    try:
        # Read file content
        content = await file.read()
        
        # Calculate file hash
        file_hash = hashlib.sha256(content).hexdigest()
        
        # Simple threat detection logic (demo)
        threat_level = "LOW"
        confidence_score = 0.85
        analysis_summary = "File appears to be safe based on initial analysis."
        recommendations = []
        
        # Basic file type detection
        file_extension = os.path.splitext(file.filename)[1].lower()
        
        # Demo threat detection rules
        if file_extension in ['.exe', '.bat', '.cmd', '.scr', '.pif']:
            threat_level = "HIGH"
            confidence_score = 0.92
            analysis_summary = "Executable file detected. Exercise caution when running."
            recommendations.append("Scan with antivirus before execution")
            recommendations.append("Verify file source and authenticity")
            
        elif file_extension in ['.zip', '.rar', '.7z']:
            threat_level = "MEDIUM"
            confidence_score = 0.78
            analysis_summary = "Archive file detected. Contents should be inspected."
            recommendations.append("Extract and scan contents individually")
            
        elif len(content) > 50 * 1024 * 1024:  # Large files
            threat_level = "MEDIUM"
            confidence_score = 0.75
            analysis_summary = "Large file detected. May contain embedded threats."
            
        # Save analysis result
        result = {
            "file_id": file_hash[:16],
            "filename": file.filename,
            "file_hash": file_hash,
            "file_size": len(content),
            "file_type": file_extension,
            "threat_level": threat_level,
            "confidence_score": confidence_score,
            "analysis_summary": analysis_summary,
            "recommendations": "; ".join(recommendations) if recommendations else None,
            "timestamp": datetime.now().isoformat()
        }
        
        analysis_results[file_hash] = result
        
        # Save file for demo (optional)
        file_path = f"uploads/{file_hash[:16]}_{file.filename}"
        async with aiofiles.open(file_path, 'wb') as f:
            await f.write(content)
        
        return JSONResponse(content=result)
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")

@app.get("/api/workshop")
async def workshop_modules():
    """Get available workshop modules"""
    modules = [
        {
            "id": "malware_detection",
            "title": "Malware Detection Fundamentals",
            "description": "Learn to identify and analyze malicious software",
            "difficulty": "Beginner",
            "duration": "30 minutes"
        },
        {
            "id": "phishing_awareness",
            "title": "Phishing and Social Engineering",
            "description": "Understand common attack vectors and prevention",
            "difficulty": "Intermediate",
            "duration": "45 minutes"
        },
        {
            "id": "file_security",
            "title": "Secure File Handling",
            "description": "Best practices for file processing and storage",
            "difficulty": "Advanced",
            "duration": "60 minutes"
        }
    ]
    return JSONResponse(content={"modules": modules})

@app.get("/api/stats")
async def get_stats():
    """Get system statistics"""
    stats = {
        "total_files_analyzed": len(analysis_results),
        "threat_levels": {
            "LOW": sum(1 for r in analysis_results.values() if r["threat_level"] == "LOW"),
            "MEDIUM": sum(1 for r in analysis_results.values() if r["threat_level"] == "MEDIUM"),
            "HIGH": sum(1 for r in analysis_results.values() if r["threat_level"] == "HIGH"),
            "CRITICAL": sum(1 for r in analysis_results.values() if r["threat_level"] == "CRITICAL")
        },
        "recent_analyses": list(analysis_results.values())[-10:]
    }
    return JSONResponse(content=stats)

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return JSONResponse(content={
        "status": "healthy",
        "message": "AI Cybersecurity Fraud Detection System is running",
        "timestamp": datetime.now().isoformat()
    })

if __name__ == "__main__":
    print("🛡️  Starting AI Cybersecurity Fraud Detection System...")
    print("🌐 Access the web interface at: http://localhost:8000")
    print("📚 API Documentation available at: http://localhost:8000/docs")
    
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=8000,
        reload=False,
        log_level="info"
    )