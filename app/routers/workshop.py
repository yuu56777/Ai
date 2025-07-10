from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List, Dict
from datetime import datetime

from app.database import get_db
from app.models import WorkshopProgress
from app.schemas import WorkshopModule, WorkshopProgressResponse

router = APIRouter()

# Workshop modules data
WORKSHOP_MODULES = {
    "malware_basics": {
        "title": "Malware Detection Fundamentals",
        "description": "Learn the basics of malware detection and analysis",
        "duration": "15 minutes",
        "content": {
            "introduction": """
            # Malware Detection Fundamentals
            
            ## What is Malware?
            Malware (malicious software) is any software designed to harm, exploit, or otherwise compromise a computer system. Common types include:
            
            - **Viruses**: Replicate and spread to other files
            - **Trojans**: Disguise themselves as legitimate software
            - **Ransomware**: Encrypt files and demand payment
            - **Spyware**: Secretly monitor user activities
            - **Adware**: Display unwanted advertisements
            """,
            "detection_methods": """
            ## Detection Methods
            
            ### 1. Signature-Based Detection
            - Uses known malware signatures (hash values)
            - Fast and accurate for known threats
            - Cannot detect new, unknown malware
            
            ### 2. Heuristic Analysis
            - Analyzes behavior patterns
            - Can detect unknown malware
            - May produce false positives
            
            ### 3. Machine Learning
            - Uses AI to identify suspicious patterns
            - Adapts to new threats
            - Requires training data
            """,
            "best_practices": """
            ## Best Practices
            
            1. **Keep software updated**
            2. **Use reputable antivirus software**
            3. **Be cautious with email attachments**
            4. **Download software from official sources**
            5. **Regular system backups**
            6. **Network segmentation**
            """
        },
        "quiz": [
            {
                "question": "Which detection method can identify unknown malware?",
                "options": ["Signature-based", "Heuristic analysis", "Hash checking", "Whitelist filtering"],
                "correct": 1
            },
            {
                "question": "What type of malware encrypts files and demands payment?",
                "options": ["Virus", "Trojan", "Ransomware", "Spyware"],
                "correct": 2
            }
        ]
    },
    "phishing_awareness": {
        "title": "Phishing Attack Recognition",
        "description": "Identify and prevent phishing attacks",
        "duration": "20 minutes",
        "content": {
            "introduction": """
            # Phishing Attack Recognition
            
            ## What is Phishing?
            Phishing is a cybercrime where attackers impersonate legitimate organizations to steal sensitive information such as:
            - Login credentials
            - Credit card numbers
            - Personal identification information
            - Financial data
            """,
            "types": """
            ## Types of Phishing
            
            ### Email Phishing
            - Most common type
            - Mass emails to many targets
            - Generic messages
            
            ### Spear Phishing
            - Targeted attacks
            - Personalized messages
            - Research specific individuals
            
            ### Whaling
            - Targets high-profile individuals
            - CEOs, executives, politicians
            - High-value information
            
            ### Smishing
            - SMS-based phishing
            - Text message attacks
            - Mobile-focused
            """,
            "indicators": """
            ## Red Flags to Watch For
            
            1. **Urgent language** - "Act now!" "Limited time!"
            2. **Generic greetings** - "Dear Customer"
            3. **Suspicious sender** - Check email address carefully
            4. **Poor grammar/spelling** - Professional companies proofread
            5. **Suspicious links** - Hover to check destination
            6. **Unexpected attachments** - Don't open unless expected
            7. **Requests for sensitive info** - Legitimate companies don't ask via email
            """
        },
        "quiz": [
            {
                "question": "What is spear phishing?",
                "options": ["Mass email attacks", "Targeted personalized attacks", "SMS phishing", "Voice phishing"],
                "correct": 1
            },
            {
                "question": "Which is NOT a red flag for phishing emails?",
                "options": ["Urgent language", "Generic greeting", "Proper spelling", "Suspicious links"],
                "correct": 2
            }
        ]
    },
    "secure_file_handling": {
        "title": "Secure File Handling Practices",
        "description": "Best practices for handling and analyzing suspicious files",
        "duration": "25 minutes",
        "content": {
            "introduction": """
            # Secure File Handling Practices
            
            ## Why Secure File Handling Matters
            Files can contain hidden threats that activate when opened, downloaded, or executed. Proper handling prevents:
            - System compromise
            - Data theft
            - Network infections
            - Business disruption
            """,
            "isolation": """
            ## File Isolation Techniques
            
            ### Sandboxing
            - Isolated environment for testing
            - Contains potential threats
            - Allows safe analysis
            
            ### Virtual Machines
            - Separate operating system instance
            - Complete isolation from host
            - Can be reset if compromised
            
            ### Air-Gapped Systems
            - No network connectivity
            - Ultimate isolation
            - Used for highly sensitive analysis
            """,
            "analysis_tools": """
            ## File Analysis Tools
            
            ### Static Analysis
            - Examine without execution
            - Hash checking
            - Metadata analysis
            - String extraction
            
            ### Dynamic Analysis
            - Monitor behavior during execution
            - Network activity
            - File system changes
            - Registry modifications
            
            ### Hybrid Analysis
            - Combines static and dynamic
            - Comprehensive assessment
            - Better threat detection
            """
        },
        "quiz": [
            {
                "question": "What is sandboxing?",
                "options": ["File encryption", "Isolated testing environment", "Network monitoring", "Backup system"],
                "correct": 1
            },
            {
                "question": "Which analysis type examines files without executing them?",
                "options": ["Dynamic analysis", "Static analysis", "Hybrid analysis", "Behavioral analysis"],
                "correct": 1
            }
        ]
    }
}

@router.get("/modules")
async def get_workshop_modules():
    """Get all available workshop modules"""
    return {
        module_id: {
            "title": module["title"],
            "description": module["description"],
            "duration": module["duration"]
        }
        for module_id, module in WORKSHOP_MODULES.items()
    }

@router.get("/modules/{module_id}")
async def get_workshop_module(module_id: str):
    """Get specific workshop module content"""
    if module_id not in WORKSHOP_MODULES:
        raise HTTPException(status_code=404, detail="Module not found")
    
    return WORKSHOP_MODULES[module_id]

@router.post("/modules/{module_id}/progress")
async def update_progress(
    module_id: str,
    user_session: str,
    completed: bool = False,
    score: float = None,
    db: Session = Depends(get_db)
):
    """Update user progress for a module"""
    if module_id not in WORKSHOP_MODULES:
        raise HTTPException(status_code=404, detail="Module not found")
    
    # Check if progress already exists
    progress = db.query(WorkshopProgress).filter(
        WorkshopProgress.user_session == user_session,
        WorkshopProgress.module_name == module_id
    ).first()
    
    if progress:
        progress.completed = completed
        progress.score = score
        if completed:
            progress.completion_time = datetime.utcnow()
    else:
        progress = WorkshopProgress(
            user_session=user_session,
            module_name=module_id,
            completed=completed,
            score=score,
            completion_time=datetime.utcnow() if completed else None
        )
        db.add(progress)
    
    db.commit()
    db.refresh(progress)
    
    return {"status": "success", "progress_id": progress.id}

@router.get("/progress/{user_session}")
async def get_user_progress(user_session: str, db: Session = Depends(get_db)):
    """Get user's workshop progress"""
    progress_records = db.query(WorkshopProgress).filter(
        WorkshopProgress.user_session == user_session
    ).all()
    
    progress_map = {record.module_name: record for record in progress_records}
    
    result = []
    for module_id, module in WORKSHOP_MODULES.items():
        progress = progress_map.get(module_id)
        result.append({
            "module_id": module_id,
            "title": module["title"],
            "completed": progress.completed if progress else False,
            "score": progress.score if progress else None,
            "completion_time": progress.completion_time if progress else None
        })
    
    return result

@router.post("/modules/{module_id}/quiz")
async def submit_quiz(
    module_id: str,
    answers: List[int],
    user_session: str,
    db: Session = Depends(get_db)
):
    """Submit quiz answers and calculate score"""
    if module_id not in WORKSHOP_MODULES:
        raise HTTPException(status_code=404, detail="Module not found")
    
    module = WORKSHOP_MODULES[module_id]
    quiz = module.get("quiz", [])
    
    if len(answers) != len(quiz):
        raise HTTPException(status_code=400, detail="Answer count mismatch")
    
    correct_answers = 0
    total_questions = len(quiz)
    
    for i, answer in enumerate(answers):
        if answer == quiz[i]["correct"]:
            correct_answers += 1
    
    score = correct_answers / total_questions if total_questions > 0 else 0
    
    # Update progress
    await update_progress(module_id, user_session, True, score, db)
    
    return {
        "score": score,
        "correct_answers": correct_answers,
        "total_questions": total_questions,
        "passed": score >= 0.7,  # 70% passing grade
        "feedback": "Excellent work!" if score >= 0.9 else 
                   "Good job!" if score >= 0.7 else 
                   "Please review the material and try again."
    }