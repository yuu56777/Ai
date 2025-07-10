from sqlalchemy import Column, Integer, String, Text, DateTime, Float, Boolean, JSON, ForeignKey
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from app.database import Base

class FileAnalysis(Base):
    __tablename__ = "file_analyses"
    
    id = Column(Integer, primary_key=True, index=True)
    filename = Column(String, nullable=False)
    file_hash = Column(String, unique=True, index=True)
    file_size = Column(Integer)
    file_type = Column(String)
    upload_time = Column(DateTime(timezone=True), server_default=func.now())
    
    # Analysis results
    is_malicious = Column(Boolean, default=False)
    threat_level = Column(String)  # LOW, MEDIUM, HIGH, CRITICAL
    confidence_score = Column(Float)
    analysis_summary = Column(Text)
    detailed_results = Column(JSON)
    
    # API results
    virustotal_results = Column(JSON)
    hybrid_analysis_results = Column(JSON)
    ml_analysis_results = Column(JSON)
    
    # Relationships
    feedback_entries = relationship("UserFeedback", back_populates="analysis")

class UserFeedback(Base):
    __tablename__ = "user_feedback"
    
    id = Column(Integer, primary_key=True, index=True)
    analysis_id = Column(Integer, ForeignKey("file_analyses.id"))
    feedback_type = Column(String)  # FALSE_POSITIVE, FALSE_NEGATIVE, CORRECT
    user_comment = Column(Text)
    submitted_at = Column(DateTime(timezone=True), server_default=func.now())
    
    # Relationships
    analysis = relationship("FileAnalysis", back_populates="feedback_entries")

class ThreatIntelligence(Base):
    __tablename__ = "threat_intelligence"
    
    id = Column(Integer, primary_key=True, index=True)
    indicator_type = Column(String)  # hash, domain, ip, url
    indicator_value = Column(String, index=True)
    threat_type = Column(String)
    severity = Column(String)
    description = Column(Text)
    source = Column(String)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    last_seen = Column(DateTime(timezone=True))

class WorkshopProgress(Base):
    __tablename__ = "workshop_progress"
    
    id = Column(Integer, primary_key=True, index=True)
    user_session = Column(String, index=True)
    module_name = Column(String)
    completed = Column(Boolean, default=False)
    completion_time = Column(DateTime(timezone=True))
    score = Column(Float)
    
class SystemMetrics(Base):
    __tablename__ = "system_metrics"
    
    id = Column(Integer, primary_key=True, index=True)
    metric_name = Column(String)
    metric_value = Column(Float)
    recorded_at = Column(DateTime(timezone=True), server_default=func.now())
    metadata = Column(JSON)