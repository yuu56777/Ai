from pydantic_settings import BaseSettings
from typing import Optional
import os

class Settings(BaseSettings):
    # Database
    database_url: str = "sqlite:///./fraud_detection.db"
    
    # API Keys (to be set in environment variables)
    virustotal_api_key: Optional[str] = None
    hybrid_analysis_api_key: Optional[str] = None
    
    # File handling
    max_file_size: int = 100 * 1024 * 1024  # 100MB
    upload_dir: str = "./uploads"
    allowed_extensions: list = [
        ".pdf", ".docx", ".doc", ".txt", ".zip", ".rar", ".7z",
        ".exe", ".bat", ".cmd", ".scr", ".pif", ".com", ".msi",
        ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".svg",
        ".html", ".htm", ".js", ".css", ".xml", ".json"
    ]
    
    # Security
    secret_key: str = "your-secret-key-change-in-production"
    algorithm: str = "HS256"
    access_token_expire_minutes: int = 30
    
    # ML Model settings
    model_confidence_threshold: float = 0.7
    enable_learning: bool = True
    
    # API Rate limiting
    api_rate_limit: int = 100  # requests per hour
    
    class Config:
        env_file = ".env"

settings = Settings()

# Create upload directory if it doesn't exist
os.makedirs(settings.upload_dir, exist_ok=True)