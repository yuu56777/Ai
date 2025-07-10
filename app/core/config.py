import os
from pathlib import Path
from typing import Set

# Allowed extensions for uploads
ALLOWED_EXT: Set[str] = {
    ".pdf",
    ".doc",
    ".docx",
    ".xls",
    ".xlsx",
    ".ppt",
    ".pptx",
    ".txt",
    ".rtf",
    ".zip",
    ".rar",
}

# Maximum file size in bytes (default 50 MB)
MAX_FILE_SIZE: int = int(os.getenv("MAX_FILE_SIZE", "52428800"))

# VirusTotal API key (optional). If not provided, VT integration is disabled.
VT_API_KEY: str | None = os.getenv("VT_API_KEY")

# Directory to store temporary uploads
TMP_DIR: Path = Path(os.getenv("TMP_DIR", "/tmp/analyzer_uploads"))
TMP_DIR.mkdir(parents=True, exist_ok=True)