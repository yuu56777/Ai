from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from app.api import upload as upload_router

app = FastAPI(title="Cybersecurity Fraud Detection API")

# Include API routes
app.include_router(upload_router.router)

# Serve simple frontend
frontend_path = Path(__file__).parent.parent / "frontend"
app.mount("/static", StaticFiles(directory=frontend_path, html=True), name="static")


@app.get("/", include_in_schema=False)
async def index():
    """Return the upload UI."""
    return FileResponse(frontend_path / "index.html")


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=True)