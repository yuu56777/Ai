#!/usr/bin/env python3
"""
AI Cybersecurity Fraud Detection System
Server startup script
"""

import uvicorn
import os
import sys
from pathlib import Path

def main():
    """Main server startup function"""
    print("🛡️  Starting AI Cybersecurity Fraud Detection System")
    print("=" * 60)
    
    # Add the project root to Python path
    project_root = Path(__file__).parent
    sys.path.insert(0, str(project_root))
    
    # Check if .env file exists, if not copy from example
    env_path = project_root / ".env"
    env_example_path = project_root / ".env.example"
    
    if not env_path.exists() and env_example_path.exists():
        print("📋 Creating .env file from template...")
        env_path.write_text(env_example_path.read_text())
        print("✅ .env file created. Please review and update the configuration.")
    
    # Create necessary directories
    directories = ["uploads", "models"]
    for directory in directories:
        dir_path = project_root / directory
        dir_path.mkdir(exist_ok=True)
        print(f"📁 Directory ready: {directory}/")
    
    # Get configuration from environment or use defaults
    host = os.getenv("HOST", "0.0.0.0")
    port = int(os.getenv("PORT", "8000"))
    debug = os.getenv("DEBUG", "false").lower() == "true"
    
    print(f"🌐 Server starting on http://{host}:{port}")
    print(f"📚 API Documentation: http://{host}:{port}/api/docs")
    print(f"🎓 Workshop: http://{host}:{port}/api/workshop")
    print(f"💡 Debug mode: {debug}")
    print("=" * 60)
    
    try:
        # Start the server
        uvicorn.run(
            "app.main:app",
            host=host,
            port=port,
            reload=debug,
            log_level="info" if not debug else "debug"
        )
    except KeyboardInterrupt:
        print("\n🛑 Server shutdown requested by user")
    except Exception as e:
        print(f"❌ Server startup failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()