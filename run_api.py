"""Standalone API server script that works without package installation."""

import sys
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

# Now import and run the server
from src.api.server import app

if __name__ == "__main__":
    import uvicorn
    print("Starting AI Compliance Assessor API Server...")
    print("API Documentation: http://localhost:8000/docs")
    print("API Root: http://localhost:8000")
    uvicorn.run(app, host="0.0.0.0", port=8000)
