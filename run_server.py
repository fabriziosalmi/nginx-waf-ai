#!/usr/bin/env python3
"""
Simple server startup script
"""

import sys
import os
from pathlib import Path

# Add src to Python path
current_dir = Path(__file__).parent
src_dir = current_dir / "src"
sys.path.insert(0, str(current_dir))
sys.path.insert(0, str(src_dir))

# Set environment variable for module loading
os.environ['PYTHONPATH'] = f"{current_dir}:{src_dir}"

import uvicorn
from src.main import app

if __name__ == "__main__":
    print("🚀 Starting Nginx WAF AI Server...")
    print("📡 API Documentation: http://localhost:8000/docs")
    print("🔍 Health Check: http://localhost:8000/health")
    
    uvicorn.run(
        "src.main:app",
        host="0.0.0.0",
        port=8000,
        log_level="info",
        reload=False
    )
