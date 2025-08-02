#!/usr/bin/env python3
"""
Log Server - Provides API access to nginx access logs
Simulates real nginx log monitoring for the WAF AI system
"""

import os
import re
import json
from datetime import datetime, timedelta
from typing import List, Dict, Optional
from fastapi import FastAPI, HTTPException
import uvicorn

app = FastAPI(title="Nginx Log Server", description="Provides API access to nginx logs")

NODE_ID = os.getenv("NODE_ID", "unknown-node")
LOG_PATH = os.getenv("LOG_PATH", "/logs/access.log")

def parse_nginx_log_line(line: str) -> Optional[Dict]:
    """Parse nginx log line into structured data"""
    # Nginx log format: IP - user [timestamp] "method url protocol" status size "referer" "user-agent" request_time upstream_time request_length bytes_sent
    pattern = r'^(\S+) - (\S+) \[([^\]]+)\] "([A-Z]+) ([^"]*) HTTP/[^"]*" (\d+) (\d+) "([^"]*)" "([^"]*)"(.*)'
    
    match = re.match(pattern, line.strip())
    if not match:
        return None
    
    try:
        groups = match.groups()
        timestamp_str = groups[2]
        
        # Parse timestamp
        try:
            timestamp = datetime.strptime(timestamp_str, "%d/%b/%Y:%H:%M:%S %z")
        except:
            timestamp = datetime.now()
        
        return {
            "timestamp": timestamp.isoformat(),
            "method": groups[3],
            "url": groups[4],
            "status": int(groups[5]),
            "size": int(groups[6]) if groups[6].isdigit() else 0,
            "referer": groups[7] if groups[7] != '-' else '',
            "user_agent": groups[8],
            "source_ip": groups[0],
            "headers": {
                "user-agent": groups[8],
                "referer": groups[7] if groups[7] != '-' else ''
            },
            "body": "",  # Not available in access logs
            "content_length": int(groups[6]) if groups[6].isdigit() else 0,
            "node_id": NODE_ID
        }
    except Exception as e:
        print(f"Error parsing log line: {e}")
        return None

def get_recent_logs(limit: int = 100) -> List[Dict]:
    """Get recent log entries"""
    logs = []
    
    try:
        if os.path.exists(LOG_PATH):
            with open(LOG_PATH, 'r') as f:
                lines = f.readlines()
                # Get last N lines
                recent_lines = lines[-limit:] if len(lines) > limit else lines
                
                for line in recent_lines:
                    parsed = parse_nginx_log_line(line)
                    if parsed:
                        logs.append(parsed)
        else:
            # If no log file exists, return empty logs
            print(f"Log file {LOG_PATH} does not exist")
            
    except Exception as e:
        print(f"Error reading logs: {e}")
        # Return empty logs if file reading fails
        
    return logs

# Mock data generation removed - using real log parsing only

@app.get("/")
async def root():
    """Root endpoint"""
    return {
        "service": "nginx-log-server",
        "node_id": NODE_ID,
        "status": "running",
        "endpoints": ["/api/logs", "/health"]
    }

@app.get("/health")
async def health():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "node_id": NODE_ID,
        "log_path": LOG_PATH,
        "log_exists": os.path.exists(LOG_PATH)
    }

@app.get("/api/logs")
async def get_logs(limit: int = 100):
    """Get recent nginx access logs"""
    try:
        logs = get_recent_logs(limit)
        return {
            "logs": logs,
            "count": len(logs),
            "node_id": NODE_ID,
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error retrieving logs: {str(e)}")

@app.get("/api/traffic-logs")
async def get_traffic_logs(limit: int = 100):
    """Alternative endpoint name for compatibility"""
    return await get_logs(limit)

if __name__ == "__main__":
    print(f"Starting log server for node: {NODE_ID}")
    print(f"Log path: {LOG_PATH}")
    uvicorn.run(app, host="0.0.0.0", port=8080)
