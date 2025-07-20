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
            # If no log file exists, generate some sample data
            logs = generate_sample_logs()
            
    except Exception as e:
        print(f"Error reading logs: {e}")
        # Return sample data if file reading fails
        logs = generate_sample_logs()
    
    return logs

def generate_sample_logs() -> List[Dict]:
    """Generate sample log data for testing"""
    sample_logs = []
    now = datetime.now()
    
    # Generate some normal requests
    normal_requests = [
        {"method": "GET", "url": "/", "status": 200, "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"},
        {"method": "GET", "url": "/api/products", "status": 200, "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)"},
        {"method": "POST", "url": "/api/login", "status": 200, "user_agent": "curl/7.68.0"},
        {"method": "GET", "url": "/dashboard/", "status": 200, "user_agent": "Mozilla/5.0 (X11; Linux x86_64)"},
    ]
    
    # Generate some suspicious requests
    suspicious_requests = [
        {"method": "GET", "url": "/admin' OR 1=1--", "status": 403, "user_agent": "sqlmap/1.6.12"},
        {"method": "POST", "url": "/search", "status": 200, "user_agent": "Mozilla/5.0", "body": "<script>alert('xss')</script>"},
        {"method": "GET", "url": "/api/users?id=1' UNION SELECT * FROM passwords--", "status": 403, "user_agent": "python-requests/2.28.1"},
        {"method": "GET", "url": "/.env", "status": 404, "user_agent": "Wget/1.20.3"},
    ]
    
    # Mix normal and suspicious requests
    all_requests = normal_requests * 5 + suspicious_requests
    
    for i, req in enumerate(all_requests[:20]):  # Limit to 20 entries
        sample_logs.append({
            "timestamp": (now - timedelta(minutes=i)).isoformat(),
            "method": req["method"],
            "url": req["url"],
            "status": req["status"],
            "size": 1024 + i * 10,
            "referer": "",
            "user_agent": req["user_agent"],
            "source_ip": f"192.168.1.{100 + (i % 50)}",
            "headers": {
                "user-agent": req["user_agent"],
                "referer": ""
            },
            "body": req.get("body", ""),
            "content_length": req.get("size", 0),
            "node_id": NODE_ID
        })
    
    return sample_logs

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
