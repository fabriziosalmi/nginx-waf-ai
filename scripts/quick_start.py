#!/usr/bin/env python3
"""
WAF AI Quick Start Script

This script provides a simple way to train the ML model and start the WAF system.
Usage: python scripts/quick_start.py
"""

import requests
import json
import time
import sys
from datetime import datetime
from typing import Dict, List

# Configuration
WAF_API_URL = "http://localhost:8000"
TIMEOUT = 30

def log(message: str, level: str = "INFO"):
    """Log message with timestamp"""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    colors = {
        "INFO": "\033[0;34m",    # Blue
        "SUCCESS": "\033[0;32m", # Green
        "WARNING": "\033[1;33m", # Yellow
        "ERROR": "\033[0;31m",   # Red
        "RESET": "\033[0m"       # Reset
    }
    
    color = colors.get(level, colors["INFO"])
    reset = colors["RESET"]
    
    print(f"{color}[{timestamp}] {level}: {message}{reset}")

def wait_for_api() -> bool:
    """Wait for WAF API to be ready"""
    log("Waiting for WAF API to be ready...")
    
    for attempt in range(TIMEOUT):
        try:
            response = requests.get(f"{WAF_API_URL}/api/status", timeout=5)
            if response.status_code == 200:
                log("WAF API is ready!", "SUCCESS")
                return True
        except requests.exceptions.RequestException:
            pass
        
        if attempt % 5 == 0:
            print(".", end="", flush=True)
        time.sleep(1)
    
    log("WAF API failed to start", "ERROR")
    return False

def get_training_data() -> Dict:
    """Get comprehensive training data for ML model"""
    return {
        "training_data": [
            # Normal traffic
            {
                "timestamp": "2025-07-20T21:45:00",
                "method": "GET",
                "url": "/",
                "headers_count": 5,
                "body_length": 0,
                "source_ip": "192.168.1.1",
                "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "content_length": 0,
                "has_suspicious_headers": False,
                "url_length": 1,
                "contains_sql_patterns": False,
                "contains_xss_patterns": False
            },
            {
                "timestamp": "2025-07-20T21:45:01",
                "method": "GET",
                "url": "/api/products",
                "headers_count": 4,
                "body_length": 0,
                "source_ip": "192.168.1.2",
                "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
                "content_length": 0,
                "has_suspicious_headers": False,
                "url_length": 13,
                "contains_sql_patterns": False,
                "contains_xss_patterns": False
            },
            {
                "timestamp": "2025-07-20T21:45:02",
                "method": "POST",
                "url": "/api/login",
                "headers_count": 6,
                "body_length": 150,
                "source_ip": "192.168.1.10",
                "user_agent": "MyApp/1.0",
                "content_length": 150,
                "has_suspicious_headers": False,
                "url_length": 10,
                "contains_sql_patterns": False,
                "contains_xss_patterns": False
            },
            # SQL Injection attacks
            {
                "timestamp": "2025-07-20T21:45:03",
                "method": "GET", 
                "url": "/api/users?id=1' OR '1'='1",
                "headers_count": 4,
                "body_length": 0,
                "source_ip": "10.0.0.100",
                "user_agent": "sqlmap/1.6.12",
                "content_length": 0,
                "has_suspicious_headers": False,
                "url_length": 30,
                "contains_sql_patterns": True,
                "contains_xss_patterns": False
            },
            {
                "timestamp": "2025-07-20T21:45:04",
                "method": "GET",
                "url": "/search?q=test' UNION SELECT * FROM users--",
                "headers_count": 4,
                "body_length": 0,
                "source_ip": "10.0.0.200",
                "user_agent": "python-requests/2.28.1",
                "content_length": 0,
                "has_suspicious_headers": False,
                "url_length": 45,
                "contains_sql_patterns": True,
                "contains_xss_patterns": False
            },
            # XSS attacks
            {
                "timestamp": "2025-07-20T21:45:05",
                "method": "GET",
                "url": "/search?q=<script>alert('xss')</script>",
                "headers_count": 3,
                "body_length": 0,
                "source_ip": "172.16.0.50",
                "user_agent": "BadBot/1.0",
                "content_length": 0,
                "has_suspicious_headers": False,
                "url_length": 35,
                "contains_sql_patterns": False,
                "contains_xss_patterns": True
            },
            {
                "timestamp": "2025-07-20T21:45:06",
                "method": "GET",
                "url": "/api/search?q=<svg/onload=alert('xss')>",
                "headers_count": 3,
                "body_length": 0,
                "source_ip": "172.16.0.75",
                "user_agent": "XSSHunter",
                "content_length": 0,
                "has_suspicious_headers": False,
                "url_length": 32,
                "contains_sql_patterns": False,
                "contains_xss_patterns": True
            },
            # Unauthorized access attempts
            {
                "timestamp": "2025-07-20T21:45:07",
                "method": "GET",
                "url": "/admin/config.php",
                "headers_count": 2,
                "body_length": 0,
                "source_ip": "203.0.113.42",
                "user_agent": "Nmap NSE",
                "content_length": 0,
                "has_suspicious_headers": False,
                "url_length": 17,
                "contains_sql_patterns": False,
                "contains_xss_patterns": False
            },
            {
                "timestamp": "2025-07-20T21:45:08",
                "method": "GET",
                "url": "/admin/backup.sql",
                "headers_count": 2,
                "body_length": 0,
                "source_ip": "203.0.113.50",
                "user_agent": "Wget/1.20.3",
                "content_length": 0,
                "has_suspicious_headers": False,
                "url_length": 17,
                "contains_sql_patterns": False,
                "contains_xss_patterns": False
            },
            # File access attempts
            {
                "timestamp": "2025-07-20T21:45:09",
                "method": "GET",
                "url": "/../../../etc/passwd",
                "headers_count": 3,
                "body_length": 0,
                "source_ip": "198.51.100.25",
                "user_agent": "DirBuster",
                "content_length": 0,
                "has_suspicious_headers": False,
                "url_length": 18,
                "contains_sql_patterns": False,
                "contains_xss_patterns": False
            },
            {
                "timestamp": "2025-07-20T21:45:10",
                "method": "GET",
                "url": "/api/file?path=../../../etc/hosts",
                "headers_count": 3,
                "body_length": 0,
                "source_ip": "198.51.100.50",
                "user_agent": "curl/7.68.0",
                "content_length": 0,
                "has_suspicious_headers": False,
                "url_length": 32,
                "contains_sql_patterns": False,
                "contains_xss_patterns": False
            }
        ],
        "labels": [
            "normal", "normal", "normal",           # Normal traffic
            "sql_injection", "sql_injection",      # SQL injection
            "xss", "xss",                          # XSS attacks
            "unauthorized_access", "unauthorized_access",  # Admin access
            "file_access", "file_access"           # File traversal
        ]
    }

def train_model() -> bool:
    """Train the ML model with sample data"""
    log("Training ML model with comprehensive attack patterns...")
    
    try:
        training_data = get_training_data()
        
        response = requests.post(
            f"{WAF_API_URL}/api/training/start",
            json=training_data,
            timeout=30
        )
        
        if response.status_code == 200:
            result = response.json()
            if result.get("is_trained"):
                log("ML model trained successfully!", "SUCCESS")
                log(f"Training completed at: {result.get('timestamp')}")
                return True
            else:
                log("Training completed but model not marked as trained", "WARNING")
                return False
        else:
            log(f"Training failed with status {response.status_code}: {response.text}", "ERROR")
            return False
            
    except requests.exceptions.RequestException as e:
        log(f"Failed to train model: {e}", "ERROR")
        return False

def start_processing() -> bool:
    """Start real-time processing"""
    log("Starting real-time processing...")
    
    try:
        response = requests.post(f"{WAF_API_URL}/api/processing/start", timeout=10)
        
        if response.status_code == 200:
            result = response.json()
            log("Real-time processing started successfully!", "SUCCESS")
            log(f"Started at: {result.get('timestamp')}")
            return True
        else:
            log(f"Failed to start processing: {response.text}", "ERROR")
            return False
            
    except requests.exceptions.RequestException as e:
        log(f"Failed to start processing: {e}", "ERROR")
        return False

def check_system_status() -> Dict:
    """Check overall system status"""
    log("Checking system status...")
    
    try:
        response = requests.get(f"{WAF_API_URL}/api/status", timeout=10)
        
        if response.status_code == 200:
            status = response.json()
            
            # Pretty print status
            log("System Status:", "SUCCESS")
            print(f"  Traffic Collector: {'✅' if status.get('traffic_collector') else '❌'}")
            print(f"  ML Engine Trained: {'✅' if status.get('ml_engine_trained') else '❌'}")
            print(f"  Real-time Processor: {'✅' if status.get('real_time_processor') else '❌'}")
            print(f"  Processing Active: {'✅' if status.get('is_processing') else '❌'}")
            print(f"  Recent Requests: {status.get('recent_requests_count', 0)}")
            
            return status
        else:
            log(f"Failed to get status: {response.text}", "ERROR")
            return {}
            
    except requests.exceptions.RequestException as e:
        log(f"Failed to check status: {e}", "ERROR")
        return {}

def main():
    """Main execution function"""
    print("\n" + "="*50)
    print("       WAF AI Quick Start Script")
    print("="*50 + "\n")
    
    # Wait for API
    if not wait_for_api():
        sys.exit(1)
    
    # Train model
    if not train_model():
        log("Training failed, exiting", "ERROR")
        sys.exit(1)
    
    # Start processing
    if not start_processing():
        log("Failed to start processing, exiting", "ERROR")
        sys.exit(1)
    
    # Check final status
    status = check_system_status()
    
    if all([
        status.get('traffic_collector'),
        status.get('ml_engine_trained'),
        status.get('real_time_processor'),
        status.get('is_processing')
    ]):
        log("WAF AI system is fully operational! 🚀", "SUCCESS")
        
        print("\n" + "="*50)
        print("Access URLs:")
        print(f"  WAF API Docs: {WAF_API_URL}/docs")
        print(f"  Prometheus:   http://localhost:9090")
        print(f"  Grafana:      http://localhost:3000 (admin/admin)")
        print("="*50 + "\n")
        
        print("Next steps:")
        print("1. Open Grafana and view the 'Unified WAF Monitoring' dashboard")
        print("2. Monitor real-time threats and metrics")
        print(f"3. Check generated rules: {WAF_API_URL}/api/rules")
        print(f"4. View detected threats: {WAF_API_URL}/api/threats")
        
    else:
        log("System not fully operational, check logs", "WARNING")
        sys.exit(1)

if __name__ == "__main__":
    main()
