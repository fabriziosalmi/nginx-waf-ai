#!/usr/bin/env python3
"""
Test script to verify status endpoints are working correctly
"""

import asyncio
import json
import time
import requests
from datetime import datetime

# Base URL for the WAF API
BASE_URL = "http://localhost:8000"

def test_endpoint(endpoint, expected_status=200):
    """Test a single endpoint and return the result"""
    url = f"{BASE_URL}{endpoint}"
    try:
        start_time = time.time()
        response = requests.get(url, timeout=10)
        response_time = round((time.time() - start_time) * 1000, 2)
        
        print(f"✓ {endpoint}")
        print(f"  Status: {response.status_code}")
        print(f"  Response time: {response_time}ms")
        
        if response.status_code == expected_status:
            try:
                data = response.json()
                print(f"  Response preview: {json.dumps(data, indent=2)[:200]}...")
                return True, data
            except json.JSONDecodeError:
                print(f"  Response (text): {response.text[:100]}...")
                return True, response.text
        else:
            print(f"  ❌ Expected {expected_status}, got {response.status_code}")
            print(f"  Error: {response.text[:100]}...")
            return False, None
            
    except requests.exceptions.RequestException as e:
        print(f"❌ {endpoint}")
        print(f"  Error: {str(e)}")
        return False, None

def main():
    """Test all status endpoints"""
    print("=" * 60)
    print("WAF AI Status Endpoints Test")
    print("=" * 60)
    print(f"Testing endpoints on {BASE_URL}")
    print(f"Test started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print()
    
    # Test endpoints that don't require authentication
    public_endpoints = [
        "/health",
        "/metrics"
    ]
    
    # Test authenticated endpoints (these might fail without auth)
    protected_endpoints = [
        "/api/debug/status",
        "/api/status", 
        "/api/health",
        "/api/nodes/status",
        "/api/rules/stats"
    ]
    
    results = {
        "public": {},
        "protected": {}
    }
    
    print("Testing Public Endpoints:")
    print("-" * 30)
    for endpoint in public_endpoints:
        success, data = test_endpoint(endpoint)
        results["public"][endpoint] = {"success": success, "data": data}
        print()
    
    print("Testing Protected Endpoints (may require authentication):")
    print("-" * 50)
    for endpoint in protected_endpoints:
        success, data = test_endpoint(endpoint)
        results["protected"][endpoint] = {"success": success, "data": data}
        print()
    
    # Summary
    print("=" * 60)
    print("SUMMARY")
    print("=" * 60)
    
    public_success = sum(1 for r in results["public"].values() if r["success"])
    protected_success = sum(1 for r in results["protected"].values() if r["success"])
    
    print(f"Public endpoints: {public_success}/{len(public_endpoints)} working")
    print(f"Protected endpoints: {protected_success}/{len(protected_endpoints)} working")
    
    # Service status analysis
    print("\nService Status Analysis:")
    print("-" * 25)
    
    # Check if we can get debug status
    debug_status = results["protected"].get("/api/debug/status", {}).get("data")
    if debug_status:
        traffic_collector = debug_status.get("traffic_collector", {})
        ml_engine = debug_status.get("ml_engine", {})
        processing = debug_status.get("processing", {})
        
        print(f"Traffic Collector: {'✓' if traffic_collector.get('initialized') else '❌'} Initialized")
        print(f"                  {'✓' if traffic_collector.get('is_collecting') else '❌'} Collecting")
        print(f"                  {traffic_collector.get('collected_requests_count', 0)} Requests")
        
        print(f"ML Engine:        {'✓' if ml_engine.get('initialized') else '❌'} Initialized")
        print(f"                  {'✓' if ml_engine.get('is_trained') else '❌'} Trained")
        
        print(f"Processing:       {'✓' if processing.get('is_processing') else '❌'} Active")
    else:
        print("Unable to get detailed service status")
    
    print(f"\nTest completed at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

if __name__ == "__main__":
    main()
