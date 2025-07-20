#!/usr/bin/env python3
"""
Test script for the nginx WAF AI API
"""

import requests
import json
import time

BASE_URL = "http://localhost:8000"

def test_health():
    """Test health endpoint"""
    print("🔍 Testing health endpoint...")
    response = requests.get(f"{BASE_URL}/health")
    print(f"Status: {response.status_code}")
    print(f"Response: {json.dumps(response.json(), indent=2)}")
    return response.status_code == 200

def test_stats():
    """Test stats endpoint"""
    print("\n📊 Testing stats endpoint...")
    response = requests.get(f"{BASE_URL}/api/stats")
    print(f"Status: {response.status_code}")
    print(f"Response: {json.dumps(response.json(), indent=2)}")
    return response.status_code == 200

def test_add_nginx_node():
    """Test adding an nginx node"""
    print("\n🖥️  Testing add nginx node...")
    node_data = {
        "node_id": "test-node-1",
        "hostname": "localhost",
        "ssh_host": "127.0.0.1",
        "ssh_port": 22,
        "ssh_username": "test",
        "nginx_config_path": "/tmp/nginx",
        "nginx_reload_command": "echo 'reload nginx'",
        "api_endpoint": "http://localhost:8080"
    }
    
    response = requests.post(f"{BASE_URL}/api/nodes/add", json=node_data)
    print(f"Status: {response.status_code}")
    print(f"Response: {json.dumps(response.json(), indent=2)}")
    return response.status_code == 200

def test_list_nodes():
    """Test listing nginx nodes"""
    print("\n📋 Testing list nodes...")
    response = requests.get(f"{BASE_URL}/api/nodes")
    print(f"Status: {response.status_code}")
    print(f"Response: {json.dumps(response.json(), indent=2)}")
    return response.status_code == 200

def test_get_rules():
    """Test getting WAF rules"""
    print("\n📜 Testing get rules...")
    response = requests.get(f"{BASE_URL}/api/rules")
    print(f"Status: {response.status_code}")
    print(f"Response: {json.dumps(response.json(), indent=2)}")
    return response.status_code == 200

def test_nginx_config():
    """Test nginx config generation"""
    print("\n⚙️  Testing nginx config generation...")
    response = requests.get(f"{BASE_URL}/api/config/nginx")
    print(f"Status: {response.status_code}")
    print(f"Response: {json.dumps(response.json(), indent=2)}")
    return response.status_code == 200

def test_simulate_threat_detection():
    """Simulate threat detection by testing rule generation"""
    print("\n🚨 Testing threat simulation...")
    
    # First, let's test with sample threat data
    sample_threats = [
        {
            "request_id": "test_1",
            "threat_score": -0.8,
            "threat_type": "sql_injection",
            "confidence": 0.9,
            "features_used": ["url_length", "contains_sql_patterns"],
            "timestamp": "2024-01-01T10:00:00Z",
            "source_ip": "192.168.1.100"
        },
        {
            "request_id": "test_2", 
            "threat_score": -0.7,
            "threat_type": "xss_attack",
            "confidence": 0.85,
            "features_used": ["contains_xss_patterns"],
            "timestamp": "2024-01-01T10:01:00Z",
            "source_ip": "192.168.1.101"
        }
    ]
    
    print(f"Sample threats: {json.dumps(sample_threats, indent=2)}")
    return True

def main():
    print("🧪 Starting nginx WAF AI API Tests\n")
    
    tests = [
        ("Health Check", test_health),
        ("System Stats", test_stats),
        ("Add Nginx Node", test_add_nginx_node),
        ("List Nodes", test_list_nodes),
        ("Get WAF Rules", test_get_rules),
        ("Nginx Config", test_nginx_config),
        ("Threat Simulation", test_simulate_threat_detection)
    ]
    
    results = []
    for test_name, test_func in tests:
        try:
            result = test_func()
            results.append((test_name, "✅ PASS" if result else "❌ FAIL"))
        except Exception as e:
            print(f"Error in {test_name}: {e}")
            results.append((test_name, f"❌ ERROR: {e}"))
        
        time.sleep(0.5)  # Small delay between tests
    
    print("\n" + "="*50)
    print("📋 TEST RESULTS:")
    print("="*50)
    for test_name, result in results:
        print(f"{result:15} {test_name}")
    
    passed = len([r for _, r in results if "✅" in r])
    total = len(results)
    print(f"\n🎯 Results: {passed}/{total} tests passed")

if __name__ == "__main__":
    main()
