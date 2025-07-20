#!/usr/bin/env python3
"""
Complete nginx WAF AI Demo Script
Shows full workflow from setup to deployment
"""

import requests
import json
import time
import subprocess
import sys

BASE_URL = "http://localhost:8000"

def print_step(step_num, title, description=""):
    """Print a nicely formatted step"""
    print(f"\n{'='*60}")
    print(f"Step {step_num}: {title}")
    if description:
        print(f"Description: {description}")
    print('='*60)

def print_response(response, show_full=True):
    """Print API response"""
    print(f"Status Code: {response.status_code}")
    if show_full:
        try:
            print(f"Response: {json.dumps(response.json(), indent=2)}")
        except:
            print(f"Response: {response.text}")
    else:
        print("Response: [data received]")

def demo_health_check():
    print_step(1, "Health Check", "Verify the API server is running")
    response = requests.get(f"{BASE_URL}/health")
    print_response(response)
    return response.status_code == 200

def demo_system_stats():
    print_step(2, "System Statistics", "Check initial system state")
    response = requests.get(f"{BASE_URL}/api/stats")
    print_response(response)
    return response.status_code == 200

def demo_add_nginx_node():
    print_step(3, "Add Nginx Node", "Register an nginx node for management")
    node_data = {
        "node_id": "prod-node-1",
        "hostname": "production-server",
        "ssh_host": "10.0.1.100",
        "ssh_port": 22,
        "ssh_username": "nginx-admin",
        "nginx_config_path": "/etc/nginx/conf.d",
        "nginx_reload_command": "sudo systemctl reload nginx",
        "api_endpoint": "http://10.0.1.100:8080/api/logs"
    }
    
    response = requests.post(f"{BASE_URL}/api/nodes/add", json=node_data)
    print_response(response)
    return response.status_code == 200

def demo_ml_training():
    print_step(4, "Machine Learning Training", "Train the threat detection model")
    
    # Sample training data representing different attack patterns
    training_data = {
        "training_data": [
            {
                "timestamp": "2024-01-01T10:00:00Z",
                "method": "GET",
                "url": "/login?id=1' OR '1'='1",
                "headers_count": 5,
                "body_length": 0,
                "source_ip": "192.168.1.100",
                "user_agent": "sqlmap/1.0",
                "content_length": 0
            },
            {
                "timestamp": "2024-01-01T10:01:00Z",
                "method": "POST",
                "url": "/comment",
                "headers_count": 6,
                "body_length": 45,
                "source_ip": "192.168.1.101",
                "user_agent": "Mozilla/5.0",
                "content_length": 45,
                "body_contains_script": True
            },
            {
                "timestamp": "2024-01-01T10:02:00Z",
                "method": "GET",
                "url": "/search?q=normal+query",
                "headers_count": 6,
                "body_length": 0,
                "source_ip": "192.168.1.50",
                "user_agent": "Mozilla/5.0",
                "content_length": 0
            },
            {
                "timestamp": "2024-01-01T10:03:00Z",
                "method": "POST",
                "url": "/api/users",
                "headers_count": 8,
                "body_length": 120,
                "source_ip": "192.168.1.25",
                "user_agent": "MyApp/1.0",
                "content_length": 120
            }
        ],
        "labels": ["malicious", "malicious", "benign", "benign"]
    }
    
    response = requests.post(f"{BASE_URL}/api/training/start", json=training_data)
    print_response(response)
    return response.status_code == 200

def demo_traffic_collection():
    print_step(5, "Start Traffic Collection", "Begin monitoring HTTP traffic")
    
    node_urls = ["http://10.0.1.100:8080/api/logs", "http://10.0.1.101:8080/api/logs"]
    response = requests.post(f"{BASE_URL}/api/traffic/start-collection", json=node_urls)
    print_response(response)
    return response.status_code == 200

def demo_real_time_processing():
    print_step(6, "Start Real-time Processing", "Enable threat detection and rule generation")
    
    response = requests.post(f"{BASE_URL}/api/processing/start")
    print_response(response)
    return response.status_code == 200

def demo_system_status():
    print_step(7, "Check System Status", "Verify all components are active")
    
    response = requests.get(f"{BASE_URL}/api/stats")
    print_response(response)
    
    print("\n" + "-"*40)
    print("COMPONENT STATUS:")
    print("-"*40)
    data = response.json()
    components = data.get('components', {})
    for component, status in components.items():
        status_icon = "✅" if status else "❌"
        print(f"{status_icon} {component.replace('_', ' ').title()}: {status}")
    
    return response.status_code == 200

def demo_nginx_config():
    print_step(8, "Generate Nginx Configuration", "Generate WAF rules for nginx")
    
    response = requests.get(f"{BASE_URL}/api/config/nginx")
    print_response(response, show_full=False)
    
    # Show a snippet of the config
    config = response.json().get('config', '')
    lines = config.split('\n')[:10]
    print(f"Config Preview (first 10 lines):")
    print("-" * 40)
    for line in lines:
        print(line)
    print("... (truncated)")
    
    return response.status_code == 200

def demo_node_management():
    print_step(9, "Node Management", "List and check node status")
    
    # List nodes
    response = requests.get(f"{BASE_URL}/api/nodes")
    print("Registered Nodes:")
    print_response(response)
    
    print("\n" + "-"*30)
    print("Node Status Check:")
    print("-"*30)
    
    # Check node status
    response = requests.get(f"{BASE_URL}/api/nodes/status")
    print_response(response)
    
    return True

def demo_cleanup():
    print_step(10, "Cleanup", "Stop processing (optional)")
    
    try:
        response = requests.post(f"{BASE_URL}/api/processing/stop")
        print_response(response)
    except:
        print("No cleanup needed or already stopped")
    
    return True

def main():
    print("🛡️  nginx WAF AI - Complete System Demonstration")
    print("This demo shows the full workflow of the AI-powered WAF system")
    print("-" * 70)
    
    demos = [
        ("Health Check", demo_health_check),
        ("System Stats", demo_system_stats),
        ("Add Nginx Node", demo_add_nginx_node),
        ("ML Training", demo_ml_training),
        ("Traffic Collection", demo_traffic_collection),
        ("Real-time Processing", demo_real_time_processing),
        ("System Status", demo_system_status),
        ("Nginx Config", demo_nginx_config),
        ("Node Management", demo_node_management),
        ("Cleanup", demo_cleanup)
    ]
    
    results = []
    
    for demo_name, demo_func in demos:
        try:
            print(f"\n⏳ Running: {demo_name}...")
            success = demo_func()
            results.append((demo_name, "✅ PASS" if success else "❌ FAIL"))
            
            # Small delay between demos
            time.sleep(1)
            
        except requests.exceptions.ConnectionError:
            print(f"❌ Connection Error: Is the server running at {BASE_URL}?")
            results.append((demo_name, "❌ CONNECTION ERROR"))
            break
        except Exception as e:
            print(f"❌ Error in {demo_name}: {e}")
            results.append((demo_name, f"❌ ERROR: {e}"))
    
    # Final Summary
    print("\n" + "="*70)
    print("🎯 DEMONSTRATION RESULTS")
    print("="*70)
    
    for demo_name, result in results:
        print(f"{result:<20} {demo_name}")
    
    passed = len([r for _, r in results if "✅" in r])
    total = len(results)
    
    print(f"\n📊 Summary: {passed}/{total} demonstrations completed successfully")
    
    if passed == total:
        print("\n🎉 All demonstrations passed! The nginx WAF AI system is fully operational.")
        print("\n📋 Next Steps:")
        print("   1. Deploy to production environment")
        print("   2. Configure real nginx nodes")
        print("   3. Monitor threat detection performance")
        print("   4. Fine-tune ML models with production data")
    else:
        print("\n⚠️  Some demonstrations failed. Check the error messages above.")

if __name__ == "__main__":
    main()
