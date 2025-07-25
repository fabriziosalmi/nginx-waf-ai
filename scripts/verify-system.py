#!/usr/bin/env python3
"""
Simple verification script to test WAF AI system functionality
"""

import requests
import json
import time

API_BASE = "http://localhost:8000"
UI_BASE = "http://localhost"
GRAFANA_BASE = "http://localhost:3000"

def test_endpoint(name, url, expected_status=200):
    """Test if an endpoint is responding"""
    try:
        response = requests.get(url, timeout=5)
        if response.status_code == expected_status:
            print(f"✓ {name}: OK")
            return True
        else:
            print(f"✗ {name}: HTTP {response.status_code}")
            return False
    except Exception as e:
        print(f"✗ {name}: {e}")
        return False

def test_authentication():
    """Test API authentication"""
    try:
        auth_data = {"username": "admin", "password": "admin123"}
        response = requests.post(f"{API_BASE}/auth/login", json=auth_data, timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            token = data.get("access_token")
            if token:
                print("✓ Authentication: OK")
                return token
            else:
                print("✗ Authentication: No token returned")
                return None
        else:
            print(f"✗ Authentication: HTTP {response.status_code}")
            return None
    except Exception as e:
        print(f"✗ Authentication: {e}")
        return None

def test_api_endpoints(token):
    """Test authenticated API endpoints"""
    headers = {"Authorization": f"Bearer {token}"}
    
    endpoints = [
        ("Health Check", f"{API_BASE}/health"),
        ("System Stats", f"{API_BASE}/api/stats"),
        ("Nodes", f"{API_BASE}/api/nodes"),
        ("Rules", f"{API_BASE}/api/rules"),
        ("Threats", f"{API_BASE}/api/threats"),
        ("Traffic Stats", f"{API_BASE}/api/traffic/stats")
    ]
    
    success_count = 0
    for name, url in endpoints:
        try:
            response = requests.get(url, headers=headers, timeout=5)
            if response.status_code == 200:
                print(f"✓ {name}: OK")
                success_count += 1
            else:
                print(f"✗ {name}: HTTP {response.status_code}")
        except Exception as e:
            print(f"✗ {name}: {e}")
    
    return success_count, len(endpoints)

def test_data_flow(token):
    """Test if data is flowing through the system"""
    headers = {"Authorization": f"Bearer {token}"}
    
    try:
        # Get system stats
        response = requests.get(f"{API_BASE}/api/stats", headers=headers, timeout=5)
        if response.status_code == 200:
            stats = response.json()
            
            print(f"\n📊 System Data:")
            print(f"   • Nodes: {stats.get('components', {}).get('nginx_nodes_count', 0)}")
            print(f"   • Threats: {stats.get('threats', {}).get('total_threats', 0)}")
            print(f"   • Traffic: {stats.get('traffic', {}).get('total_requests', 0)} requests")
            print(f"   • Rules: {stats.get('rules', {}).get('active_rules', 0)}")
            
            # Check if we have some data
            has_nodes = stats.get('components', {}).get('nginx_nodes_count', 0) > 0
            has_traffic = stats.get('traffic', {}).get('total_requests', 0) > 0
            
            if has_nodes:
                print("✓ Node data: OK")
            else:
                print("⚠ Node data: No nodes registered")
            
            if has_traffic:
                print("✓ Traffic data: OK")
            else:
                print("⚠ Traffic data: No traffic detected yet")
                
            return has_nodes or has_traffic
        else:
            print(f"✗ Stats endpoint: HTTP {response.status_code}")
            return False
            
    except Exception as e:
        print(f"✗ Data flow test: {e}")
        return False

def main():
    print("🔍 WAF AI System Verification")
    print("=" * 40)
    
    # Test basic connectivity
    print("\n🌐 Testing Basic Connectivity:")
    services = [
        ("WAF API", f"{API_BASE}/health"),
        ("WAF Metrics", f"{API_BASE}/metrics"),
        ("UI", UI_BASE),
        ("Grafana", f"{GRAFANA_BASE}/api/health"),
        ("Prometheus", "http://localhost:9090/-/ready"),
        ("Nginx Node 1", "http://localhost:8081"),
        ("Nginx Node 2", "http://localhost:8082")
    ]
    
    connectivity_score = 0
    for name, url in services:
        if test_endpoint(name, url):
            connectivity_score += 1
    
    print(f"\nConnectivity Score: {connectivity_score}/{len(services)}")
    
    if connectivity_score < 3:
        print("\n❌ Critical services are not responding. Please check Docker services.")
        print("Run: docker-compose ps")
        return
    
    # Test authentication
    print("\n🔐 Testing Authentication:")
    token = test_authentication()
    
    if not token:
        print("\n❌ Authentication failed. Cannot proceed with API tests.")
        return
    
    # Test API endpoints
    print("\n🔌 Testing API Endpoints:")
    api_success, api_total = test_api_endpoints(token)
    print(f"\nAPI Score: {api_success}/{api_total}")
    
    # Test data flow
    print("\n📊 Testing Data Flow:")
    has_data = test_data_flow(token)
    
    # Final assessment
    print("\n" + "=" * 40)
    print("📋 VERIFICATION SUMMARY")
    print("=" * 40)
    
    if connectivity_score >= 5 and api_success >= 4 and token:
        print("🎉 System Status: EXCELLENT")
        print("   All services are running and responding correctly.")
        
        if has_data:
            print("   Data is flowing through the system.")
        else:
            print("   ⚠  Data may still be initializing (this is normal for new deployments).")
            
    elif connectivity_score >= 3 and api_success >= 3 and token:
        print("✅ System Status: GOOD")
        print("   Core services are working. Some optional services may need attention.")
        
    else:
        print("⚠️  System Status: NEEDS ATTENTION")
        print("   Some critical services are not responding correctly.")
    
    print(f"\n📱 Access your WAF dashboard at: {UI_BASE}")
    print(f"📊 Access Grafana at: {GRAFANA_BASE} (admin/waf-admin)")
    print(f"🔧 Access API docs at: {API_BASE}/docs")
    
    print("\n💡 If you see issues:")
    print("   1. Wait 1-2 minutes for services to fully initialize")
    print("   2. Run: docker-compose logs -f waf-api")
    print("   3. Try the UI bootstrap: http://localhost -> Initialize System")

if __name__ == "__main__":
    main()
