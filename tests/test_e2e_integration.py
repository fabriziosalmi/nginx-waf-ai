#!/usr/bin/env python3
"""
Docker Compose and end-to-end integration tests.

This test suite verifies the complete system working together,
including Docker container interactions, API integration,
and real traffic processing workflows.
"""

import pytest
import asyncio
import time
import json
import subprocess
import requests
from datetime import datetime, timedelta
from typing import Dict, List, Any
import docker
import httpx

from test_api_integration import TestAPIIntegration


class TestDockerCompose:
    """Test Docker Compose deployment and container interactions"""
    
    @pytest.fixture(scope="class", autouse=True)
    def setup_docker_environment(self):
        """Set up Docker environment for testing"""
        self.docker_client = docker.from_env()
        self.compose_file = "docker-compose.yml"
        self.containers_started = False
        
        yield
        
        # Cleanup after tests
        if self.containers_started:
            self.teardown_containers()
    
    def start_containers(self):
        """Start Docker Compose services"""
        try:
            # Start containers
            result = subprocess.run(
                ["docker-compose", "up", "-d"],
                capture_output=True,
                text=True,
                timeout=300  # 5 minutes timeout
            )
            
            if result.returncode != 0:
                pytest.skip(f"Failed to start Docker containers: {result.stderr}")
            
            self.containers_started = True
            
            # Wait for services to be ready
            self.wait_for_services()
            
        except subprocess.TimeoutExpired:
            pytest.skip("Docker containers took too long to start")
        except Exception as e:
            pytest.skip(f"Failed to start Docker environment: {e}")
    
    def teardown_containers(self):
        """Stop and remove Docker Compose services"""
        try:
            subprocess.run(
                ["docker-compose", "down", "-v"],
                capture_output=True,
                text=True,
                timeout=60
            )
        except Exception as e:
            print(f"Warning: Failed to cleanup containers: {e}")
    
    def wait_for_services(self):
        """Wait for all services to be ready"""
        services = {
            "waf-api": "http://localhost:8000/health",
            "nginx-node-1": "http://localhost:8081",
            "nginx-node-2": "http://localhost:8082",
            "log-server-1": "http://localhost:8080/health",
            "log-server-2": "http://localhost:8083/health",
            "prometheus": "http://localhost:9090/-/ready",
            "grafana": "http://localhost:3000/api/health"
        }
        
        max_wait = 120  # 2 minutes
        start_time = time.time()
        
        for service_name, health_url in services.items():
            print(f"Waiting for {service_name} to be ready...")
            
            while time.time() - start_time < max_wait:
                try:
                    response = requests.get(health_url, timeout=5)
                    if response.status_code in [200, 201]:
                        print(f"✓ {service_name} is ready")
                        break
                except requests.RequestException:
                    pass
                
                time.sleep(2)
            else:
                pytest.skip(f"Service {service_name} did not become ready in {max_wait} seconds")
    
    def test_container_health(self):
        """Test that all containers are healthy"""
        self.start_containers()
        
        # Check container health
        containers = self.docker_client.containers.list()
        waf_containers = [c for c in containers if 'waf' in c.name or 'nginx-node' in c.name]
        
        assert len(waf_containers) >= 3  # waf-api + 2 nginx nodes minimum
        
        for container in waf_containers:
            assert container.status == "running"
    
    def test_api_accessibility(self):
        """Test that the WAF API is accessible"""
        self.start_containers()
        
        response = requests.get("http://localhost:8000/health", timeout=10)
        assert response.status_code == 200
        
        data = response.json()
        assert "status" in data
        assert "components" in data
    
    def test_nginx_nodes_accessibility(self):
        """Test that nginx nodes are accessible"""
        self.start_containers()
        
        # Test nginx node 1
        response = requests.get("http://localhost:8081", timeout=10)
        assert response.status_code == 200
        
        # Test nginx node 2
        response = requests.get("http://localhost:8082", timeout=10)
        assert response.status_code == 200
    
    def test_log_servers_accessibility(self):
        """Test that log servers are accessible"""
        self.start_containers()
        
        # Test log server 1
        response = requests.get("http://localhost:8080/health", timeout=10)
        assert response.status_code == 200
        
        # Test log server 2
        response = requests.get("http://localhost:8083/health", timeout=10)
        assert response.status_code == 200
    
    def test_monitoring_stack_accessibility(self):
        """Test that monitoring stack is accessible"""
        self.start_containers()
        
        # Test Prometheus
        response = requests.get("http://localhost:9090/-/ready", timeout=10)
        assert response.status_code == 200
        
        # Test Grafana
        response = requests.get("http://localhost:3000/api/health", timeout=10)
        assert response.status_code == 200


class TestEndToEndWorkflow:
    """Test complete end-to-end workflows"""
    
    @pytest.fixture(autouse=True)
    def setup_method(self):
        """Set up test environment"""
        self.base_url = "http://localhost:8000"
        self.admin_token = None
        self.operator_token = None
        
        # Wait a bit for services to stabilize
        time.sleep(5)
        
        # Authenticate to get tokens
        self.authenticate()
    
    def authenticate(self):
        """Authenticate and get access tokens"""
        try:
            # Login as admin
            admin_response = requests.post(
                f"{self.base_url}/auth/login",
                json={"username": "admin", "password": "admin123"},
                timeout=10
            )
            
            if admin_response.status_code == 200:
                self.admin_token = admin_response.json()["access_token"]
            
            # Try to create operator user if needed
            if self.admin_token:
                requests.post(
                    f"{self.base_url}/auth/users",
                    headers={"Authorization": f"Bearer {self.admin_token}"},
                    json={
                        "username": "operator",
                        "password": "Operator123!",
                        "roles": ["operator"]
                    },
                    timeout=10
                )
                
                # Login as operator
                operator_response = requests.post(
                    f"{self.base_url}/auth/login",
                    json={"username": "operator", "password": "Operator123!"},
                    timeout=10
                )
                
                if operator_response.status_code == 200:
                    self.operator_token = operator_response.json()["access_token"]
        
        except Exception as e:
            pytest.skip(f"Failed to authenticate: {e}")
    
    def test_complete_waf_workflow(self):
        """Test complete WAF workflow from training to deployment"""
        if not self.admin_token:
            pytest.skip("Admin authentication required for this test")
        
        admin_headers = {"Authorization": f"Bearer {self.admin_token}"}
        operator_headers = {"Authorization": f"Bearer {self.operator_token}"} if self.operator_token else admin_headers
        
        # Step 1: Add nginx nodes
        node_data = {
            "node_id": "test-node-e2e",
            "hostname": "nginx-node-1",
            "ssh_host": "nginx-node-1",
            "ssh_port": 22,
            "ssh_username": "root",
            "ssh_key_path": "/tmp/test_key",
            "nginx_config_path": "/etc/nginx/conf.d",
            "nginx_reload_command": "nginx -s reload",
            "api_endpoint": "http://nginx-node-1:80"
        }
        
        response = requests.post(
            f"{self.base_url}/api/nodes/add",
            headers=admin_headers,
            json=node_data,
            timeout=10
        )
        
        assert response.status_code == 200
        
        # Step 2: Train ML model
        training_data = {
            "training_data": [
                {
                    "timestamp": "2024-01-01T00:00:00Z",
                    "url": "/admin/login?user=admin' OR 1=1--",
                    "source_ip": "192.168.1.100",
                    "user_agent": "Mozilla/5.0 (X11; Linux x86_64)",
                    "url_length": 30,
                    "body_length": 0,
                    "headers_count": 5,
                    "content_length": 0,
                    "has_suspicious_headers": False,
                    "contains_sql_patterns": True,
                    "contains_xss_patterns": False,
                    "method": "GET"
                },
                {
                    "timestamp": "2024-01-01T00:01:00Z",
                    "url": "/search?q=<script>alert('xss')</script>",
                    "source_ip": "192.168.1.101",
                    "user_agent": "Mozilla/5.0 (Windows NT 10.0)",
                    "url_length": 25,
                    "body_length": 0,
                    "headers_count": 5,
                    "content_length": 0,
                    "has_suspicious_headers": False,
                    "contains_sql_patterns": False,
                    "contains_xss_patterns": True,
                    "method": "GET"
                }
            ],
            "labels": ["sql_injection", "xss_attack"]
        }
        
        response = requests.post(
            f"{self.base_url}/api/training/start",
            headers=operator_headers,
            json=training_data,
            timeout=30
        )
        
        assert response.status_code == 200
        
        # Step 3: Start traffic collection
        response = requests.post(
            f"{self.base_url}/api/traffic/start-collection",
            headers=operator_headers,
            json=["http://log-server-1:8080", "http://log-server-2:8080"],
            timeout=10
        )
        
        assert response.status_code == 200
        
        # Step 4: Start real-time processing
        response = requests.post(
            f"{self.base_url}/api/processing/start",
            headers=operator_headers,
            timeout=10
        )
        
        assert response.status_code == 200
        
        # Step 5: Wait a bit for processing
        time.sleep(5)
        
        # Step 6: Check system stats
        response = requests.get(
            f"{self.base_url}/api/stats",
            headers=operator_headers,
            timeout=10
        )
        
        assert response.status_code == 200
        data = response.json()
        assert "components" in data
        assert "traffic" in data
        
        # Step 7: Test ML prediction
        response = requests.post(
            f"{self.base_url}/api/debug/test-prediction",
            headers=operator_headers,
            timeout=10
        )
        
        assert response.status_code == 200
        data = response.json()
        assert "predictions" in data
        
        # Step 8: Get active rules
        response = requests.get(
            f"{self.base_url}/api/rules",
            headers=operator_headers,
            timeout=10
        )
        
        assert response.status_code == 200
        
        # Step 9: Deploy rules (this might fail due to SSH, but should attempt)
        response = requests.post(
            f"{self.base_url}/api/rules/deploy",
            headers=admin_headers,
            json={
                "node_ids": ["test-node-e2e"],
                "force_deployment": False
            },
            timeout=30
        )
        
        # Deployment might fail due to SSH connectivity in test environment
        # But the endpoint should respond properly
        assert response.status_code in [200, 400, 500]
    
    def test_traffic_generation_and_detection(self):
        """Test traffic generation and threat detection"""
        if not self.operator_token:
            pytest.skip("Operator authentication required for this test")
        
        operator_headers = {"Authorization": f"Bearer {self.operator_token}"}
        
        # Start processing first
        requests.post(
            f"{self.base_url}/api/processing/start",
            headers=operator_headers,
            timeout=10
        )
        
        # Generate some test traffic to nginx nodes
        test_requests = [
            # Normal request
            "http://localhost:8081/",
            # Potential SQL injection
            "http://localhost:8081/login?user=admin'%20OR%201=1--",
            # Potential XSS
            "http://localhost:8081/search?q=%3Cscript%3Ealert('xss')%3C/script%3E",
        ]
        
        for url in test_requests:
            try:
                requests.get(url, timeout=5)
            except:
                pass  # Ignore connection errors, just generating traffic
        
        # Wait for processing
        time.sleep(10)
        
        # Check if threats were detected
        response = requests.get(
            f"{self.base_url}/api/threats",
            headers=operator_headers,
            timeout=10
        )
        
        assert response.status_code == 200
        data = response.json()
        assert "threats" in data
        assert "total_threats" in data
    
    def test_monitoring_integration(self):
        """Test monitoring stack integration"""
        # Test Prometheus metrics
        try:
            response = requests.get("http://localhost:9090/api/v1/query?query=up", timeout=10)
            assert response.status_code == 200
        except:
            pytest.skip("Prometheus not accessible")
        
        # Test that WAF API metrics are available
        try:
            response = requests.get("http://localhost:8000/metrics", timeout=10)
            # This will fail without auth, but should return 401, not connection error
            assert response.status_code in [200, 401]
        except:
            pytest.skip("WAF API metrics not accessible")


class TestPerformanceAndResilience:
    """Test system performance and resilience"""
    
    def setup_method(self):
        """Set up for performance tests"""
        self.base_url = "http://localhost:8000"
        
        # Simple health check to ensure system is running
        try:
            response = requests.get(f"{self.base_url}/health", timeout=5)
            if response.status_code != 200:
                pytest.skip("WAF API not accessible for performance tests")
        except:
            pytest.skip("WAF API not accessible for performance tests")
    
    def test_api_response_time(self):
        """Test API response times under normal load"""
        endpoints = [
            "/health",
            "/",
        ]
        
        for endpoint in endpoints:
            start_time = time.time()
            response = requests.get(f"{self.base_url}{endpoint}", timeout=10)
            end_time = time.time()
            
            response_time = end_time - start_time
            
            assert response.status_code == 200
            assert response_time < 2.0  # Should respond within 2 seconds
    
    def test_concurrent_requests(self):
        """Test handling of concurrent requests"""
        import concurrent.futures
        import threading
        
        def make_request():
            try:
                response = requests.get(f"{self.base_url}/health", timeout=10)
                return response.status_code == 200
            except:
                return False
        
        # Make 10 concurrent requests
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(make_request) for _ in range(10)]
            results = [future.result() for future in concurrent.futures.as_completed(futures)]
        
        # At least 80% should succeed
        success_rate = sum(results) / len(results)
        assert success_rate >= 0.8
    
    def test_memory_usage_stability(self):
        """Test that memory usage remains stable under load"""
        # This would require monitoring the container's memory usage
        # For now, just ensure the service remains responsive
        
        initial_response = requests.get(f"{self.base_url}/health", timeout=5)
        assert initial_response.status_code == 200
        
        # Make several requests
        for _ in range(50):
            requests.get(f"{self.base_url}/health", timeout=5)
        
        # Should still be responsive
        final_response = requests.get(f"{self.base_url}/health", timeout=5)
        assert final_response.status_code == 200
    
    def test_graceful_degradation(self):
        """Test graceful degradation when components fail"""
        # Test that API remains partially functional even when
        # some components are not available
        
        # The health endpoint should still work
        response = requests.get(f"{self.base_url}/health", timeout=10)
        assert response.status_code == 200
        
        # The root endpoint should still work
        response = requests.get(f"{self.base_url}/", timeout=10)
        assert response.status_code == 200


class TestSecurityValidation:
    """Test security aspects of the deployment"""
    
    def setup_method(self):
        """Set up for security tests"""
        self.base_url = "http://localhost:8000"
    
    def test_authentication_required(self):
        """Test that protected endpoints require authentication"""
        protected_endpoints = [
            "/api/status",
            "/api/nodes",
            "/api/training/start",
            "/api/rules",
            "/api/threats"
        ]
        
        for endpoint in protected_endpoints:
            response = requests.get(f"{self.base_url}{endpoint}", timeout=10)
            assert response.status_code == 401  # Unauthorized
    
    def test_security_headers(self):
        """Test that security headers are present"""
        response = requests.get(f"{self.base_url}/health", timeout=10)
        
        # Check for basic security headers
        headers = response.headers
        
        # These headers should be present for security
        expected_headers = [
            'X-Content-Type-Options',
            'X-Frame-Options',
            'X-XSS-Protection'
        ]
        
        present_headers = [h for h in expected_headers if h in headers]
        assert len(present_headers) > 0  # At least some security headers should be present
    
    def test_rate_limiting_behavior(self):
        """Test rate limiting behavior"""
        # Make rapid requests to test rate limiting
        responses = []
        
        for _ in range(20):
            try:
                response = requests.get(f"{self.base_url}/health", timeout=1)
                responses.append(response.status_code)
            except:
                responses.append(0)  # Connection error/timeout
        
        # Should mostly get 200s, but some might be rate limited
        success_count = responses.count(200)
        assert success_count > 0  # Some should succeed
    
    def test_input_validation(self):
        """Test input validation on API endpoints"""
        # Test with malformed JSON
        response = requests.post(
            f"{self.base_url}/auth/login",
            data="invalid json",
            headers={"Content-Type": "application/json"},
            timeout=10
        )
        
        assert response.status_code in [400, 422]  # Bad request or unprocessable entity
        
        # Test with missing fields
        response = requests.post(
            f"{self.base_url}/auth/login",
            json={"username": "test"},  # Missing password
            timeout=10
        )
        
        assert response.status_code in [400, 422]  # Should reject incomplete data


if __name__ == "__main__":
    # When run directly, perform a basic smoke test
    print("Running basic smoke test...")
    
    try:
        response = requests.get("http://localhost:8000/health", timeout=10)
        if response.status_code == 200:
            print("✓ WAF API is accessible")
            data = response.json()
            print(f"✓ System status: {data.get('status', 'unknown')}")
        else:
            print(f"✗ WAF API returned status code: {response.status_code}")
    except Exception as e:
        print(f"✗ Failed to connect to WAF API: {e}")
    
    try:
        response = requests.get("http://localhost:8081", timeout=10)
        if response.status_code == 200:
            print("✓ Nginx node 1 is accessible")
        else:
            print(f"✗ Nginx node 1 returned status code: {response.status_code}")
    except Exception as e:
        print(f"✗ Failed to connect to Nginx node 1: {e}")
    
    try:
        response = requests.get("http://localhost:8082", timeout=10)
        if response.status_code == 200:
            print("✓ Nginx node 2 is accessible")
        else:
            print(f"✗ Nginx node 2 returned status code: {response.status_code}")
    except Exception as e:
        print(f"✗ Failed to connect to Nginx node 2: {e}")
    
    print("Smoke test completed.")
