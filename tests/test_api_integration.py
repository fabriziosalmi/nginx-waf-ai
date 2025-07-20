#!/usr/bin/env python3
"""
Integration tests for the Nginx WAF AI API endpoints.

This test suite verifies that all API endpoints work correctly with proper
authentication, authorization, and business logic.
"""

import pytest
import asyncio
import json
from datetime import datetime, timedelta
from typing import Dict, Any, Optional
from unittest.mock import Mock, patch, AsyncMock

import httpx
from fastapi.testclient import TestClient
from fastapi import status

from src.main import app
from src.auth import create_access_token, get_password_hash
from src.ml_engine import MLEngine, ThreatPrediction
from src.traffic_collector import TrafficCollector
from src.nginx_manager import NginxManager
from src.waf_rule_generator import WAFRuleGenerator


class TestAPIIntegration:
    """Integration tests for the API endpoints"""
    
    @pytest.fixture(autouse=True)
    def setup_method(self):
        """Set up test client and mock authentication"""
        self.client = TestClient(app)
        
        # Create test user tokens
        self.admin_token = create_access_token(data={"sub": "admin", "roles": ["admin"]})
        self.operator_token = create_access_token(data={"sub": "operator", "roles": ["operator"]})
        self.viewer_token = create_access_token(data={"sub": "viewer", "roles": ["viewer"]})
        
        # Headers for different user types
        self.admin_headers = {"Authorization": f"Bearer {self.admin_token}"}
        self.operator_headers = {"Authorization": f"Bearer {self.operator_token}"}
        self.viewer_headers = {"Authorization": f"Bearer {self.viewer_token}"}
        
        # Test data
        self.test_node_data = {
            "node_id": "test-node-1",
            "hostname": "test.example.com",
            "ssh_host": "192.168.1.100",
            "ssh_port": 22,
            "ssh_username": "nginx",
            "ssh_key_path": "/home/nginx/.ssh/id_rsa",
            "nginx_config_path": "/etc/nginx/conf.d",
            "nginx_reload_command": "sudo systemctl reload nginx",
            "api_endpoint": "http://192.168.1.100:8080"
        }
        
        self.test_training_data = {
            "training_data": [
                {
                    "timestamp": "2024-01-01T00:00:00Z",
                    "url": "/admin/login?user=admin' OR 1=1--",
                    "source_ip": "192.168.1.100",
                    "user_agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
                    "url_length": 30,
                    "body_length": 0,
                    "headers_count": 5,
                    "content_length": 0,
                    "has_suspicious_headers": False,
                    "contains_sql_patterns": True,
                    "contains_xss_patterns": False,
                    "method": "GET"
                }
            ],
            "labels": ["sql_injection"]
        }

    # =================== AUTHENTICATION TESTS ===================
    
    def test_login_valid_credentials(self):
        """Test login with valid credentials"""
        with patch('src.auth.verify_password') as mock_verify:
            with patch('src.auth.get_user') as mock_get_user:
                mock_verify.return_value = True
                mock_get_user.return_value = {
                    "username": "admin",
                    "hashed_password": "hashed",
                    "roles": ["admin"]
                }
                
                response = self.client.post(
                    "/auth/login",
                    json={"username": "admin", "password": "admin123"}
                )
                
                assert response.status_code == status.HTTP_200_OK
                data = response.json()
                assert "access_token" in data
                assert data["token_type"] == "bearer"
    
    def test_login_invalid_credentials(self):
        """Test login with invalid credentials"""
        with patch('src.auth.verify_password') as mock_verify:
            with patch('src.auth.get_user') as mock_get_user:
                mock_verify.return_value = False
                mock_get_user.return_value = None
                
                response = self.client.post(
                    "/auth/login",
                    json={"username": "invalid", "password": "wrong"}
                )
                
                assert response.status_code == status.HTTP_401_UNAUTHORIZED
    
    def test_create_user_admin_required(self):
        """Test that user creation requires admin role"""
        response = self.client.post(
            "/auth/users",
            headers=self.viewer_headers,
            json={
                "username": "newuser",
                "password": "NewPass123!",
                "roles": ["viewer"]
            }
        )
        
        assert response.status_code == status.HTTP_403_FORBIDDEN
    
    def test_create_user_admin_success(self):
        """Test successful user creation by admin"""
        with patch('src.auth.get_user') as mock_get_user:
            with patch('src.auth.create_user') as mock_create_user:
                mock_get_user.return_value = None  # User doesn't exist
                mock_create_user.return_value = True
                
                response = self.client.post(
                    "/auth/users",
                    headers=self.admin_headers,
                    json={
                        "username": "newuser",
                        "password": "NewPass123!",
                        "roles": ["viewer"]
                    }
                )
                
                assert response.status_code == status.HTTP_200_OK
                assert response.json()["message"] == "User created successfully"
    
    def test_generate_api_key_admin_required(self):
        """Test that API key generation requires admin role"""
        response = self.client.post(
            "/auth/api-key",
            headers=self.viewer_headers,
            json={"username": "admin"}
        )
        
        assert response.status_code == status.HTTP_403_FORBIDDEN
    
    def test_list_users_admin_required(self):
        """Test that listing users requires admin role"""
        response = self.client.get("/auth/users", headers=self.viewer_headers)
        assert response.status_code == status.HTTP_403_FORBIDDEN
        
        response = self.client.get("/auth/users", headers=self.admin_headers)
        assert response.status_code == status.HTTP_200_OK

    # =================== PUBLIC ENDPOINTS TESTS ===================
    
    def test_root_endpoint(self):
        """Test root endpoint"""
        response = self.client.get("/")
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert "message" in data
        assert "nginx-waf-ai" in data["message"].lower()
    
    def test_health_endpoint_public(self):
        """Test public health endpoint"""
        response = self.client.get("/health")
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert "status" in data
        assert "components" in data
    
    def test_metrics_endpoint_requires_auth(self):
        """Test that metrics endpoint requires authentication"""
        response = self.client.get("/metrics")
        assert response.status_code == status.HTTP_401_UNAUTHORIZED
        
        response = self.client.get("/metrics", headers=self.viewer_headers)
        assert response.status_code == status.HTTP_200_OK

    # =================== SYSTEM STATUS TESTS ===================
    
    def test_system_status_requires_viewer(self):
        """Test that system status requires viewer role or higher"""
        response = self.client.get("/api/status")
        assert response.status_code == status.HTTP_401_UNAUTHORIZED
        
        response = self.client.get("/api/status", headers=self.viewer_headers)
        assert response.status_code == status.HTTP_200_OK
    
    def test_debug_status_requires_operator(self):
        """Test that debug status requires operator role or higher"""
        response = self.client.get("/api/debug/status", headers=self.viewer_headers)
        assert response.status_code == status.HTTP_403_FORBIDDEN
        
        response = self.client.get("/api/debug/status", headers=self.operator_headers)
        assert response.status_code == status.HTTP_200_OK
    
    def test_system_health_detailed(self):
        """Test detailed system health endpoint"""
        response = self.client.get("/api/health", headers=self.viewer_headers)
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert "system_status" in data
        assert "health_score" in data
        assert "components" in data

    # =================== NODE MANAGEMENT TESTS ===================
    
    def test_add_node_requires_admin(self):
        """Test that adding nodes requires admin role"""
        response = self.client.post(
            "/api/nodes/add",
            headers=self.operator_headers,
            json=self.test_node_data
        )
        assert response.status_code == status.HTTP_403_FORBIDDEN
    
    def test_add_node_admin_success(self):
        """Test successful node addition by admin"""
        with patch('src.nginx_manager.NginxManager') as mock_manager:
            mock_instance = Mock()
            mock_manager.return_value = mock_instance
            mock_instance.add_node.return_value = True
            
            response = self.client.post(
                "/api/nodes/add",
                headers=self.admin_headers,
                json=self.test_node_data
            )
            
            assert response.status_code == status.HTTP_200_OK
            assert response.json()["message"] == "Node added successfully"
    
    def test_list_nodes_viewer_access(self):
        """Test that viewers can list nodes"""
        response = self.client.get("/api/nodes", headers=self.viewer_headers)
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert "nodes" in data
        assert "total_nodes" in data
    
    def test_node_cluster_status(self):
        """Test cluster status endpoint"""
        response = self.client.get("/api/nodes/status", headers=self.viewer_headers)
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert "cluster_status" in data

    # =================== ML TRAINING TESTS ===================
    
    def test_training_requires_operator(self):
        """Test that training requires operator role or higher"""
        response = self.client.post(
            "/api/training/start",
            headers=self.viewer_headers,
            json=self.test_training_data
        )
        assert response.status_code == status.HTTP_403_FORBIDDEN
    
    def test_training_operator_success(self):
        """Test successful training by operator"""
        with patch('src.ml_engine.MLEngine') as mock_engine:
            mock_instance = Mock()
            mock_engine.return_value = mock_instance
            mock_instance.train.return_value = True
            mock_instance.is_trained = True
            
            response = self.client.post(
                "/api/training/start",
                headers=self.operator_headers,
                json=self.test_training_data
            )
            
            assert response.status_code == status.HTTP_200_OK
            assert "training completed" in response.json()["message"].lower()
    
    def test_ml_prediction_testing(self):
        """Test ML prediction testing endpoint"""
        with patch('src.ml_engine.MLEngine') as mock_engine:
            mock_instance = Mock()
            mock_engine.return_value = mock_instance
            mock_instance.is_trained = True
            mock_instance.predict_threats.return_value = [
                ThreatPrediction(
                    threat_score=-0.8,
                    threat_type="sql_injection",
                    confidence=0.9,
                    features_used=["url_length", "contains_sql_patterns"]
                )
            ]
            
            response = self.client.post(
                "/api/debug/test-prediction",
                headers=self.operator_headers
            )
            
            assert response.status_code == status.HTTP_200_OK
            data = response.json()
            assert "predictions" in data

    # =================== TRAFFIC COLLECTION TESTS ===================
    
    def test_start_traffic_collection_operator_required(self):
        """Test that traffic collection requires operator role"""
        response = self.client.post(
            "/api/traffic/start-collection",
            headers=self.viewer_headers,
            json=["http://localhost:8081"]
        )
        assert response.status_code == status.HTTP_403_FORBIDDEN
    
    def test_start_traffic_collection_success(self):
        """Test successful traffic collection start"""
        with patch('src.traffic_collector.TrafficCollector') as mock_collector:
            mock_instance = Mock()
            mock_collector.return_value = mock_instance
            mock_instance.start_collection = AsyncMock()
            
            response = self.client.post(
                "/api/traffic/start-collection",
                headers=self.operator_headers,
                json=["http://localhost:8081", "http://localhost:8082"]
            )
            
            assert response.status_code == status.HTTP_200_OK
    
    def test_traffic_stats(self):
        """Test traffic statistics endpoint"""
        response = self.client.get("/api/traffic/stats", headers=self.viewer_headers)
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert "total_requests" in data

    # =================== REAL-TIME PROCESSING TESTS ===================
    
    def test_start_processing_operator_required(self):
        """Test that starting processing requires operator role"""
        response = self.client.post("/api/processing/start", headers=self.viewer_headers)
        assert response.status_code == status.HTTP_403_FORBIDDEN
    
    def test_start_processing_success(self):
        """Test successful processing start"""
        with patch('src.ml_engine.MLEngine') as mock_engine:
            mock_instance = Mock()
            mock_engine.return_value = mock_instance
            mock_instance.is_trained = True
            
            response = self.client.post("/api/processing/start", headers=self.operator_headers)
            assert response.status_code == status.HTTP_200_OK
    
    def test_stop_processing_operator_required(self):
        """Test that stopping processing requires operator role"""
        response = self.client.post("/api/processing/stop", headers=self.viewer_headers)
        assert response.status_code == status.HTTP_403_FORBIDDEN
    
    def test_stop_processing_success(self):
        """Test successful processing stop"""
        # First start processing
        with patch('src.main.system_state', {'is_processing': True}):
            response = self.client.post("/api/processing/stop", headers=self.operator_headers)
            assert response.status_code == status.HTTP_200_OK

    # =================== WAF RULES TESTS ===================
    
    def test_get_rules_viewer_access(self):
        """Test that viewers can access rules"""
        response = self.client.get("/api/rules", headers=self.viewer_headers)
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert "rules" in data
    
    def test_deploy_rules_admin_required(self):
        """Test that rule deployment requires admin role"""
        deploy_data = {
            "node_ids": ["test-node-1"],
            "force_deployment": False
        }
        
        response = self.client.post(
            "/api/rules/deploy",
            headers=self.operator_headers,
            json=deploy_data
        )
        assert response.status_code == status.HTTP_403_FORBIDDEN
    
    def test_deploy_rules_admin_success(self):
        """Test successful rule deployment by admin"""
        with patch('src.waf_rule_generator.WAFRuleGenerator') as mock_generator:
            with patch('src.nginx_manager.NginxManager') as mock_manager:
                mock_gen_instance = Mock()
                mock_mgr_instance = Mock()
                mock_generator.return_value = mock_gen_instance
                mock_manager.return_value = mock_mgr_instance
                
                mock_gen_instance.get_active_rules.return_value = []
                mock_mgr_instance.deploy_rules = AsyncMock(return_value=[])
                
                deploy_data = {
                    "node_ids": ["test-node-1"],
                    "force_deployment": False
                }
                
                response = self.client.post(
                    "/api/rules/deploy",
                    headers=self.admin_headers,
                    json=deploy_data
                )
                
                assert response.status_code == status.HTTP_200_OK

    # =================== THREATS TESTS ===================
    
    def test_get_threats_viewer_access(self):
        """Test that viewers can access threat data"""
        response = self.client.get("/api/threats", headers=self.viewer_headers)
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert "threats" in data
        assert "total_threats" in data

    # =================== CONFIGURATION TESTS ===================
    
    def test_nginx_config_operator_required(self):
        """Test that nginx config requires operator role"""
        response = self.client.get("/api/config/nginx", headers=self.viewer_headers)
        assert response.status_code == status.HTTP_403_FORBIDDEN
    
    def test_nginx_config_generation(self):
        """Test nginx configuration generation"""
        with patch('src.waf_rule_generator.WAFRuleGenerator') as mock_generator:
            mock_instance = Mock()
            mock_generator.return_value = mock_instance
            mock_instance.generate_nginx_config.return_value = "# nginx config"
            
            response = self.client.get("/api/config/nginx", headers=self.operator_headers)
            assert response.status_code == status.HTTP_200_OK

    # =================== SECURITY TESTS ===================
    
    def test_security_stats_admin_required(self):
        """Test that security stats require admin role"""
        response = self.client.get("/api/security/stats", headers=self.operator_headers)
        assert response.status_code == status.HTTP_403_FORBIDDEN
    
    def test_security_stats_admin_success(self):
        """Test security stats access by admin"""
        response = self.client.get("/api/security/stats", headers=self.admin_headers)
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert "timestamp" in data
        assert "system_security" in data
    
    def test_unblock_ip_admin_required(self):
        """Test that IP unblocking requires admin role"""
        response = self.client.post(
            "/api/security/unblock-ip",
            headers=self.operator_headers,
            params={"ip_address": "192.168.1.100"}
        )
        assert response.status_code == status.HTTP_403_FORBIDDEN
    
    def test_emergency_shutdown_admin_required(self):
        """Test that emergency shutdown requires admin role"""
        response = self.client.post("/api/security/emergency-shutdown", headers=self.operator_headers)
        assert response.status_code == status.HTTP_403_FORBIDDEN

    # =================== SYSTEM STATISTICS TESTS ===================
    
    def test_system_stats_viewer_access(self):
        """Test that viewers can access system statistics"""
        response = self.client.get("/api/stats", headers=self.viewer_headers)
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert "timestamp" in data
        assert "components" in data
        assert "traffic" in data
        assert "threats" in data
        assert "rules" in data

    # =================== ERROR HANDLING TESTS ===================
    
    def test_unauthorized_access(self):
        """Test unauthorized access to protected endpoints"""
        protected_endpoints = [
            ("GET", "/api/status"),
            ("GET", "/api/nodes"),
            ("POST", "/api/training/start"),
            ("GET", "/api/rules"),
            ("GET", "/api/threats")
        ]
        
        for method, endpoint in protected_endpoints:
            if method == "GET":
                response = self.client.get(endpoint)
            else:
                response = self.client.post(endpoint, json={})
            
            assert response.status_code == status.HTTP_401_UNAUTHORIZED
    
    def test_invalid_json_payload(self):
        """Test handling of invalid JSON payloads"""
        # Test with malformed JSON
        response = self.client.post(
            "/auth/login",
            data="invalid json",
            headers={"Content-Type": "application/json"}
        )
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY
    
    def test_missing_required_fields(self):
        """Test handling of missing required fields"""
        # Test login without password
        response = self.client.post(
            "/auth/login",
            json={"username": "admin"}
        )
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY
    
    def test_rate_limiting_simulation(self):
        """Test rate limiting behavior (simulated)"""
        # This would require actual rate limiting to be configured
        # For now, just test that the endpoints respond correctly
        for _ in range(5):
            response = self.client.get("/health")
            assert response.status_code == status.HTTP_200_OK

    # =================== INTEGRATION WORKFLOW TESTS ===================
    
    def test_complete_workflow_simulation(self):
        """Test a complete workflow from training to deployment"""
        with patch('src.ml_engine.MLEngine') as mock_engine:
            with patch('src.traffic_collector.TrafficCollector') as mock_collector:
                with patch('src.waf_rule_generator.WAFRuleGenerator') as mock_generator:
                    with patch('src.nginx_manager.NginxManager') as mock_manager:
                        # Setup mocks
                        mock_engine_instance = Mock()
                        mock_collector_instance = Mock()
                        mock_generator_instance = Mock()
                        mock_manager_instance = Mock()
                        
                        mock_engine.return_value = mock_engine_instance
                        mock_collector.return_value = mock_collector_instance
                        mock_generator.return_value = mock_generator_instance
                        mock_manager.return_value = mock_manager_instance
                        
                        mock_engine_instance.is_trained = True
                        mock_engine_instance.train.return_value = True
                        mock_collector_instance.start_collection = AsyncMock()
                        mock_generator_instance.get_active_rules.return_value = []
                        mock_manager_instance.add_node.return_value = True
                        mock_manager_instance.deploy_rules = AsyncMock(return_value=[])
                        
                        # 1. Add a node (admin required)
                        response = self.client.post(
                            "/api/nodes/add",
                            headers=self.admin_headers,
                            json=self.test_node_data
                        )
                        assert response.status_code == status.HTTP_200_OK
                        
                        # 2. Train the model (operator can do this)
                        response = self.client.post(
                            "/api/training/start",
                            headers=self.operator_headers,
                            json=self.test_training_data
                        )
                        assert response.status_code == status.HTTP_200_OK
                        
                        # 3. Start traffic collection (operator can do this)
                        response = self.client.post(
                            "/api/traffic/start-collection",
                            headers=self.operator_headers,
                            json=["http://localhost:8081"]
                        )
                        assert response.status_code == status.HTTP_200_OK
                        
                        # 4. Start real-time processing (operator can do this)
                        response = self.client.post(
                            "/api/processing/start",
                            headers=self.operator_headers
                        )
                        assert response.status_code == status.HTTP_200_OK
                        
                        # 5. Check system status (viewer can do this)
                        response = self.client.get("/api/stats", headers=self.viewer_headers)
                        assert response.status_code == status.HTTP_200_OK
                        
                        # 6. Deploy rules (admin required)
                        response = self.client.post(
                            "/api/rules/deploy",
                            headers=self.admin_headers,
                            json={"node_ids": ["test-node-1"], "force_deployment": False}
                        )
                        assert response.status_code == status.HTTP_200_OK
