#!/usr/bin/env python3
"""
Test configuration and fixtures for the Nginx WAF AI test suite.

This module provides common test configurations, fixtures, and utilities
used across multiple test modules.
"""

import pytest
import os
import tempfile
import json
import asyncio
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from unittest.mock import Mock, patch

# Import project modules
from src.config import Config
from src.ml_engine import MLEngine, ThreatPrediction
from src.traffic_collector import TrafficCollector, HttpRequest
from src.waf_rule_generator import WAFRuleGenerator, WAFRule, RuleType, RuleAction
from src.nginx_manager import NginxManager, NginxNode
from src.auth import create_access_token


# Test data constants
TEST_BASE_URL = "http://localhost:8000"
TEST_ADMIN_USER = {"username": "admin", "password": "admin123"}
TEST_OPERATOR_USER = {"username": "operator", "password": "Operator123!"}
TEST_VIEWER_USER = {"username": "viewer", "password": "Viewer123!"}


@pytest.fixture(scope="session")
def event_loop():
    """Create an instance of the default event loop for the test session."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest.fixture
def temp_dir():
    """Create a temporary directory for test files"""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield tmpdir


@pytest.fixture
def test_config():
    """Create a test configuration"""
    config = Config()
    config.api_host = "localhost"
    config.api_port = 8000
    config.api_debug = True
    config.log_level = "DEBUG"
    return config


@pytest.fixture
def mock_ml_engine():
    """Create a mock ML engine for testing"""
    engine = Mock(spec=MLEngine)
    engine.is_trained = True
    engine.model_path = "/tmp/test_model.joblib"
    
    # Mock training method
    engine.train.return_value = True
    
    # Mock prediction method
    engine.predict_threats.return_value = [
        ThreatPrediction(
            threat_score=-0.8,
            threat_type="sql_injection",
            confidence=0.9,
            features_used=["url_contains_sql", "suspicious_patterns"]
        ),
        ThreatPrediction(
            threat_score=-0.6,
            threat_type="xss_attack",
            confidence=0.8,
            features_used=["url_contains_script"]
        )
    ]
    
    return engine


@pytest.fixture
def mock_traffic_collector():
    """Create a mock traffic collector for testing"""
    collector = Mock(spec=TrafficCollector)
    collector.is_collecting = False
    collector.collected_requests = []
    
    # Mock HTTP requests
    sample_requests = [
        HttpRequest(
            timestamp=datetime.now(),
            method="GET",
            url="/admin/login?user=admin' OR 1=1--",
            headers={"User-Agent": "Mozilla/5.0"},
            body=None,
            source_ip="192.168.1.100",
            user_agent="Mozilla/5.0",
            content_length=0
        ),
        HttpRequest(
            timestamp=datetime.now(),
            method="GET",
            url="/search?q=<script>alert('xss')</script>",
            headers={"User-Agent": "Mozilla/5.0"},
            body=None,
            source_ip="192.168.1.101",
            user_agent="Mozilla/5.0",
            content_length=0
        )
    ]
    
    collector.get_recent_requests.return_value = sample_requests
    collector.extract_features.return_value = {
        "url_length": 30,
        "body_length": 0,
        "headers_count": 1,
        "contains_sql_patterns": True,
        "contains_xss_patterns": False,
        "method": "GET"
    }
    
    return collector


@pytest.fixture
def mock_waf_rule_generator():
    """Create a mock WAF rule generator for testing"""
    generator = Mock(spec=WAFRuleGenerator)
    
    # Mock rules
    sample_rules = [
        WAFRule(
            rule_id="test-rule-1",
            rule_type=RuleType.URL_PATTERN,
            pattern=".*admin.*",
            action=RuleAction.BLOCK,
            priority=90,
            description="Block admin access"
        ),
        WAFRule(
            rule_id="test-rule-2",
            rule_type=RuleType.IP_BLOCK,
            pattern="192.168.1.100",
            action=RuleAction.BLOCK,
            priority=95,
            description="Block malicious IP"
        )
    ]
    
    generator.get_active_rules.return_value = sample_rules
    generator.generate_rules_from_threats.return_value = sample_rules
    generator.generate_nginx_config.return_value = "# Test nginx config\nlocation ~ /admin { deny all; }"
    
    return generator


@pytest.fixture
def mock_nginx_manager():
    """Create a mock nginx manager for testing"""
    manager = Mock(spec=NginxManager)
    
    # Mock nodes
    sample_nodes = [
        NginxNode(
            node_id="test-node-1",
            hostname="web-1.example.com",
            ssh_host="192.168.1.10",
            ssh_port=22,
            ssh_username="nginx",
            ssh_key_path="/home/nginx/.ssh/id_rsa",
            nginx_config_path="/etc/nginx/conf.d",
            nginx_reload_command="sudo systemctl reload nginx",
            api_endpoint="http://192.168.1.10:8080"
        )
    ]
    
    manager.nodes = sample_nodes
    manager.list_nodes.return_value = sample_nodes
    manager.get_node.return_value = sample_nodes[0]
    manager.add_node.return_value = True
    
    return manager


@pytest.fixture
def test_tokens():
    """Create test JWT tokens for different user roles"""
    admin_token = create_access_token(data={"sub": "admin", "roles": ["admin"]})
    operator_token = create_access_token(data={"sub": "operator", "roles": ["operator"]})
    viewer_token = create_access_token(data={"sub": "viewer", "roles": ["viewer"]})
    
    return {
        "admin": admin_token,
        "operator": operator_token,
        "viewer": viewer_token
    }


@pytest.fixture
def test_headers(test_tokens):
    """Create test headers with authorization tokens"""
    return {
        "admin": {"Authorization": f"Bearer {test_tokens['admin']}"},
        "operator": {"Authorization": f"Bearer {test_tokens['operator']}"},
        "viewer": {"Authorization": f"Bearer {test_tokens['viewer']}"}
    }


@pytest.fixture
def sample_training_data():
    """Create sample training data for ML tests"""
    return {
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
            },
            {
                "timestamp": "2024-01-01T00:02:00Z",
                "url": "/normal/page",
                "source_ip": "192.168.1.102",
                "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X)",
                "url_length": 12,
                "body_length": 0,
                "headers_count": 5,
                "content_length": 0,
                "has_suspicious_headers": False,
                "contains_sql_patterns": False,
                "contains_xss_patterns": False,
                "method": "GET"
            }
        ],
        "labels": ["sql_injection", "xss_attack", "normal"]
    }


@pytest.fixture
def sample_node_data():
    """Create sample nginx node data"""
    return {
        "node_id": "test-node-api",
        "hostname": "test.example.com",
        "ssh_host": "192.168.1.100",
        "ssh_port": 22,
        "ssh_username": "nginx",
        "ssh_key_path": "/home/nginx/.ssh/id_rsa",
        "nginx_config_path": "/etc/nginx/conf.d",
        "nginx_reload_command": "sudo systemctl reload nginx",
        "api_endpoint": "http://192.168.1.100:8080"
    }


@pytest.fixture
def sample_threat_predictions():
    """Create sample threat predictions"""
    return [
        ThreatPrediction(
            threat_score=-0.9,
            threat_type="sql_injection",
            confidence=0.95,
            features_used=["url_contains_sql", "suspicious_patterns"],
            source_ip="192.168.1.100",
            url="/admin/login?id=1' OR 1=1--",
            user_agent="Mozilla/5.0 (X11; Linux x86_64)"
        ),
        ThreatPrediction(
            threat_score=-0.8,
            threat_type="xss_attack",
            confidence=0.9,
            features_used=["url_contains_script"],
            source_ip="192.168.1.101",
            url="/search?q=<script>alert('test')</script>",
            user_agent="Mozilla/5.0 (Windows NT 10.0)"
        ),
        ThreatPrediction(
            threat_score=-0.7,
            threat_type="brute_force",
            confidence=0.85,
            features_used=["repeated_requests", "failed_auth"],
            source_ip="192.168.1.102",
            url="/login",
            user_agent="Python/3.8"
        )
    ]


@pytest.fixture
def sample_waf_rules():
    """Create sample WAF rules"""
    return [
        WAFRule(
            rule_id="sql-injection-block",
            rule_type=RuleType.URL_PATTERN,
            pattern=".*('|(union)|(select)|(insert)|(drop)).*",
            action=RuleAction.BLOCK,
            priority=95,
            description="Block SQL injection attempts",
            created_at=datetime.now(),
            expires_at=datetime.now() + timedelta(hours=24)
        ),
        WAFRule(
            rule_id="xss-block",
            rule_type=RuleType.URL_PATTERN,
            pattern=".*(script|iframe|object).*",
            action=RuleAction.BLOCK,
            priority=90,
            description="Block XSS attempts",
            created_at=datetime.now(),
            expires_at=datetime.now() + timedelta(hours=24)
        ),
        WAFRule(
            rule_id="ip-block-malicious",
            rule_type=RuleType.IP_BLOCK,
            pattern="192.168.1.100",
            action=RuleAction.BLOCK,
            priority=99,
            description="Block known malicious IP",
            created_at=datetime.now(),
            expires_at=datetime.now() + timedelta(days=7)
        ),
        WAFRule(
            rule_id="rate-limit-api",
            rule_type=RuleType.RATE_LIMIT,
            pattern="/api/",
            action=RuleAction.RATE_LIMIT,
            priority=70,
            description="Rate limit API endpoints",
            created_at=datetime.now(),
            metadata={"rate": "10r/m", "burst": "20"}
        )
    ]


@pytest.fixture
def mock_file_system(temp_dir):
    """Create mock file system for testing"""
    # Create test directories
    config_dir = os.path.join(temp_dir, "config")
    models_dir = os.path.join(temp_dir, "models")
    logs_dir = os.path.join(temp_dir, "logs")
    
    os.makedirs(config_dir, exist_ok=True)
    os.makedirs(models_dir, exist_ok=True)
    os.makedirs(logs_dir, exist_ok=True)
    
    # Create test configuration files
    nginx_nodes_config = [
        {
            "node_id": "test-node-1",
            "hostname": "web-1.example.com",
            "ssh_host": "192.168.1.10",
            "ssh_port": 22,
            "ssh_username": "nginx",
            "ssh_key_path": "/home/nginx/.ssh/id_rsa",
            "nginx_config_path": "/etc/nginx/conf.d",
            "nginx_reload_command": "sudo systemctl reload nginx",
            "api_endpoint": "http://192.168.1.10:8080"
        }
    ]
    
    with open(os.path.join(config_dir, "nginx_nodes.json"), "w") as f:
        json.dump(nginx_nodes_config, f, indent=2)
    
    # Create test model file
    model_file = os.path.join(models_dir, "test_model.joblib")
    with open(model_file, "w") as f:
        f.write("# Mock model file")
    
    return {
        "temp_dir": temp_dir,
        "config_dir": config_dir,
        "models_dir": models_dir,
        "logs_dir": logs_dir,
        "nginx_nodes_config": os.path.join(config_dir, "nginx_nodes.json"),
        "model_file": model_file
    }


class TestDataGenerator:
    """Utility class for generating test data"""
    
    @staticmethod
    def generate_http_requests(count: int = 10, include_malicious: bool = True) -> List[HttpRequest]:
        """Generate HTTP requests for testing"""
        requests = []
        
        # Normal requests
        normal_urls = [
            "/",
            "/home",
            "/about",
            "/contact",
            "/products",
            "/services"
        ]
        
        # Malicious requests
        malicious_urls = [
            "/admin/login?user=admin' OR 1=1--",
            "/search?q=<script>alert('xss')</script>",
            "/api/users?id=1 UNION SELECT * FROM passwords",
            "/upload.php?file=../../etc/passwd",
            "/login.php?username=admin&password=' OR '1'='1"
        ]
        
        for i in range(count):
            if include_malicious and i % 3 == 0:
                url = malicious_urls[i % len(malicious_urls)]
            else:
                url = normal_urls[i % len(normal_urls)]
            
            request = HttpRequest(
                timestamp=datetime.now() - timedelta(minutes=i),
                method="GET",
                url=url,
                headers={"User-Agent": f"TestAgent/{i}"},
                body=None,
                source_ip=f"192.168.1.{100 + (i % 50)}",
                user_agent=f"TestAgent/{i}",
                content_length=0
            )
            
            requests.append(request)
        
        return requests
    
    @staticmethod
    def generate_threat_predictions(count: int = 5) -> List[ThreatPrediction]:
        """Generate threat predictions for testing"""
        threat_types = ["sql_injection", "xss_attack", "brute_force", "directory_traversal", "command_injection"]
        predictions = []
        
        for i in range(count):
            prediction = ThreatPrediction(
                threat_score=-0.5 - (i * 0.1),  # Varying threat scores
                threat_type=threat_types[i % len(threat_types)],
                confidence=0.7 + (i * 0.05),
                features_used=[f"feature_{j}" for j in range(3)],
                source_ip=f"192.168.1.{100 + i}",
                url=f"/test/path/{i}",
                user_agent=f"TestAgent/{i}"
            )
            predictions.append(prediction)
        
        return predictions


# Utility functions for tests
def assert_valid_response_time(response_time: float, max_time: float = 2.0):
    """Assert that response time is within acceptable limits"""
    assert response_time > 0, "Response time should be positive"
    assert response_time < max_time, f"Response time {response_time:.3f}s exceeds maximum {max_time}s"


def assert_valid_http_status(status_code: int, expected_codes: List[int] = None):
    """Assert that HTTP status code is valid"""
    if expected_codes is None:
        expected_codes = [200, 201, 202, 204]
    
    assert status_code in expected_codes, f"HTTP status {status_code} not in expected codes {expected_codes}"


def assert_valid_json_response(response_data: Dict[str, Any], required_keys: List[str] = None):
    """Assert that JSON response has required structure"""
    assert isinstance(response_data, dict), "Response should be a JSON object"
    
    if required_keys:
        for key in required_keys:
            assert key in response_data, f"Required key '{key}' missing from response"


def assert_security_headers_present(headers: Dict[str, str]):
    """Assert that security headers are present"""
    security_headers = [
        "X-Content-Type-Options",
        "X-Frame-Options", 
        "X-XSS-Protection"
    ]
    
    present_headers = [h for h in security_headers if h in headers]
    assert len(present_headers) > 0, f"No security headers found. Expected one of: {security_headers}"


# Test markers for categorizing tests
pytestmark = [
    pytest.mark.unit,  # Unit tests
    pytest.mark.integration,  # Integration tests
    pytest.mark.e2e,  # End-to-end tests
    pytest.mark.performance,  # Performance tests
    pytest.mark.security,  # Security tests
]


# Skip conditions for different test environments
skip_if_no_docker = pytest.mark.skipif(
    os.system("docker --version") != 0,
    reason="Docker not available"
)

skip_if_no_api = pytest.mark.skipif(
    os.environ.get("SKIP_API_TESTS", "false").lower() == "true",
    reason="API tests disabled"
)

skip_if_no_ml = pytest.mark.skipif(
    os.environ.get("SKIP_ML_TESTS", "false").lower() == "true",
    reason="ML tests disabled"
)

skip_performance_tests = pytest.mark.skipif(
    os.environ.get("SKIP_PERFORMANCE_TESTS", "false").lower() == "true",
    reason="Performance tests disabled"
)
