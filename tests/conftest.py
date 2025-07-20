#!/usr/bin/env python3
"""
Minimal test configuration and fixtures for the Nginx WAF AI test suite.
"""

import pytest
import os
import tempfile
import json
from typing import Dict, List, Any
from unittest.mock import Mock, MagicMock

# Basic test configuration
@pytest.fixture
def test_config():
    """Basic test configuration"""
    return {
        'api_host': '127.0.0.1',
        'api_port': 8000,
        'api_debug': True,
        'redis_url': 'redis://localhost:6379'
    }

# Temporary directory for test files
@pytest.fixture
def temp_dir():
    """Temporary directory for test files"""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield tmpdir

# Sample data fixtures
@pytest.fixture
def sample_traffic_data():
    """Sample traffic data for testing"""
    return [
        {
            'timestamp': '2024-01-01T10:00:00Z',
            'ip': '192.168.1.100',
            'method': 'GET',
            'url': '/api/users',
            'user_agent': 'Mozilla/5.0',
            'status_code': 200,
            'response_size': 1024
        },
        {
            'timestamp': '2024-01-01T10:01:00Z',
            'ip': '192.168.1.101',
            'method': 'POST',
            'url': '/api/login',
            'user_agent': 'curl/7.68.0',
            'status_code': 401,
            'response_size': 256
        }
    ]

@pytest.fixture
def sample_threats():
    """Sample threat data for testing"""
    return [
        {
            'timestamp': '2024-01-01T10:00:00Z',
            'ip': '10.0.0.1',
            'threat_type': 'sql_injection',
            'confidence': 0.95,
            'details': {'pattern': 'UNION SELECT', 'url': '/search?q=\' OR 1=1'}
        },
        {
            'timestamp': '2024-01-01T10:01:00Z',
            'ip': '10.0.0.2',
            'threat_type': 'brute_force',
            'confidence': 0.88,
            'details': {'attempts': 25, 'url': '/login'}
        }
    ]

@pytest.fixture
def mock_redis():
    """Mock Redis client"""
    mock = MagicMock()
    mock.ping.return_value = True
    mock.get.return_value = None
    mock.set.return_value = True
    mock.delete.return_value = 1
    return mock

@pytest.fixture
def mock_ssh_client():
    """Mock SSH client for testing nginx manager"""
    mock = MagicMock()
    mock.connect.return_value = None
    mock.exec_command.return_value = (MagicMock(), MagicMock(), MagicMock())
    return mock

# Test users and authentication
@pytest.fixture
def test_users():
    """Sample test users"""
    return [
        {
            'username': 'admin',
            'email': 'admin@example.com',
            'password': 'admin123',
            'role': 'admin',
            'is_active': True
        },
        {
            'username': 'user',
            'email': 'user@example.com', 
            'password': 'user123',
            'role': 'user',
            'is_active': True
        },
        {
            'username': 'viewer',
            'email': 'viewer@example.com',
            'password': 'viewer123', 
            'role': 'viewer',
            'is_active': True
        }
    ]

@pytest.fixture
def admin_token():
    """Admin JWT token for testing"""
    try:
        from src.auth import create_access_token
        return create_access_token(
            data={'sub': 'admin', 'role': 'admin'}
        )
    except ImportError:
        return 'mock-admin-token'

@pytest.fixture
def user_token():
    """Regular user JWT token for testing"""
    try:
        from src.auth import create_access_token
        return create_access_token(
            data={'sub': 'user', 'role': 'user'}
        )
    except ImportError:
        return 'mock-user-token'

# HTTP client fixtures
@pytest.fixture
def api_client():
    """HTTP client for API testing"""
    try:
        import httpx
        return httpx.Client(base_url="http://localhost:8000")
    except ImportError:
        return MagicMock()

@pytest.fixture
def async_api_client():
    """Async HTTP client for API testing"""
    try:
        import httpx
        return httpx.AsyncClient(base_url="http://localhost:8000")
    except ImportError:
        return MagicMock()

# Test data directories
@pytest.fixture(scope="session")
def test_data_dir():
    """Directory containing test data files"""
    return os.path.join(os.path.dirname(__file__), '..', 'data')

# Sample WAF rules
@pytest.fixture
def sample_waf_rules():
    """Sample WAF rules for testing"""
    return [
        {
            'id': 'rule_001',
            'name': 'Block SQL Injection',
            'description': 'Block common SQL injection patterns',
            'pattern': r'(\bUNION\b|\bSELECT\b|\bDROP\b).*(\bFROM\b|\bWHERE\b)',
            'action': 'block',
            'priority': 100,
            'enabled': True
        },
        {
            'id': 'rule_002', 
            'name': 'Rate Limit',
            'description': 'Rate limit requests from same IP',
            'pattern': 'ip_rate_limit',
            'action': 'rate_limit',
            'priority': 50,
            'enabled': True,
            'rate_limit': {'requests': 100, 'window': 60}
        }
    ]

# Environment setup
@pytest.fixture(autouse=True)
def setup_test_env():
    """Setup test environment variables"""
    original_env = os.environ.copy()
    
    # Set test environment variables
    os.environ['PYTEST_CURRENT_TEST'] = 'true'
    os.environ['WAF_API_DEBUG'] = 'true'
    os.environ['WAF_JWT_SECRET'] = 'test-secret-key-for-testing-only'
    
    yield
    
    # Restore original environment
    os.environ.clear()
    os.environ.update(original_env)

# Skip decorators for integration tests
def skip_if_no_redis():
    """Skip test if Redis is not available"""
    try:
        import redis
        r = redis.Redis(host='localhost', port=6379, decode_responses=True)
        r.ping()
        return pytest.mark.skipif(False, reason="Redis available")
    except:
        return pytest.mark.skipif(True, reason="Redis not available")

def skip_if_no_docker():
    """Skip test if Docker is not available"""
    try:
        import docker
        client = docker.from_env()
        client.ping()
        return pytest.mark.skipif(False, reason="Docker available")
    except:
        return pytest.mark.skipif(True, reason="Docker not available")
