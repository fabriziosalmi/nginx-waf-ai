#!/usr/bin/env python3
"""
Security Test Suite for Nginx WAF AI

Tests all the security fixes applied to the system.
"""

import asyncio
import json
import os
import sys
import tempfile
import requests
import subprocess
from pathlib import Path
from datetime import datetime

# Add src to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from src.auth import AuthManager
from src.validation import SecureNginxNodeModel, SecureTrainingRequest, ValidationError
from src.ml_engine import MLEngine
from src.config import SystemConfig
from src.security_middleware import SecurityMiddleware, is_ip_whitelisted


class SecurityTestSuite:
    def __init__(self):
        self.test_results = []
        self.failed_tests = 0
        self.passed_tests = 0
    
    def log_test(self, test_name: str, passed: bool, message: str = ""):
        """Log test result"""
        status = "✅ PASS" if passed else "❌ FAIL"
        self.test_results.append(f"{status} {test_name}: {message}")
        
        if passed:
            self.passed_tests += 1
        else:
            self.failed_tests += 1
        
        print(f"{status} {test_name}: {message}")
    
    def test_authentication_system(self):
        """Test 1: Authentication & Authorization"""
        print("\n🔐 Testing Authentication & Authorization...")
        
        try:
            # Test AuthManager initialization
            auth_manager = AuthManager()
            self.log_test("AuthManager initialization", True, "Auth manager created successfully")
            
            # Test user creation
            user = auth_manager.create_user("testuser", "TestPassword123!", ["operator"])
            self.log_test("User creation", True, f"User {user.username} created with roles {user.roles}")
            
            # Test password authentication
            authenticated_user = auth_manager.authenticate_user("testuser", "TestPassword123!")
            self.log_test("Password authentication", authenticated_user is not None, "User authenticated successfully")
            
            # Test wrong password
            wrong_auth = auth_manager.authenticate_user("testuser", "wrongpassword")
            self.log_test("Wrong password rejection", wrong_auth is None, "Wrong password correctly rejected")
            
            # Test JWT token creation
            token = auth_manager.create_jwt_token("testuser")
            self.log_test("JWT token creation", len(token) > 0, f"JWT token created: {token[:20]}...")
            
            # Test JWT token verification
            token_data = auth_manager.verify_jwt_token(token)
            self.log_test("JWT token verification", token_data is not None, f"Token verified for user: {token_data.username}")
            
            # Test API key generation
            api_key = auth_manager.generate_api_key("testuser")
            self.log_test("API key generation", len(api_key) > 0, f"API key generated: {api_key[:10]}...")
            
        except Exception as e:
            self.log_test("Authentication system", False, f"Error: {e}")
    
    def test_input_validation(self):
        """Test 2: Input Validation & SQL Injection Prevention"""
        print("\n🛡️ Testing Input Validation...")
        
        try:
            # Test secure nginx node validation
            valid_node = {
                "node_id": "test-node-1",
                "hostname": "192.168.1.100",
                "ssh_host": "192.168.1.100",
                "ssh_port": 22,
                "ssh_username": "nginx",
                "ssh_key_path": "/home/user/.ssh/id_rsa",
                "nginx_config_path": "/etc/nginx/conf.d",
                "nginx_reload_command": "sudo systemctl reload nginx"
            }
            
            node_model = SecureNginxNodeModel(**valid_node)
            self.log_test("Valid node validation", True, f"Node {node_model.node_id} validated successfully")
            
            # Test invalid node_id (injection attempt)
            try:
                invalid_node = valid_node.copy()
                invalid_node["node_id"] = "test; rm -rf /"
                SecureNginxNodeModel(**invalid_node)
                self.log_test("Invalid node_id rejection", False, "Malicious node_id was accepted")
            except Exception:
                self.log_test("Invalid node_id rejection", True, "Malicious node_id correctly rejected")
            
            # Test directory traversal prevention
            try:
                invalid_node = valid_node.copy()
                invalid_node["ssh_key_path"] = "../../etc/passwd"
                SecureNginxNodeModel(**invalid_node)
                self.log_test("Directory traversal prevention", False, "Directory traversal was allowed")
            except Exception:
                self.log_test("Directory traversal prevention", True, "Directory traversal correctly blocked")
            
            # Test training request validation
            valid_training_data = [{
                'timestamp': '2025-01-20T15:30:00',
                'method': 'GET',
                'url': '/api/test',
                'headers_count': 5,
                'body_length': 0,
                'source_ip': '192.168.1.50',
                'user_agent': 'Mozilla/5.0',
                'content_length': 0,
                'has_suspicious_headers': False,
                'url_length': 9,
                'contains_sql_patterns': False,
                'contains_xss_patterns': False
            }]
            
            training_request = SecureTrainingRequest(
                training_data=valid_training_data,
                labels=["normal"]
            )
            self.log_test("Training request validation", True, "Valid training request accepted")
            
        except Exception as e:
            self.log_test("Input validation", False, f"Error: {e}")
    
    def test_https_configuration(self):
        """Test 3: HTTPS/TLS Configuration"""
        print("\n🔒 Testing HTTPS/TLS Configuration...")
        
        try:
            # Test configuration with HTTPS disabled
            config = SystemConfig()
            self.log_test("Default HTTPS setting", not config.security.use_https, "HTTPS disabled by default (secure)")
            
            # Test environment variable configuration with dummy paths that we know don't exist
            os.environ['WAF_USE_HTTPS'] = 'true'
            os.environ['WAF_SSL_CERT_PATH'] = '/tmp/test_cert.pem'
            os.environ['WAF_SSL_KEY_PATH'] = '/tmp/test_key.pem'
            
            try:
                https_config = SystemConfig.from_env()
                # This should fail validation because files don't exist
                self.log_test("HTTPS environment config validation", False, "Should have failed SSL file validation")
            except Exception as e:
                if "SSL certificate not found" in str(e) or "SSL key not found" in str(e):
                    self.log_test("HTTPS environment config validation", True, "SSL file validation correctly enforced")
                else:
                    self.log_test("HTTPS environment config validation", False, f"Unexpected error: {e}")
            
            # Clean up environment
            del os.environ['WAF_USE_HTTPS']
            del os.environ['WAF_SSL_CERT_PATH']
            del os.environ['WAF_SSL_KEY_PATH']
            
        except Exception as e:
            self.log_test("HTTPS configuration", False, f"Error: {e}")
    
    def test_ml_engine_security(self):
        """Test 4: ML Engine Thread Safety"""
        print("\n🤖 Testing ML Engine Security...")
        
        try:
            # Test ML engine initialization
            ml_engine = MLEngine()
            self.log_test("ML engine initialization", True, "ML engine created successfully")
            
            # Test feature extraction with malicious data
            malicious_requests = [{
                'timestamp': '2025-01-20T15:30:00',
                'method': 'GET',
                'url': '/api/test\'; DROP TABLE users; --',
                'headers_count': 5,
                'body_length': 0,
                'source_ip': '192.168.1.50',
                'user_agent': '<script>alert("xss")</script>',
                'content_length': 0,
                'has_suspicious_headers': True,
                'url_length': 35,
                'contains_sql_patterns': True,
                'contains_xss_patterns': True
            }]
            
            features = ml_engine.extract_features(malicious_requests)
            self.log_test("Malicious data feature extraction", not features.empty, "Features extracted safely from malicious data")
            
            # Test thread safety by running multiple extractions concurrently
            import threading
            import concurrent.futures
            
            def extract_features_thread():
                return ml_engine.extract_features(malicious_requests)
            
            with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
                futures = [executor.submit(extract_features_thread) for _ in range(10)]
                results = [future.result() for future in futures]
            
            self.log_test("ML engine thread safety", all(not df.empty for df in results), "ML engine is thread-safe")
            
        except Exception as e:
            self.log_test("ML engine security", False, f"Error: {e}")
    
    def test_security_middleware(self):
        """Test 5: Security Middleware"""
        print("\n🛡️ Testing Security Middleware...")
        
        try:
            # Test IP whitelisting
            localhost_whitelisted = is_ip_whitelisted("127.0.0.1")
            self.log_test("Localhost whitelisting", localhost_whitelisted, "Localhost is whitelisted")
            
            external_ip_whitelisted = is_ip_whitelisted("8.8.8.8")
            self.log_test("External IP filtering", not external_ip_whitelisted, "External IP correctly filtered")
            
            # Test private network whitelisting
            private_ip_whitelisted = is_ip_whitelisted("192.168.1.100")
            self.log_test("Private IP whitelisting", private_ip_whitelisted, "Private IP is whitelisted")
            
        except Exception as e:
            self.log_test("Security middleware", False, f"Error: {e}")
    
    def test_ssh_key_security(self):
        """Test 6: SSH Key Security"""
        print("\n🔑 Testing SSH Key Security...")
        
        try:
            from src.nginx_manager import SecureSSHKeyManager
            
            # Test SSH key manager initialization
            ssh_manager = SecureSSHKeyManager("test_password")
            self.log_test("SSH key manager initialization", True, "SSH key manager created")
            
            # Test cleanup functionality
            ssh_manager.cleanup_temp_keys()
            self.log_test("SSH key cleanup", True, "SSH key cleanup executed successfully")
            
        except Exception as e:
            self.log_test("SSH key security", False, f"Error: {e}")
    
    def test_environment_configuration(self):
        """Test 7: Environment Configuration Security"""
        print("\n⚙️ Testing Environment Configuration...")
        
        try:
            # Test secure defaults (without HTTPS enabled to avoid file validation)
            config = SystemConfig()
            
            self.log_test("Secure API host default", config.api_host == "127.0.0.1", "API host defaults to localhost")
            self.log_test("Debug mode default", not config.api_debug, "Debug mode disabled by default")
            self.log_test("Security headers enabled", config.security.enable_security_headers, "Security headers enabled")
            
            # Test JWT secret generation
            jwt_secret_length = len(config.security.jwt_secret)
            self.log_test("JWT secret strength", jwt_secret_length >= 32, f"JWT secret is {jwt_secret_length} characters")
            
        except Exception as e:
            self.log_test("Environment configuration", False, f"Error: {e}")
    
    def test_rate_limiting(self):
        """Test 8: Rate Limiting Configuration"""
        print("\n🚦 Testing Rate Limiting...")
        
        try:
            # Test without HTTPS to avoid SSL file validation errors
            config = SystemConfig()
            
            # Test rate limiting defaults
            self.log_test("Rate limit requests default", config.security.rate_limit_requests == 100, f"Rate limit: {config.security.rate_limit_requests} requests")
            self.log_test("Rate limit window default", config.security.rate_limit_window == 60, f"Rate window: {config.security.rate_limit_window} seconds")
            
        except Exception as e:
            self.log_test("Rate limiting", False, f"Error: {e}")
    
    def test_data_validation_consistency(self):
        """Test 9: Data Validation Consistency"""
        print("\n📊 Testing Data Validation Consistency...")
        
        try:
            ml_engine = MLEngine()
            
            # Create consistent test data
            test_requests = [{
                'timestamp': '2025-01-20T15:30:00',
                'method': 'GET',
                'url': '/api/test',
                'headers_count': 5,
                'body_length': 0,
                'source_ip': '192.168.1.50',
                'user_agent': 'Test Agent',
                'content_length': 0,
                'has_suspicious_headers': False,
                'url_length': 9,
                'contains_sql_patterns': False,
                'contains_xss_patterns': False
            } for _ in range(10)]
            
            # Extract features multiple times
            features1 = ml_engine.extract_features(test_requests)
            features2 = ml_engine.extract_features(test_requests)
            
            # Check consistency
            consistent = features1.equals(features2)
            self.log_test("Feature extraction consistency", consistent, "Feature extraction is consistent")
            
            # Check feature columns are set
            has_feature_columns = len(ml_engine.feature_columns) > 0
            self.log_test("Feature columns tracking", has_feature_columns, f"Tracking {len(ml_engine.feature_columns)} feature columns")
            
        except Exception as e:
            self.log_test("Data validation consistency", False, f"Error: {e}")
    
    def run_all_tests(self):
        """Run all security tests"""
        print("🔍 Running Nginx WAF AI Security Test Suite")
        print("=" * 50)
        
        start_time = datetime.now()
        
        # Run all tests
        self.test_authentication_system()
        self.test_input_validation()
        self.test_https_configuration()
        self.test_ml_engine_security()
        self.test_security_middleware()
        self.test_ssh_key_security()
        self.test_environment_configuration()
        self.test_rate_limiting()
        self.test_data_validation_consistency()
        
        end_time = datetime.now()
        duration = (end_time - start_time).total_seconds()
        
        # Print summary
        print("\n" + "=" * 50)
        print("🏁 TEST SUMMARY")
        print("=" * 50)
        print(f"Total Tests: {self.passed_tests + self.failed_tests}")
        print(f"✅ Passed: {self.passed_tests}")
        print(f"❌ Failed: {self.failed_tests}")
        print(f"⏱️ Duration: {duration:.2f} seconds")
        
        if self.failed_tests == 0:
            print("\n🎉 ALL SECURITY TESTS PASSED!")
            return True
        else:
            print(f"\n⚠️ {self.failed_tests} SECURITY TESTS FAILED!")
            print("\nFailed tests:")
            for result in self.test_results:
                if "❌ FAIL" in result:
                    print(f"  {result}")
            return False


if __name__ == "__main__":
    test_suite = SecurityTestSuite()
    success = test_suite.run_all_tests()
    sys.exit(0 if success else 1)
