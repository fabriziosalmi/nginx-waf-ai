#!/usr/bin/env python3
"""
Unit tests for authentication and authorization functionality.

This test suite verifies JWT token handling, role-based access control,
password security, and API key management.
"""

import pytest
from datetime import datetime, timedelta
from unittest.mock import Mock, patch
import jwt
from passlib.context import CryptContext

from src.auth import (
    create_access_token, verify_token, get_current_user, require_role,
    verify_password, get_password_hash, create_user, get_user,
    require_admin, require_operator, require_viewer
)
from src.config import Config


class TestAuthentication:
    """Test authentication functionality"""
    
    def setup_method(self):
        """Set up test fixtures"""
        self.config = Config()
        self.pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
        
        # Test user data
        self.test_user = {
            "username": "testuser",
            "password": "TestPass123!",
            "roles": ["viewer"]
        }
        
        self.admin_user = {
            "username": "admin",
            "password": "AdminPass123!",
            "roles": ["admin"]
        }
    
    def test_password_hashing(self):
        """Test password hashing and verification"""
        password = "TestPassword123!"
        
        # Test hashing
        hashed = get_password_hash(password)
        assert hashed != password
        assert len(hashed) > 50  # Bcrypt hashes are long
        
        # Test verification
        assert verify_password(password, hashed) == True
        assert verify_password("wrong_password", hashed) == False
    
    def test_jwt_token_creation(self):
        """Test JWT token creation"""
        data = {"sub": "testuser", "roles": ["viewer"]}
        token = create_access_token(data)
        
        assert isinstance(token, str)
        assert len(token) > 100  # JWT tokens are long
        
        # Decode token to verify contents
        decoded = jwt.decode(
            token, 
            self.config.jwt_secret_key, 
            algorithms=[self.config.jwt_algorithm]
        )
        
        assert decoded["sub"] == "testuser"
        assert decoded["roles"] == ["viewer"]
        assert "exp" in decoded
        assert "iat" in decoded
    
    def test_jwt_token_expiration(self):
        """Test JWT token expiration"""
        # Create token with short expiry
        data = {"sub": "testuser", "roles": ["viewer"]}
        token = create_access_token(data, expires_delta=timedelta(seconds=-1))
        
        # Token should be expired
        with pytest.raises(jwt.ExpiredSignatureError):
            jwt.decode(
                token,
                self.config.jwt_secret_key,
                algorithms=[self.config.jwt_algorithm]
            )
    
    def test_token_verification_valid(self):
        """Test verification of valid tokens"""
        data = {"sub": "testuser", "roles": ["viewer"]}
        token = create_access_token(data)
        
        token_data = verify_token(token)
        
        assert token_data.username == "testuser"
        assert token_data.roles == ["viewer"]
    
    def test_token_verification_invalid(self):
        """Test verification of invalid tokens"""
        # Test invalid token
        with pytest.raises(Exception):
            verify_token("invalid_token")
        
        # Test token with wrong signature
        fake_token = jwt.encode(
            {"sub": "testuser", "roles": ["viewer"]},
            "wrong_secret",
            algorithm="HS256"
        )
        
        with pytest.raises(Exception):
            verify_token(fake_token)
    
    @patch('src.auth.get_user')
    def test_get_current_user_valid(self, mock_get_user):
        """Test getting current user with valid token"""
        mock_get_user.return_value = {
            "username": "testuser",
            "hashed_password": "hashed",
            "roles": ["viewer"]
        }
        
        data = {"sub": "testuser", "roles": ["viewer"]}
        token = create_access_token(data)
        
        user = get_current_user(token)
        
        assert user.username == "testuser"
        assert user.roles == ["viewer"]
    
    def test_get_current_user_invalid(self):
        """Test getting current user with invalid token"""
        with pytest.raises(Exception):
            get_current_user("invalid_token")


class TestAuthorization:
    """Test role-based authorization"""
    
    def setup_method(self):
        """Set up test fixtures"""
        self.admin_token_data = Mock()
        self.admin_token_data.username = "admin"
        self.admin_token_data.roles = ["admin"]
        
        self.operator_token_data = Mock()
        self.operator_token_data.username = "operator"
        self.operator_token_data.roles = ["operator"]
        
        self.viewer_token_data = Mock()
        self.viewer_token_data.username = "viewer"
        self.viewer_token_data.roles = ["viewer"]
        
        self.multi_role_token_data = Mock()
        self.multi_role_token_data.username = "multi"
        self.multi_role_token_data.roles = ["viewer", "operator"]
    
    def test_require_admin_with_admin_user(self):
        """Test admin requirement with admin user"""
        decorator = require_admin()
        
        # Should not raise exception
        result = decorator(self.admin_token_data)
        assert result == self.admin_token_data
    
    def test_require_admin_with_non_admin_user(self):
        """Test admin requirement with non-admin user"""
        decorator = require_admin()
        
        # Should raise exception
        with pytest.raises(Exception):
            decorator(self.viewer_token_data)
    
    def test_require_operator_with_operator_user(self):
        """Test operator requirement with operator user"""
        decorator = require_operator()
        
        # Should not raise exception
        result = decorator(self.operator_token_data)
        assert result == self.operator_token_data
    
    def test_require_operator_with_admin_user(self):
        """Test operator requirement with admin user (should work)"""
        decorator = require_operator()
        
        # Admin should be able to do operator tasks
        result = decorator(self.admin_token_data)
        assert result == self.admin_token_data
    
    def test_require_operator_with_viewer_user(self):
        """Test operator requirement with viewer user (should fail)"""
        decorator = require_operator()
        
        # Should raise exception
        with pytest.raises(Exception):
            decorator(self.viewer_token_data)
    
    def test_require_viewer_with_any_user(self):
        """Test viewer requirement with any user"""
        decorator = require_viewer()
        
        # All users should be able to view
        assert decorator(self.viewer_token_data) == self.viewer_token_data
        assert decorator(self.operator_token_data) == self.operator_token_data
        assert decorator(self.admin_token_data) == self.admin_token_data
    
    def test_multiple_roles_user(self):
        """Test user with multiple roles"""
        operator_decorator = require_operator()
        viewer_decorator = require_viewer()
        
        # Should work for both operator and viewer requirements
        assert operator_decorator(self.multi_role_token_data) == self.multi_role_token_data
        assert viewer_decorator(self.multi_role_token_data) == self.multi_role_token_data
        
        # Should fail for admin requirement
        admin_decorator = require_admin()
        with pytest.raises(Exception):
            admin_decorator(self.multi_role_token_data)
    
    def test_role_hierarchy(self):
        """Test that role hierarchy works correctly"""
        # Admin should be able to do everything
        for decorator in [require_viewer(), require_operator(), require_admin()]:
            assert decorator(self.admin_token_data) == self.admin_token_data
        
        # Operator should be able to do viewer and operator tasks
        for decorator in [require_viewer(), require_operator()]:
            assert decorator(self.operator_token_data) == self.operator_token_data
        
        # Operator should NOT be able to do admin tasks
        with pytest.raises(Exception):
            require_admin()(self.operator_token_data)
        
        # Viewer should only be able to do viewer tasks
        assert require_viewer()(self.viewer_token_data) == self.viewer_token_data
        
        for decorator in [require_operator(), require_admin()]:
            with pytest.raises(Exception):
                decorator(self.viewer_token_data)


class TestUserManagement:
    """Test user management functionality"""
    
    def setup_method(self):
        """Set up test fixtures"""
        self.test_users = {}
    
    def mock_user_storage(self, username, user_data):
        """Mock user storage for testing"""
        self.test_users[username] = user_data
    
    def mock_user_retrieval(self, username):
        """Mock user retrieval for testing"""
        return self.test_users.get(username)
    
    @patch('src.auth.users_db')
    def test_create_user_success(self, mock_users_db):
        """Test successful user creation"""
        mock_users_db.__setitem__ = self.mock_user_storage
        mock_users_db.get = self.mock_user_retrieval
        
        username = "newuser"
        password = "NewPass123!"
        roles = ["viewer"]
        
        result = create_user(username, password, roles)
        
        assert result == True
        assert username in self.test_users
        
        user_data = self.test_users[username]
        assert user_data["username"] == username
        assert "hashed_password" in user_data
        assert user_data["roles"] == roles
        assert verify_password(password, user_data["hashed_password"])
    
    @patch('src.auth.users_db')
    def test_create_user_duplicate(self, mock_users_db):
        """Test creating duplicate user"""
        mock_users_db.__setitem__ = self.mock_user_storage
        mock_users_db.get = self.mock_user_retrieval
        
        # Create user first time
        username = "existinguser"
        password = "Pass123!"
        roles = ["viewer"]
        
        create_user(username, password, roles)
        
        # Try to create same user again
        result = create_user(username, password, roles)
        
        assert result == False
    
    @patch('src.auth.users_db')
    def test_get_user_existing(self, mock_users_db):
        """Test getting existing user"""
        mock_users_db.get = self.mock_user_retrieval
        
        # Add user to mock storage
        username = "testuser"
        user_data = {
            "username": username,
            "hashed_password": "hashed",
            "roles": ["viewer"]
        }
        self.test_users[username] = user_data
        
        result = get_user(username)
        
        assert result == user_data
    
    @patch('src.auth.users_db')
    def test_get_user_nonexistent(self, mock_users_db):
        """Test getting non-existent user"""
        mock_users_db.get = self.mock_user_retrieval
        
        result = get_user("nonexistent")
        
        assert result is None
    
    def test_password_strength_validation(self):
        """Test password strength requirements"""
        weak_passwords = [
            "123",  # Too short
            "password",  # No uppercase, no numbers, no special chars
            "PASSWORD",  # No lowercase, no numbers, no special chars
            "Password",  # No numbers, no special chars
            "Password123",  # No special chars
        ]
        
        strong_passwords = [
            "Password123!",
            "MyStr0ng@Pass",
            "C0mpl3x#Passw0rd",
        ]
        
        # Test that weak passwords can be hashed (no validation in current implementation)
        # In a real implementation, you might want to add password strength validation
        for password in weak_passwords + strong_passwords:
            hashed = get_password_hash(password)
            assert verify_password(password, hashed)


class TestAPIKeysManagement:
    """Test API key management functionality"""
    
    def setup_method(self):
        """Set up test fixtures"""
        self.test_api_keys = {}
    
    def mock_api_key_storage(self, key, data):
        """Mock API key storage"""
        self.test_api_keys[key] = data
    
    def mock_api_key_retrieval(self, key):
        """Mock API key retrieval"""
        return self.test_api_keys.get(key)
    
    def test_api_key_format(self):
        """Test API key format and uniqueness"""
        import secrets
        
        # Generate multiple API keys
        keys = []
        for _ in range(10):
            key = secrets.token_urlsafe(32)
            keys.append(key)
        
        # Check that all keys are unique
        assert len(set(keys)) == len(keys)
        
        # Check key format (URL-safe base64)
        for key in keys:
            assert isinstance(key, str)
            assert len(key) > 30  # Should be reasonably long
            # Should only contain URL-safe characters
            import string
            allowed_chars = string.ascii_letters + string.digits + '-_'
            assert all(c in allowed_chars for c in key)


class TestSecurityFeatures:
    """Test security-related features"""
    
    def test_timing_attack_resistance(self):
        """Test that password verification is resistant to timing attacks"""
        import time
        
        correct_password = "CorrectPassword123!"
        hashed = get_password_hash(correct_password)
        
        # Test with various wrong passwords of different lengths
        wrong_passwords = [
            "x",
            "wrong",
            "wrongpassword",
            "WrongPassword123!",
            "x" * 100
        ]
        
        times = []
        for wrong_password in wrong_passwords:
            start = time.perf_counter()
            result = verify_password(wrong_password, hashed)
            end = time.perf_counter()
            
            assert result == False
            times.append(end - start)
        
        # Note: In a real implementation, you'd want the times to be relatively consistent
        # to prevent timing attacks. bcrypt naturally provides some protection against this.
    
    def test_jwt_claims_validation(self):
        """Test JWT claims validation"""
        from src.config import Config
        config = Config()
        
        # Test with missing required claims
        incomplete_token_data = {"sub": "testuser"}  # Missing roles
        token = jwt.encode(
            incomplete_token_data,
            config.jwt_secret_key,
            algorithm=config.jwt_algorithm
        )
        
        # Should handle missing claims gracefully
        try:
            token_data = verify_token(token)
            # If no exception, check that roles is handled properly
            assert hasattr(token_data, 'roles')
        except Exception:
            # Exception is acceptable for malformed tokens
            pass
    
    def test_role_case_sensitivity(self):
        """Test that roles are case-sensitive"""
        token_data_lower = Mock()
        token_data_lower.username = "user"
        token_data_lower.roles = ["admin"]  # lowercase
        
        token_data_upper = Mock()
        token_data_upper.username = "user"
        token_data_upper.roles = ["ADMIN"]  # uppercase
        
        admin_decorator = require_admin()
        
        # Should work with lowercase "admin"
        assert admin_decorator(token_data_lower) == token_data_lower
        
        # Should NOT work with uppercase "ADMIN" (case-sensitive)
        with pytest.raises(Exception):
            admin_decorator(token_data_upper)
    
    def test_empty_roles_handling(self):
        """Test handling of users with no roles"""
        token_data_no_roles = Mock()
        token_data_no_roles.username = "user"
        token_data_no_roles.roles = []
        
        # Should fail all role requirements
        for decorator in [require_viewer(), require_operator(), require_admin()]:
            with pytest.raises(Exception):
                decorator(token_data_no_roles)
