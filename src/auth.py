"""
Authentication and Authorization Module

Provides API key authentication, JWT tokens, and role-based access control.
"""

import os
import jwt
import hashlib
import secrets
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any
from dataclasses import dataclass
from fastapi import HTTPException, Depends, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
import bcrypt
from loguru import logger


@dataclass
class User:
    """User model for authentication"""
    username: str
    password_hash: str
    roles: List[str]
    api_keys: List[str]
    created_at: datetime
    last_login: Optional[datetime] = None
    is_active: bool = True


class TokenData(BaseModel):
    """JWT token data model"""
    username: str
    roles: List[str]
    exp: datetime


class AuthConfig:
    """Authentication configuration"""
    def __init__(self):
        self.jwt_secret = os.getenv('WAF_JWT_SECRET', self._generate_secret())
        self.jwt_algorithm = 'HS256'
        self.jwt_expiry_hours = int(os.getenv('WAF_JWT_EXPIRY_HOURS', '24'))
        self.api_key_length = 32
        self.bcrypt_rounds = 12
        
        # Warn if using default secret
        if 'WAF_JWT_SECRET' not in os.environ:
            logger.warning("Using auto-generated JWT secret. Set WAF_JWT_SECRET environment variable for production.")
    
    def _generate_secret(self) -> str:
        """Generate a secure random secret"""
        return secrets.token_urlsafe(32)


class AuthManager:
    """Manages authentication and authorization"""
    
    def __init__(self):
        self.config = AuthConfig()
        self.users: Dict[str, User] = {}
        self.api_keys: Dict[str, str] = {}  # api_key -> username
        self.security = HTTPBearer()
        
        # Initialize with default admin user if no users exist
        self._init_default_admin()
    
    def _init_default_admin(self):
        """Initialize default admin user"""
        admin_password = os.getenv('WAF_ADMIN_PASSWORD', 'admin123')
        if admin_password == 'admin123':
            logger.warning("Using default admin password. Set WAF_ADMIN_PASSWORD environment variable.")
        
        admin_user = self.create_user(
            username='admin',
            password=admin_password,
            roles=['admin', 'operator', 'viewer']
        )
        
        # Generate default API key for admin
        api_key = self.generate_api_key('admin')
        logger.info(f"Default admin API key: {api_key}")
    
    def hash_password(self, password: str) -> str:
        """Hash password using bcrypt"""
        salt = bcrypt.gensalt(rounds=self.config.bcrypt_rounds)
        return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')
    
    def verify_password(self, password: str, password_hash: str) -> bool:
        """Verify password against hash"""
        return bcrypt.checkpw(password.encode('utf-8'), password_hash.encode('utf-8'))
    
    def create_user(self, username: str, password: str, roles: List[str]) -> User:
        """Create a new user"""
        if username in self.users:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="User already exists"
            )
        
        password_hash = self.hash_password(password)
        user = User(
            username=username,
            password_hash=password_hash,
            roles=roles,
            api_keys=[],
            created_at=datetime.now()
        )
        
        self.users[username] = user
        logger.info(f"Created user: {username} with roles: {roles}")
        return user
    
    def authenticate_user(self, username: str, password: str) -> Optional[User]:
        """Authenticate user with username/password"""
        user = self.users.get(username)
        if not user or not user.is_active:
            return None
        
        if self.verify_password(password, user.password_hash):
            user.last_login = datetime.now()
            logger.info(f"User authenticated: {username}")
            return user
        
        logger.warning(f"Failed authentication attempt for user: {username}")
        return None
    
    def generate_api_key(self, username: str) -> str:
        """Generate API key for user"""
        user = self.users.get(username)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )
        
        api_key = secrets.token_urlsafe(self.config.api_key_length)
        user.api_keys.append(api_key)
        self.api_keys[api_key] = username
        
        logger.info(f"Generated API key for user: {username}")
        return api_key
    
    def revoke_api_key(self, api_key: str) -> bool:
        """Revoke an API key"""
        username = self.api_keys.pop(api_key, None)
        if username:
            user = self.users.get(username)
            if user and api_key in user.api_keys:
                user.api_keys.remove(api_key)
            logger.info(f"Revoked API key for user: {username}")
            return True
        return False
    
    def create_jwt_token(self, username: str) -> str:
        """Create JWT token for user"""
        user = self.users.get(username)
        if not user or not user.is_active:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid user"
            )
        
        expiry = datetime.utcnow() + timedelta(hours=self.config.jwt_expiry_hours)
        payload = {
            'username': username,
            'roles': user.roles,
            'exp': expiry,
            'iat': datetime.utcnow()
        }
        
        token = jwt.encode(payload, self.config.jwt_secret, algorithm=self.config.jwt_algorithm)
        logger.info(f"Created JWT token for user: {username}")
        return token
    
    def verify_jwt_token(self, token: str) -> Optional[TokenData]:
        """Verify and decode JWT token"""
        try:
            payload = jwt.decode(
                token, 
                self.config.jwt_secret, 
                algorithms=[self.config.jwt_algorithm]
            )
            
            username = payload.get('username')
            roles = payload.get('roles', [])
            exp = datetime.fromtimestamp(payload.get('exp'))
            
            if username and username in self.users:
                return TokenData(username=username, roles=roles, exp=exp)
        except jwt.ExpiredSignatureError:
            logger.warning("JWT token expired")
        except jwt.JWTError as e:
            logger.warning(f"JWT verification failed: {e}")
        
        return None
    
    def verify_api_key(self, api_key: str) -> Optional[User]:
        """Verify API key and return user"""
        username = self.api_keys.get(api_key)
        if username:
            user = self.users.get(username)
            if user and user.is_active:
                return user
        return None
    
    def require_roles(self, required_roles: List[str]):
        """Decorator factory for role-based access control"""
        def role_checker(token_data: TokenData) -> TokenData:
            if not any(role in token_data.roles for role in required_roles):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Insufficient permissions. Required roles: {required_roles}"
                )
            return token_data
        return role_checker
    
    async def get_current_user_from_token(
        self, 
        credentials: HTTPAuthorizationCredentials = Depends(HTTPBearer())
    ) -> TokenData:
        """Get current user from JWT token"""
        token = credentials.credentials
        
        # Try JWT first
        token_data = self.verify_jwt_token(token)
        if token_data:
            return token_data
        
        # Try API key
        user = self.verify_api_key(token)
        if user:
            return TokenData(
                username=user.username,
                roles=user.roles,
                exp=datetime.now() + timedelta(hours=24)  # API keys don't expire
            )
        
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    def get_user_stats(self) -> Dict[str, Any]:
        """Get user management statistics"""
        return {
            'total_users': len(self.users),
            'active_users': sum(1 for user in self.users.values() if user.is_active),
            'total_api_keys': len(self.api_keys),
            'users': [
                {
                    'username': user.username,
                    'roles': user.roles,
                    'api_keys_count': len(user.api_keys),
                    'created_at': user.created_at.isoformat(),
                    'last_login': user.last_login.isoformat() if user.last_login else None,
                    'is_active': user.is_active
                }
                for user in self.users.values()
            ]
        }


# Global auth manager instance
auth_manager = AuthManager()

# Dependency functions for FastAPI
async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(HTTPBearer())
) -> TokenData:
    """Get current authenticated user"""
    return await auth_manager.get_current_user_from_token(credentials)

def require_admin() -> TokenData:
    """Require admin role"""
    def admin_checker(token_data: TokenData = Depends(get_current_user)) -> TokenData:
        if 'admin' not in token_data.roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Admin role required"
            )
        return token_data
    return Depends(admin_checker)

def require_operator() -> TokenData:
    """Require operator role or higher"""
    def operator_checker(token_data: TokenData = Depends(get_current_user)) -> TokenData:
        if not any(role in token_data.roles for role in ['admin', 'operator']):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Operator role or higher required"
            )
        return token_data
    return Depends(operator_checker)

def require_viewer() -> TokenData:
    """Require viewer role or higher (any authenticated user)"""
    def viewer_checker(token_data: TokenData = Depends(get_current_user)) -> TokenData:
        if not any(role in token_data.roles for role in ['admin', 'operator', 'viewer']):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Viewer role or higher required"
            )
        return token_data
    return Depends(viewer_checker)
