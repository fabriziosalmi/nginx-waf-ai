"""
Input Validation Module

Provides comprehensive input validation and sanitization for API endpoints.
"""

import re
import ipaddress
from typing import List, Dict, Any, Optional, Union
from datetime import datetime
from pydantic import BaseModel, validator, Field, EmailStr
from fastapi import HTTPException, status
from enum import Enum


class ThreatType(str, Enum):
    """Valid threat types"""
    NORMAL = "normal"
    SQL_INJECTION = "sql_injection"
    XSS_ATTACK = "xss_attack"
    UNAUTHORIZED_ACCESS = "unauthorized_access"
    FILE_ACCESS = "file_access"
    COMMAND_INJECTION = "command_injection"
    DIRECTORY_TRAVERSAL = "directory_traversal"


class HttpMethod(str, Enum):
    """Valid HTTP methods"""
    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    DELETE = "DELETE"
    PATCH = "PATCH"
    HEAD = "HEAD"
    OPTIONS = "OPTIONS"


class NodeStatus(str, Enum):
    """Valid node status values"""
    ONLINE = "online"
    OFFLINE = "offline"
    MAINTENANCE = "maintenance"
    ERROR = "error"


class ValidationError(HTTPException):
    """Custom validation error"""
    def __init__(self, detail: str):
        super().__init__(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Validation error: {detail}"
        )


class SecureNginxNodeModel(BaseModel):
    """Secure model for nginx node configuration with strict validation"""
    node_id: str = Field(..., min_length=1, max_length=50, pattern=r'^[a-zA-Z0-9\-_]+$')
    hostname: str = Field(..., min_length=1, max_length=255)
    ssh_host: str = Field(..., min_length=1, max_length=255)
    ssh_port: int = Field(default=22, ge=1, le=65535)
    ssh_username: str = Field(..., min_length=1, max_length=50, pattern=r'^[a-zA-Z0-9._-]+$')
    ssh_key_path: str = Field(..., min_length=1, max_length=500)
    nginx_config_path: str = Field(..., min_length=1, max_length=500)
    nginx_reload_command: str = Field(default="sudo systemctl reload nginx", max_length=200)
    api_endpoint: str = Field(..., min_length=1, max_length=500)  # Added missing field
    
    @validator('hostname')
    def validate_hostname(cls, v):
        # Allow IP addresses or valid hostnames
        try:
            ipaddress.ip_address(v)
            return v
        except ValueError:
            # Validate as hostname
            if not re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$', v):
                raise ValueError('Invalid hostname format')
            return v
    
    @validator('ssh_host')
    def validate_ssh_host(cls, v):
        # Same validation as hostname
        try:
            ipaddress.ip_address(v)
            return v
        except ValueError:
            if not re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$', v):
                raise ValueError('Invalid SSH host format')
            return v
    
    @validator('ssh_key_path')
    def validate_ssh_key_path(cls, v):
        if v is not None:
            # Basic path validation - must be absolute path
            if not v.startswith('/'):
                raise ValueError('SSH key path must be absolute')
            # Prevent directory traversal
            if '..' in v:
                raise ValueError('SSH key path cannot contain ".."')
        return v
    
    @validator('api_endpoint')
    def validate_api_endpoint(cls, v):
        # Validate URL format
        if not (v.startswith('http://') or v.startswith('https://')):
            raise ValueError('API endpoint must be a valid HTTP/HTTPS URL')
        return v
    
    @validator('nginx_config_path')
    def validate_nginx_config_path(cls, v):
        # Must be absolute path
        if not v.startswith('/'):
            raise ValueError('Nginx config path must be absolute')
        # Prevent directory traversal
        if '..' in v:
            raise ValueError('Nginx config path cannot contain ".."')
        return v
    
    @validator('nginx_reload_command')
    def validate_nginx_reload_command(cls, v):
        # Whitelist allowed commands
        allowed_commands = [
            'sudo systemctl reload nginx',
            'sudo systemctl restart nginx',
            'sudo nginx -s reload',
            'sudo service nginx reload',
            'systemctl reload nginx',
            'nginx -s reload'
        ]
        if v not in allowed_commands:
            raise ValueError(f'Nginx reload command must be one of: {allowed_commands}')
        return v


class SecureTrainingRequest(BaseModel):
    """Secure training request with validation"""
    training_data: List[Dict[str, Any]] = Field(..., min_items=1, max_items=10000)
    labels: Optional[List[str]] = Field(None, max_items=10000)
    
    @validator('training_data')
    def validate_training_data(cls, v):
        required_fields = [
            'timestamp', 'method', 'url', 'headers_count', 'body_length',
            'source_ip', 'user_agent', 'content_length', 'has_suspicious_headers',
            'url_length', 'contains_sql_patterns', 'contains_xss_patterns'
        ]
        
        for i, item in enumerate(v):
            # Check required fields
            missing_fields = [field for field in required_fields if field not in item]
            if missing_fields:
                raise ValueError(f'Training data item {i} missing fields: {missing_fields}')
            
            # Validate data types and ranges
            try:
                # Timestamp validation
                if isinstance(item['timestamp'], str):
                    datetime.fromisoformat(item['timestamp'].replace('Z', '+00:00'))
                
                # Method validation
                if item['method'] not in [m.value for m in HttpMethod]:
                    raise ValueError(f'Invalid HTTP method: {item["method"]}')
                
                # URL validation
                url = item['url']
                if not isinstance(url, str) or len(url) > 2000:
                    raise ValueError(f'Invalid URL length: {len(url)}')
                
                # Numeric field validation
                numeric_fields = ['headers_count', 'body_length', 'content_length', 'url_length']
                for field in numeric_fields:
                    if not isinstance(item[field], int) or item[field] < 0 or item[field] > 1000000:
                        raise ValueError(f'Invalid {field}: {item[field]}')
                
                # Boolean field validation
                bool_fields = ['has_suspicious_headers', 'contains_sql_patterns', 'contains_xss_patterns']
                for field in bool_fields:
                    if not isinstance(item[field], bool):
                        raise ValueError(f'Invalid {field}: {item[field]}')
                
                # IP address validation
                try:
                    ipaddress.ip_address(item['source_ip'])
                except ValueError:
                    raise ValueError(f'Invalid IP address: {item["source_ip"]}')
                
                # User agent validation
                user_agent = item['user_agent']
                if not isinstance(user_agent, str) or len(user_agent) > 500:
                    raise ValueError(f'Invalid user agent length: {len(user_agent)}')
                
            except Exception as e:
                raise ValueError(f'Training data item {i} validation failed: {str(e)}')
        
        return v
    
    @validator('labels')
    def validate_labels(cls, v, values):
        if v is not None:
            # Check that labels count matches training data count
            training_data = values.get('training_data', [])
            if len(v) != len(training_data):
                raise ValueError('Labels count must match training data count')
            
            # Validate label values
            valid_labels = [t.value for t in ThreatType]
            for i, label in enumerate(v):
                if label not in valid_labels:
                    raise ValueError(f'Invalid label at index {i}: {label}. Valid labels: {valid_labels}')
        
        return v


class SecureHttpRequest(BaseModel):
    """Secure HTTP request model for analysis"""
    timestamp: str = Field(..., pattern=r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}')
    method: HttpMethod
    url: str = Field(..., min_length=1, max_length=2000)
    headers_count: int = Field(..., ge=0, le=100)
    body_length: int = Field(..., ge=0, le=10000000)  # 10MB max
    source_ip: str = Field(..., min_length=7, max_length=45)  # IPv4/IPv6
    user_agent: str = Field(..., max_length=500)
    content_length: int = Field(..., ge=0, le=10000000)
    has_suspicious_headers: bool
    url_length: int = Field(..., ge=0, le=2000)
    contains_sql_patterns: bool
    contains_xss_patterns: bool
    node_id: str = Field('default', min_length=1, max_length=50, pattern=r'^[a-zA-Z0-9\-_]+$')
    
    @validator('timestamp')
    def validate_timestamp(cls, v):
        try:
            datetime.fromisoformat(v.replace('Z', '+00:00'))
        except ValueError:
            raise ValueError('Invalid timestamp format. Use ISO 8601 format.')
        return v
    
    @validator('source_ip')
    def validate_source_ip(cls, v):
        try:
            ipaddress.ip_address(v)
        except ValueError:
            raise ValueError('Invalid IP address format')
        return v
    
    @validator('url')
    def validate_url(cls, v):
        # Basic URL validation - must start with /
        if not v.startswith('/'):
            raise ValueError('URL must start with /')
        
        # Check for suspicious patterns that might indicate injection
        suspicious_patterns = [
            r'<script.*?>',
            r'javascript:',
            r'vbscript:',
            r'data:',
            r'file:',
            r'ftp:',
            r'\.\./',
            r'%2e%2e%2f',
            r'%2e%2e/',
            r'..%2f',
            r'%00',
            r'\x00'
        ]
        
        for pattern in suspicious_patterns:
            if re.search(pattern, v, re.IGNORECASE):
                # Don't block, just log for analysis
                pass
        
        return v


class SecureRuleDeploymentRequest(BaseModel):
    """Secure rule deployment request"""
    rules: List[Dict[str, Any]] = Field(..., min_items=1, max_items=1000)
    node_ids: Optional[List[str]] = Field(None, max_items=100)
    force_deploy: bool = Field(False)
    backup_config: bool = Field(True)
    
    @validator('node_ids')
    def validate_node_ids(cls, v):
        if v is not None:
            for node_id in v:
                if not re.match(r'^[a-zA-Z0-9\-_]+$', node_id):
                    raise ValueError(f'Invalid node_id format: {node_id}')
        return v
    
    @validator('rules')
    def validate_rules(cls, v):
        for i, rule in enumerate(v):
            # Basic rule structure validation
            required_fields = ['rule_id', 'pattern', 'action']
            missing_fields = [field for field in required_fields if field not in rule]
            if missing_fields:
                raise ValueError(f'Rule {i} missing fields: {missing_fields}')
            
            # Validate rule_id
            if not re.match(r'^[a-zA-Z0-9\-_]+$', rule['rule_id']):
                raise ValueError(f'Invalid rule_id format in rule {i}')
            
            # Validate action
            valid_actions = ['block', 'allow', 'log', 'rate_limit']
            if rule['action'] not in valid_actions:
                raise ValueError(f'Invalid action in rule {i}: {rule["action"]}')
        
        return v


class UserManagementRequest(BaseModel):
    """User management request validation"""
    username: str = Field(..., min_length=3, max_length=50, pattern=r'^[a-zA-Z0-9\-_]+$')
    password: str = Field(..., min_length=8, max_length=128)
    roles: List[str] = Field(..., min_items=1, max_items=10)
    
    @validator('password')
    def validate_password(cls, v):
        # Password strength validation
        if len(v) < 8:
            raise ValueError('Password must be at least 8 characters long')
        
        if not re.search(r'[A-Z]', v):
            raise ValueError('Password must contain at least one uppercase letter')
        
        if not re.search(r'[a-z]', v):
            raise ValueError('Password must contain at least one lowercase letter')
        
        if not re.search(r'\d', v):
            raise ValueError('Password must contain at least one digit')
        
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', v):
            raise ValueError('Password must contain at least one special character')
        
        return v
    
    @validator('roles')
    def validate_roles(cls, v):
        valid_roles = ['admin', 'operator', 'viewer']
        for role in v:
            if role not in valid_roles:
                raise ValueError(f'Invalid role: {role}. Valid roles: {valid_roles}')
        return v


class LoginRequest(BaseModel):
    """Login request validation"""
    username: str = Field(..., min_length=1, max_length=50)
    password: str = Field(..., min_length=1, max_length=128)


class ApiKeyRequest(BaseModel):
    """API key generation request"""
    username: str = Field(..., min_length=1, max_length=50, pattern=r'^[a-zA-Z0-9\-_]+$')
    description: Optional[str] = Field(None, max_length=200)


def sanitize_input(value: str) -> str:
    """Sanitize string input to prevent injection attacks"""
    if not isinstance(value, str):
        return str(value)
    
    # Remove null bytes
    value = value.replace('\x00', '')
    
    # Basic HTML entity encoding for critical characters
    value = value.replace('<', '&lt;')
    value = value.replace('>', '&gt;')
    value = value.replace('"', '&quot;')
    value = value.replace("'", '&#x27;')
    value = value.replace('&', '&amp;')
    
    return value


def validate_ip_address(ip_str: str) -> bool:
    """Validate IP address format"""
    try:
        ipaddress.ip_address(ip_str)
        return True
    except ValueError:
        return False


def validate_domain_name(domain: str) -> bool:
    """Validate domain name format"""
    if len(domain) > 253:
        return False
    
    if domain.endswith('.'):
        domain = domain[:-1]
    
    allowed = re.compile(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$')
    return all(allowed.match(label) for label in domain.split('.'))


def validate_file_path(path: str, allow_relative: bool = False) -> bool:
    """Validate file path to prevent directory traversal"""
    if not isinstance(path, str):
        return False
    
    # Check for null bytes
    if '\x00' in path:
        return False
    
    # Check for directory traversal patterns
    if '..' in path:
        return False
    
    # Check if absolute path when required
    if not allow_relative and not path.startswith('/'):
        return False
    
    return True


class InputValidator:
    """Centralized input validation utility"""
    
    @staticmethod
    def validate_request_data(data: Dict[str, Any], schema: Dict[str, Any]) -> Dict[str, Any]:
        """Validate request data against schema"""
        validated_data = {}
        
        for field, rules in schema.items():
            value = data.get(field)
            
            # Required field check
            if rules.get('required', False) and value is None:
                raise ValidationError(f"Field '{field}' is required")
            
            if value is None:
                continue
            
            # Type validation
            expected_type = rules.get('type')
            if expected_type and not isinstance(value, expected_type):
                raise ValidationError(f"Field '{field}' must be of type {expected_type.__name__}")
            
            # String length validation
            if isinstance(value, str):
                min_length = rules.get('min_length', 0)
                max_length = rules.get('max_length', float('inf'))
                if not (min_length <= len(value) <= max_length):
                    raise ValidationError(f"Field '{field}' length must be between {min_length} and {max_length}")
            
            # Numeric range validation
            if isinstance(value, (int, float)):
                min_val = rules.get('min_value', float('-inf'))
                max_val = rules.get('max_value', float('inf'))
                if not (min_val <= value <= max_val):
                    raise ValidationError(f"Field '{field}' must be between {min_val} and {max_val}")
            
            # Pattern validation
            pattern = rules.get('pattern')
            if pattern and isinstance(value, str):
                if not re.match(pattern, value):
                    raise ValidationError(f"Field '{field}' does not match required pattern")
            
            validated_data[field] = value
        
        return validated_data
