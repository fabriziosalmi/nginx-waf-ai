"""
Configuration management for the nginx WAF AI system
"""

import os
import ssl
from typing import List, Dict, Any, Optional
from dataclasses import dataclass
import json
from pathlib import Path
from loguru import logger


@dataclass
class SecurityConfig:
    """Security-specific configuration"""
    # Authentication
    jwt_secret: str
    jwt_expiry_hours: int = 24
    api_key_expiry_days: int = 365
    bcrypt_rounds: int = 12
    
    # TLS/HTTPS
    use_https: bool = False
    ssl_cert_path: Optional[str] = None
    ssl_key_path: Optional[str] = None
    ssl_verify_mode: int = ssl.CERT_REQUIRED
    
    # Rate limiting
    rate_limit_requests: int = 100
    rate_limit_window: int = 60  # seconds
    
    # Security headers
    enable_security_headers: bool = True
    cors_origins: List[str] = None
    
    # SSH key encryption
    ssh_key_encryption: bool = True
    ssh_key_passphrase: Optional[str] = None


@dataclass
class SystemConfig:
    """Main system configuration"""
    # API settings
    api_host: str = "127.0.0.1"  # Changed from 0.0.0.0 for security
    api_port: int = 8000
    api_debug: bool = False  # Secure default
    
    # Security configuration
    security: SecurityConfig = None
    
    # ML settings
    ml_model_path: str = "models/waf_model.joblib"
    threat_threshold: float = -0.5
    confidence_threshold: float = 0.8
    retrain_interval_hours: int = 24
    
    # Traffic collection
    traffic_collection_interval: int = 1  # seconds
    max_requests_memory: int = 10000
    cleanup_interval_minutes: int = 60
    
    # WAF rules
    rule_expiry_hours: int = 24
    max_active_rules: int = 100
    rule_optimization_enabled: bool = True
    
    # Nginx management
    default_nginx_config_path: str = "/etc/nginx/conf.d"
    default_nginx_reload_command: str = "sudo systemctl reload nginx"
    deployment_timeout_seconds: int = 30
    
    # Logging
    log_level: str = "INFO"
    log_file: str = "logs/waf_ai.log"
    
    # Monitoring
    metrics_enabled: bool = True
    metrics_port: int = 9090
    
    def __post_init__(self):
        """Initialize security config if not provided"""
        if self.security is None:
            self.security = SecurityConfig(
                jwt_secret=os.getenv('WAF_JWT_SECRET', self._generate_jwt_secret()),
                use_https=os.getenv('WAF_USE_HTTPS', 'false').lower() == 'true',
                ssl_cert_path=os.getenv('WAF_SSL_CERT_PATH'),
                ssl_key_path=os.getenv('WAF_SSL_KEY_PATH'),
                cors_origins=self._parse_cors_origins(),
                rate_limit_requests=int(os.getenv('WAF_RATE_LIMIT_REQUESTS', '100')),
                rate_limit_window=int(os.getenv('WAF_RATE_LIMIT_WINDOW', '60'))
            )
        
        # Validate security configuration
        self._validate_security_config()
    
    def _generate_jwt_secret(self) -> str:
        """Generate a secure JWT secret"""
        import secrets
        secret = secrets.token_urlsafe(32)
        logger.warning("Auto-generated JWT secret. Set WAF_JWT_SECRET environment variable for production.")
        return secret
    
    def _parse_cors_origins(self) -> List[str]:
        """Parse CORS origins from environment"""
        origins_env = os.getenv('WAF_CORS_ORIGINS', '')
        if origins_env:
            return [origin.strip() for origin in origins_env.split(',')]
        return ['http://localhost:3000', 'http://localhost:8080']  # Development defaults
    
    def _validate_security_config(self):
        """Validate security configuration"""
        if self.security.use_https:
            if not self.security.ssl_cert_path or not self.security.ssl_key_path:
                raise ValueError("SSL certificate and key paths required when HTTPS is enabled")
            
            if not Path(self.security.ssl_cert_path).exists():
                raise ValueError(f"SSL certificate not found: {self.security.ssl_cert_path}")
            
            if not Path(self.security.ssl_key_path).exists():
                raise ValueError(f"SSL key not found: {self.security.ssl_key_path}")
        
        if self.api_debug and self.security.use_https:
            logger.warning("Debug mode enabled with HTTPS. Consider disabling debug in production.")
    
    @classmethod
    def from_env(cls) -> 'SystemConfig':
        """Load configuration from environment variables"""
        return cls(
            api_host=os.getenv('WAF_AI_HOST', '127.0.0.1'),
            api_port=int(os.getenv('WAF_AI_PORT', '8000')),
            api_debug=os.getenv('WAF_AI_DEBUG', 'false').lower() == 'true',
            
            ml_model_path=os.getenv('WAF_AI_MODEL_PATH', 'models/waf_model.joblib'),
            threat_threshold=float(os.getenv('WAF_AI_THREAT_THRESHOLD', '-0.5')),
            confidence_threshold=float(os.getenv('WAF_AI_CONFIDENCE_THRESHOLD', '0.8')),
            retrain_interval_hours=int(os.getenv('WAF_AI_RETRAIN_INTERVAL', '24')),
            
            traffic_collection_interval=int(os.getenv('WAF_AI_COLLECTION_INTERVAL', '1')),
            max_requests_memory=int(os.getenv('WAF_AI_MAX_REQUESTS', '10000')),
            cleanup_interval_minutes=int(os.getenv('WAF_AI_CLEANUP_INTERVAL', '60')),
            
            rule_expiry_hours=int(os.getenv('WAF_AI_RULE_EXPIRY', '24')),
            max_active_rules=int(os.getenv('WAF_AI_MAX_RULES', '100')),
            rule_optimization_enabled=os.getenv('WAF_AI_OPTIMIZE_RULES', 'true').lower() == 'true',
            
            default_nginx_config_path=os.getenv('WAF_AI_NGINX_CONFIG_PATH', '/etc/nginx/conf.d'),
            default_nginx_reload_command=os.getenv('WAF_AI_NGINX_RELOAD', 'sudo systemctl reload nginx'),
            deployment_timeout_seconds=int(os.getenv('WAF_AI_DEPLOY_TIMEOUT', '30')),
            
            log_level=os.getenv('WAF_AI_LOG_LEVEL', 'INFO'),
            log_file=os.getenv('WAF_AI_LOG_FILE', 'logs/waf_ai.log'),
            
            metrics_enabled=os.getenv('WAF_AI_METRICS_ENABLED', 'true').lower() == 'true',
            metrics_port=int(os.getenv('WAF_AI_METRICS_PORT', '9090'))
        )
    
    @classmethod
    def from_file(cls, config_path: str) -> 'SystemConfig':
        """Load configuration from JSON file"""
        with open(config_path, 'r') as f:
            config_data = json.load(f)
        
        return cls(**config_data)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary (excluding sensitive data)"""
        return {
            'api_host': self.api_host,
            'api_port': self.api_port,
            'api_debug': self.api_debug,
            'ml_model_path': self.ml_model_path,
            'threat_threshold': self.threat_threshold,
            'confidence_threshold': self.confidence_threshold,
            'retrain_interval_hours': self.retrain_interval_hours,
            'traffic_collection_interval': self.traffic_collection_interval,
            'max_requests_memory': self.max_requests_memory,
            'cleanup_interval_minutes': self.cleanup_interval_minutes,
            'rule_expiry_hours': self.rule_expiry_hours,
            'max_active_rules': self.max_active_rules,
            'rule_optimization_enabled': self.rule_optimization_enabled,
            'default_nginx_config_path': self.default_nginx_config_path,
            'default_nginx_reload_command': self.default_nginx_reload_command,
            'deployment_timeout_seconds': self.deployment_timeout_seconds,
            'log_level': self.log_level,
            'log_file': self.log_file,
            'metrics_enabled': self.metrics_enabled,
            'metrics_port': self.metrics_port,
            'security': {
                'use_https': self.security.use_https,
                'rate_limit_requests': self.security.rate_limit_requests,
                'rate_limit_window': self.security.rate_limit_window,
                'enable_security_headers': self.security.enable_security_headers,
                'cors_origins': self.security.cors_origins
                # Note: JWT secret and SSL paths are excluded for security
            }
        }
    
    def save_to_file(self, config_path: str):
        """Save configuration to JSON file"""
        os.makedirs(os.path.dirname(config_path), exist_ok=True)
        with open(config_path, 'w') as f:
            json.dump(self.to_dict(), f, indent=2)
    
    def validate_environment(self):
        """Validate the environment configuration"""
        errors = []
        
        # Check required directories
        if not Path(os.path.dirname(self.ml_model_path)).exists():
            errors.append(f"Model directory does not exist: {os.path.dirname(self.ml_model_path)}")
        
        if not Path(os.path.dirname(self.log_file)).exists():
            try:
                Path(os.path.dirname(self.log_file)).mkdir(parents=True, exist_ok=True)
            except Exception as e:
                errors.append(f"Cannot create log directory: {e}")
        
        # Check SSH keys if using SSH deployment
        ssh_key_path = os.getenv('WAF_AI_SSH_KEY_PATH')
        if ssh_key_path and not Path(ssh_key_path).exists():
            errors.append(f"SSH key not found: {ssh_key_path}")
        
        # Validate port ranges
        if not (1 <= self.api_port <= 65535):
            errors.append(f"Invalid API port: {self.api_port}")
        
        if not (1 <= self.metrics_port <= 65535):
            errors.append(f"Invalid metrics port: {self.metrics_port}")
        
        # Check for port conflicts
        if self.api_port == self.metrics_port:
            errors.append("API port and metrics port cannot be the same")
        
        if errors:
            raise ValueError(f"Configuration validation failed: {'; '.join(errors)}")
        
        logger.info("Environment validation passed")


@dataclass
class NginxNodeConfig:
    """Configuration for individual nginx nodes"""
    node_id: str
    hostname: str
    ssh_host: str
    ssh_port: int = 22
    ssh_username: str = 'root'
    ssh_key_path: Optional[str] = None
    nginx_config_path: str = '/etc/nginx/conf.d'
    nginx_reload_command: str = 'sudo systemctl reload nginx'
    api_endpoint: Optional[str] = None
    backup_enabled: bool = True
    backup_path: str = '/etc/nginx/conf.d/backup'
    
    def validate(self):
        """Validate nginx node configuration"""
        errors = []
        
        if not self.node_id or not self.node_id.replace('-', '').replace('_', '').isalnum():
            errors.append("node_id must be alphanumeric (with hyphens/underscores)")
        
        if not self.hostname:
            errors.append("hostname is required")
        
        if not self.ssh_host:
            errors.append("ssh_host is required")
        
        if not (1 <= self.ssh_port <= 65535):
            errors.append(f"Invalid SSH port: {self.ssh_port}")
        
        if not self.ssh_username:
            errors.append("ssh_username is required")
        
        if self.ssh_key_path and not Path(self.ssh_key_path).exists():
            errors.append(f"SSH key not found: {self.ssh_key_path}")
        
        allowed_reload_commands = [
            'sudo systemctl reload nginx',
            'sudo systemctl restart nginx',
            'sudo nginx -s reload',
            'sudo service nginx reload',
            'systemctl reload nginx',
            'nginx -s reload'
        ]
        
        if self.nginx_reload_command not in allowed_reload_commands:
            errors.append(f"Invalid nginx reload command: {self.nginx_reload_command}")
        
        if errors:
            raise ValueError(f"Nginx node configuration validation failed: {'; '.join(errors)}")


# Global configuration instance
config = SystemConfig.from_env()

# Validate configuration on import
try:
    config.validate_environment()
except Exception as e:
    logger.error(f"Configuration validation failed: {e}")
    # Don't raise here to allow for graceful startup in development
