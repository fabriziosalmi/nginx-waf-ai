"""
Configuration management for the nginx WAF AI system
"""

import os
from typing import List, Dict, Any
from dataclasses import dataclass
import json


@dataclass
class SystemConfig:
    """Main system configuration"""
    # API settings
    api_host: str = "0.0.0.0"
    api_port: int = 8000
    api_debug: bool = False
    
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
    
    @classmethod
    def from_env(cls) -> 'SystemConfig':
        """Load configuration from environment variables"""
        return cls(
            api_host=os.getenv('WAF_AI_HOST', '0.0.0.0'),
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
            log_file=os.getenv('WAF_AI_LOG_FILE', 'logs/waf_ai.log')
        )
    
    @classmethod
    def from_file(cls, config_path: str) -> 'SystemConfig':
        """Load configuration from JSON file"""
        with open(config_path, 'r') as f:
            config_data = json.load(f)
        
        return cls(**config_data)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
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
            'log_file': self.log_file
        }
    
    def save_to_file(self, config_path: str):
        """Save configuration to JSON file"""
        os.makedirs(os.path.dirname(config_path), exist_ok=True)
        with open(config_path, 'w') as f:
            json.dump(self.to_dict(), f, indent=2)


# Global configuration instance
config = SystemConfig.from_env()
