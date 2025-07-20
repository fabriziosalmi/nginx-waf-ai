"""
Main API Module

FastAPI-based API for the nginx WAF AI system with comprehensive security.
"""

import asyncio
import ipaddress
import os
import ssl
import threading
import traceback
from contextlib import asynccontextmanager
from datetime import datetime
from typing import List, Dict, Optional, Any

import uvicorn
from fastapi import FastAPI, HTTPException, BackgroundTasks, Response, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.security import HTTPBearer
from prometheus_client import Counter, Histogram, Gauge, generate_latest, CONTENT_TYPE_LATEST
from loguru import logger
from pydantic import BaseModel
# Note: slowapi might not be installed, implement custom rate limiting if needed
try:
    from slowapi import Limiter, _rate_limit_exceeded_handler
    from slowapi.util import get_remote_address
    from slowapi.errors import RateLimitExceeded
    RATE_LIMITING_AVAILABLE = True
except ImportError:
    logger.warning("slowapi not available, rate limiting disabled")
    RATE_LIMITING_AVAILABLE = False

# Import our modules
from .auth import auth_manager, get_current_user, require_admin, require_operator, require_viewer, TokenData
from .validation import (
    SecureNginxNodeModel, SecureTrainingRequest, SecureRuleDeploymentRequest,
    UserManagementRequest, LoginRequest, ApiKeyRequest, ValidationError
)
from .config import config
from .traffic_collector import TrafficCollector, HttpRequest
from .ml_engine import MLEngine, RealTimeProcessor, ThreatPrediction
from .waf_rule_generator import WAFRuleGenerator, WAFRule, RuleOptimizer
from .nginx_manager import NginxManager, NginxNode
from .security_middleware import SecurityMiddleware, is_ip_whitelisted
from .error_handling import error_recovery, degradation_manager, CircuitBreakerConfig

# Initialize rate limiter if available
if RATE_LIMITING_AVAILABLE:
    limiter = Limiter(key_func=get_remote_address)
else:
    limiter = None

# Custom rate limiting decorator when slowapi is not available
def rate_limit(limit: str):
    def decorator(func):
        if RATE_LIMITING_AVAILABLE:
            return limiter.limit(limit)(func)
        return func
    return decorator

# Thread-safe locks for global variables and state management
processing_lock = threading.RLock()  # Reentrant lock for nested calls
component_lock = threading.RLock()  # Reentrant lock for component management
state_lock = threading.RLock()  # Lock for shared state variables

# System state with proper synchronization
system_state = {
    'is_processing': False,
    'components_initialized': False,
    'last_error': None,
    'startup_time': None,
    'shutdown_requested': False
}

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Enhanced lifespan context manager with comprehensive error handling"""
    try:
        # Startup
        logger.info("Starting Nginx WAF AI system...")
        
        with state_lock:
            system_state['startup_time'] = datetime.now()
            system_state['shutdown_requested'] = False
        
        await startup_components()
        
        with state_lock:
            system_state['components_initialized'] = True
            
        logger.info("System startup completed successfully")
        
        yield
        
    except Exception as e:
        logger.error(f"Critical error during system startup: {e}")
        with state_lock:
            system_state['last_error'] = str(e)
        # Still yield to allow FastAPI to start, but mark system as unhealthy
        yield
        
    finally:
        # Shutdown
        try:
            logger.info("Shutting down Nginx WAF AI system...")
            
            with state_lock:
                system_state['shutdown_requested'] = True
                
            await shutdown_components()
            logger.info("System shutdown completed successfully")
            
        except Exception as e:
            logger.error(f"Error during system shutdown: {e}")
            with state_lock:
                system_state['last_error'] = str(e)


# Create FastAPI app with security middleware
app = FastAPI(
    title="Nginx WAF AI",
    description="Real-time machine learning WAF rule generator for nginx",
    version="0.1.0",
    lifespan=lifespan,
    docs_url="/docs" if config.api_debug else None,  # Disable docs in production
    redoc_url="/redoc" if config.api_debug else None
)

# Add security middleware first (before other middleware)
app.add_middleware(
    SecurityMiddleware,
    rate_limit_requests=config.security.rate_limit_requests,
    rate_limit_window=config.security.rate_limit_window,
    enable_dos_protection=True,
    enable_input_validation=True,
    max_request_size=10 * 1024 * 1024,  # 10MB
    enable_honeypot=True
)

# Add rate limiting if available
if RATE_LIMITING_AVAILABLE:
    app.state.limiter = limiter
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# Security middleware
if config.security.cors_origins:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=config.security.cors_origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "DELETE"],
        allow_headers=["*"],
    )

# Trusted host middleware for production
if not config.api_debug:
    app.add_middleware(
        TrustedHostMiddleware,
        allowed_hosts=["localhost", "127.0.0.1", config.api_host]
    )

# Add security headers middleware
@app.middleware("http")
async def add_security_headers(request, call_next):
    response = await call_next(request)
    
    if config.security.enable_security_headers:
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Content-Security-Policy"] = "default-src 'self'"
    
    return response

# Prometheus metrics
requests_total = Counter('waf_requests_total', 'Total number of requests processed', ['node_id', 'status'])
threats_detected = Counter('waf_threats_detected_total', 'Total number of threats detected', ['threat_type'])
rules_active = Gauge('waf_rules_active', 'Number of active WAF rules')
nodes_registered = Gauge('waf_nodes_registered', 'Number of registered nginx nodes')
processing_time = Histogram('waf_processing_time_seconds', 'Time spent processing requests')
auth_attempts = Counter('waf_auth_attempts_total', 'Authentication attempts', ['status'])

# Global components with thread safety - use proper synchronization
class ComponentManager:
    """Thread-safe component manager"""
    def __init__(self):
        self._lock = threading.RLock()
        self._components = {
            'traffic_collector': None,
            'ml_engine': None,
            'real_time_processor': None,
            'waf_rule_generator': None,
            'nginx_manager': None,
            'rule_optimizer': None
        }
        self._component_status = {
            'traffic_collector': {'status': 'stopped', 'last_error': None},
            'ml_engine': {'status': 'stopped', 'last_error': None},
            'real_time_processor': {'status': 'stopped', 'last_error': None},
            'waf_rule_generator': {'status': 'stopped', 'last_error': None},
            'nginx_manager': {'status': 'stopped', 'last_error': None},
            'rule_optimizer': {'status': 'stopped', 'last_error': None}
        }
    
    def get_component(self, name: str):
        with self._lock:
            return self._components.get(name)
    
    def set_component(self, name: str, component):
        with self._lock:
            self._components[name] = component
            if component is not None:
                self._component_status[name]['status'] = 'running'
                self._component_status[name]['last_error'] = None
    
    def get_status(self, name: str = None):
        with self._lock:
            if name:
                return self._component_status.get(name, {})
            return self._component_status.copy()
    
    def set_error(self, name: str, error: str):
        with self._lock:
            if name in self._component_status:
                self._component_status[name]['status'] = 'error'
                self._component_status[name]['last_error'] = error
    
    def shutdown_all(self):
        with self._lock:
            for name in self._components:
                self._components[name] = None
                self._component_status[name]['status'] = 'stopped'

# Global component manager instance
component_manager = ComponentManager()

# Helper functions for safe component access
def get_ml_engine() -> Optional[MLEngine]:
    """Safely get ML engine component"""
    return component_manager.get_component('ml_engine')

def get_waf_rule_generator() -> Optional[WAFRuleGenerator]:
    """Safely get WAF rule generator component"""
    return component_manager.get_component('waf_rule_generator')

def get_nginx_manager() -> Optional[NginxManager]:
    """Safely get nginx manager component"""
    return component_manager.get_component('nginx_manager')

def get_traffic_collector() -> Optional[TrafficCollector]:
    """Safely get traffic collector component"""
    return component_manager.get_component('traffic_collector')

def get_real_time_processor() -> Optional[RealTimeProcessor]:
    """Safely get real-time processor component"""
    return component_manager.get_component('real_time_processor')

def get_rule_optimizer() -> Optional[RuleOptimizer]:
    """Safely get rule optimizer component"""
    return component_manager.get_component('rule_optimizer')

def require_component(component_name: str, component):
    """Raise HTTPException if component is not available"""
    if component is None:
        raise HTTPException(
            status_code=503, 
            detail=f"{component_name} not available. Check system status."
        )


# Response models
class ThreatResponse(BaseModel):
    threats: List[Dict[str, Any]]
    total_threats: int
    threat_patterns: Dict[str, int]


class SystemStatusResponse(BaseModel):
    status: str
    components: Dict[str, bool]
    timestamp: str


class AuthResponse(BaseModel):
    access_token: str
    token_type: str
    expires_in: int


async def startup_components():
    """Initialize system components with comprehensive error handling"""
    logger.info("Starting component initialization...")
    
    try:
        with component_lock:
            # Initialize ML engine with error handling
            try:
                logger.info("Initializing ML engine...")
                ml_engine = MLEngine()
                component_manager.set_component('ml_engine', ml_engine)
                
                # Try to load existing model
                model_path = config.ml_model_path
                if os.path.exists(model_path):
                    try:
                        ml_engine.load_models(model_path)
                        logger.info(f"Loaded existing ML model from {model_path}")
                    except Exception as e:
                        logger.warning(f"Failed to load existing model: {e}, will use default model")
                
            except Exception as e:
                logger.error(f"Failed to initialize ML engine: {e}")
                component_manager.set_error('ml_engine', str(e))
                # Don't raise here, continue with other components
            
            # Initialize WAF rule generator with error handling
            try:
                logger.info("Initializing WAF rule generator...")
                waf_rule_generator = WAFRuleGenerator()
                component_manager.set_component('waf_rule_generator', waf_rule_generator)
                
            except Exception as e:
                logger.error(f"Failed to initialize WAF rule generator: {e}")
                component_manager.set_error('waf_rule_generator', str(e))
            
            # Initialize rule optimizer with error handling
            try:
                logger.info("Initializing rule optimizer...")
                rule_optimizer = RuleOptimizer()
                component_manager.set_component('rule_optimizer', rule_optimizer)
                
            except Exception as e:
                logger.error(f"Failed to initialize rule optimizer: {e}")
                component_manager.set_error('rule_optimizer', str(e))
            
            # Initialize nginx manager with error handling
            try:
                logger.info("Initializing nginx manager...")
                # Load nginx nodes from config
                nginx_nodes = []
                nginx_nodes_env = os.getenv('NGINX_NODES', '')
                
                if nginx_nodes_env:
                    node_urls = [url.strip() for url in nginx_nodes_env.split(',') if url.strip()]
                    logger.info(f"Found nginx nodes: {node_urls}")
                    
                    # Create nginx node objects (simplified for demo)
                    for i, url in enumerate(node_urls):
                        nginx_nodes.append(NginxNode(
                            node_id=f"node_{i+1}",
                            hostname=url,
                            ssh_host="localhost",  # Default for demo
                            ssh_port=22,
                            ssh_username="nginx",
                            ssh_key_path=None,
                            nginx_config_path="/etc/nginx/conf.d",
                            nginx_reload_command="sudo systemctl reload nginx"
                        ))
                
                if nginx_nodes:
                    nginx_manager = NginxManager(nginx_nodes)
                    component_manager.set_component('nginx_manager', nginx_manager)
                else:
                    logger.warning("No nginx nodes configured")
                
            except Exception as e:
                logger.error(f"Failed to initialize nginx manager: {e}")
                component_manager.set_error('nginx_manager', str(e))
            
            # Initialize traffic collector with error handling
            try:
                logger.info("Initializing traffic collector...")
                nginx_nodes_env = os.getenv('NGINX_NODES', '')
                
                if nginx_nodes_env:
                    node_urls = [url.strip() for url in nginx_nodes_env.split(',') if url.strip()]
                    if node_urls:
                        traffic_collector = TrafficCollector(node_urls)
                        component_manager.set_component('traffic_collector', traffic_collector)
                        
                        # Start collection in background with error handling
                        try:
                            asyncio.create_task(traffic_collector.start_collection())
                            logger.info(f"Traffic collection started for nodes: {node_urls}")
                        except Exception as e:
                            logger.error(f"Failed to start traffic collection: {e}")
                            component_manager.set_error('traffic_collector', str(e))
                else:
                    logger.warning("No NGINX_NODES environment variable found")
                    
            except Exception as e:
                logger.error(f"Failed to initialize traffic collector: {e}")
                component_manager.set_error('traffic_collector', str(e))
            
            # Initialize real-time processor if ML engine is available
            try:
                ml_engine = component_manager.get_component('ml_engine')
                if ml_engine:
                    logger.info("Initializing real-time processor...")
                    real_time_processor = RealTimeProcessor(ml_engine, config.threat_threshold)
                    component_manager.set_component('real_time_processor', real_time_processor)
                else:
                    logger.warning("ML engine not available, skipping real-time processor")
                    
            except Exception as e:
                logger.error(f"Failed to initialize real-time processor: {e}")
                component_manager.set_error('real_time_processor', str(e))
            
            logger.info("Component initialization completed")
            
            # Log component status
            status = component_manager.get_status()
            for component, details in status.items():
                if details['status'] == 'running':
                    logger.info(f"✓ {component}: running")
                elif details['status'] == 'error':
                    logger.warning(f"✗ {component}: error - {details['last_error']}")
                else:
                    logger.info(f"- {component}: {details['status']}")
            
            # Register fallback strategies for critical components
            logger.info("Registering fallback strategies...")
            degradation_manager.register_dependency('ml_engine', 'traffic_analysis', 'static_rules')
            degradation_manager.register_dependency('nginx_manager', 'config_deployment', 'manual_config')
            degradation_manager.register_dependency('traffic_collector', 'real_time_monitoring', 'log_based')
            logger.info("Fallback strategies registered successfully")
    
    except Exception as e:
        logger.error(f"Critical error during component initialization: {e}")
        raise


async def shutdown_components():
    """Shutdown system components gracefully with comprehensive error handling"""
    logger.info("Starting graceful component shutdown...")
    
    try:
        with component_lock:
            # Stop processing first
            with state_lock:
                system_state['is_processing'] = False
            
            # Shutdown traffic collector
            try:
                traffic_collector = component_manager.get_component('traffic_collector')
                if traffic_collector:
                    await traffic_collector.stop_collection()
                    logger.info("Traffic collector stopped")
            except Exception as e:
                logger.error(f"Error stopping traffic collector: {e}")
            
            # Shutdown nginx manager
            try:
                nginx_manager = component_manager.get_component('nginx_manager')
                if nginx_manager:
                    nginx_manager.cleanup_resources()
                    logger.info("Nginx manager cleaned up")
            except Exception as e:
                logger.error(f"Error cleaning up nginx manager: {e}")
            
            # Save ML model if available
            try:
                ml_engine = component_manager.get_component('ml_engine')
                if ml_engine and ml_engine.is_trained:
                    model_path = config.ml_model_path
                    os.makedirs(os.path.dirname(model_path), exist_ok=True)
                    ml_engine.save_models(model_path)
                    logger.info(f"ML model saved to {model_path}")
            except Exception as e:
                logger.error(f"Error saving ML model: {e}")
            
            # Shutdown all components
            component_manager.shutdown_all()
            logger.info("All components shutdown completed")
            
    except Exception as e:
        logger.error(f"Error during component shutdown: {e}")
    
    # Wait a moment for background tasks to finish
    await asyncio.sleep(2)


# ============= AUTHENTICATION ENDPOINTS =============

@app.post("/auth/login", response_model=AuthResponse)
@rate_limit("5/minute")
async def login(request: LoginRequest):
    """Authenticate user and return JWT token"""
    try:
        user = auth_manager.authenticate_user(request.username, request.password)
        if not user:
            auth_attempts.labels(status="failed").inc()
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid credentials",
                headers={"WWW-Authenticate": "Bearer"},
            )
        
        auth_attempts.labels(status="success").inc()
        token = auth_manager.create_jwt_token(user.username)
        
        return AuthResponse(
            access_token=token,
            token_type="bearer",
            expires_in=config.security.jwt_expiry_hours * 3600
        )
    
    except Exception as e:
        logger.error(f"Login error: {e}")
        auth_attempts.labels(status="error").inc()
        raise HTTPException(status_code=500, detail="Authentication error")


@app.post("/auth/api-key")
@rate_limit("3/minute")
async def generate_api_key(
    request: ApiKeyRequest,
    current_user: TokenData = require_admin()
):
    """Generate API key for user (admin only)"""
    try:
        api_key = auth_manager.generate_api_key(request.username)
        return {
            "api_key": api_key,
            "username": request.username,
            "created_at": datetime.now().isoformat()
        }
    except Exception as e:
        logger.error(f"API key generation error: {e}")
        raise HTTPException(status_code=500, detail="Failed to generate API key")


@app.post("/auth/users")
@rate_limit("5/minute")
async def create_user(
    request: UserManagementRequest,
    current_user: TokenData = require_admin()
):
    """Create new user (admin only)"""
    try:
        user = auth_manager.create_user(
            username=request.username,
            password=request.password,
            roles=request.roles
        )
        return {
            "message": f"User {request.username} created successfully",
            "username": user.username,
            "roles": user.roles,
            "created_at": user.created_at.isoformat()
        }
    except Exception as e:
        logger.error(f"User creation error: {e}")
        raise HTTPException(status_code=500, detail="Failed to create user")


@app.get("/auth/users")
@rate_limit("10/minute")
async def list_users(request: Request, current_user: TokenData = require_admin()):
    """List all users (admin only)"""
    try:
        return auth_manager.get_user_stats()
    except Exception as e:
        logger.error(f"User listing error: {e}")
        raise HTTPException(status_code=500, detail="Failed to list users")


# ============= SECURITY MANAGEMENT ENDPOINTS =============

@app.get("/api/security/stats")
@rate_limit("10/minute")
async def get_security_stats(current_user: TokenData = require_admin()):
    """Get security statistics and events (admin only)"""
    try:
        # Get security middleware stats
        security_middleware = None
        for middleware in app.user_middleware:
            if isinstance(middleware.cls, type) and issubclass(middleware.cls, SecurityMiddleware):
                # This is a bit hacky, but we need to access the middleware instance
                # In a real implementation, you'd store a reference to the middleware
                break
        
        base_stats = {
            "timestamp": datetime.now().isoformat(),
            "auth_stats": auth_manager.get_user_stats(),
            "system_security": {
                "https_enabled": config.security.use_https,
                "rate_limiting": RATE_LIMITING_AVAILABLE,
                "security_headers": config.security.enable_security_headers,
                "debug_mode": config.api_debug
            }
        }
        
        return base_stats
    
    except Exception as e:
        logger.error(f"Failed to get security stats: {e}")
        raise HTTPException(status_code=500, detail="Failed to get security stats")


@app.post("/api/security/unblock-ip")
@rate_limit("5/minute")
async def unblock_ip(
    ip_address: str,
    current_user: TokenData = require_admin()
):
    """Unblock an IP address (admin only)"""
    try:
        # Validate IP address format
        ipaddress.ip_address(ip_address)
        
        # In a real implementation, you'd access the security middleware instance
        logger.info(f"IP unblock request for {ip_address} by {current_user.username}")
        
        return {
            "message": f"IP {ip_address} unblock requested",
            "timestamp": datetime.now().isoformat(),
            "admin": current_user.username
        }
    
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid IP address format")
    except Exception as e:
        logger.error(f"Failed to unblock IP: {e}")
        raise HTTPException(status_code=500, detail="Failed to unblock IP")


@app.post("/api/security/emergency-shutdown")
@rate_limit("1/minute")
async def emergency_shutdown(current_user: TokenData = require_admin()):
    """Emergency shutdown endpoint (admin only)"""
    try:
        logger.critical(f"EMERGENCY SHUTDOWN initiated by {current_user.username}")
        
        # Stop all background processing using proper state management
        with state_lock:
            system_state['is_processing'] = False
            system_state['shutdown_requested'] = True
        
        # Could add additional emergency procedures here
        
        return {
            "message": "Emergency shutdown initiated",
            "timestamp": datetime.now().isoformat(),
            "admin": current_user.username
        }
    
    except Exception as e:
        logger.error(f"Emergency shutdown failed: {e}")
        raise HTTPException(status_code=500, detail="Emergency shutdown failed")


# ============= PUBLIC ENDPOINTS =============

@app.get("/")
@rate_limit("30/minute")
async def root():
    """Root endpoint"""
    return {
        "message": "Nginx WAF AI System",
        "version": "0.1.0",
        "status": "running",
        "timestamp": datetime.now().isoformat(),
        "security": "enabled" if not config.api_debug else "debug_mode"
    }


@app.get("/health")
@rate_limit("60/minute")
async def health_check():
    """Health check endpoint"""
    try:
        # Get components safely
        ml_engine = component_manager.get_component('ml_engine')
        traffic_collector = component_manager.get_component('traffic_collector')
        waf_rule_generator = component_manager.get_component('waf_rule_generator')
        nginx_manager = component_manager.get_component('nginx_manager')
        
        with component_lock:
            return {
                "status": "healthy",
                "components": {
                    "ml_engine": ml_engine is not None and getattr(ml_engine, 'is_trained', False),
                    "traffic_collector": traffic_collector is not None,
                    "waf_generator": waf_rule_generator is not None,
                    "nginx_manager": nginx_manager is not None,
                    "authentication": True,
                    "rate_limiting": RATE_LIMITING_AVAILABLE
                },
                "timestamp": datetime.now().isoformat()
            }
    except Exception as e:
        logger.error(f"Health check error: {e}")
        return {"status": "unhealthy", "error": str(e)}

@app.get("/metrics")
@rate_limit("30/minute")
async def get_metrics(current_user: TokenData = require_viewer()):
    """Prometheus metrics endpoint - requires authentication"""
    # Update gauge metrics using component manager
    nginx_manager = component_manager.get_component('nginx_manager')
    waf_rule_generator = component_manager.get_component('waf_rule_generator')
    
    if nginx_manager:
        nodes_registered.set(len(nginx_manager.nodes))
    
    if waf_rule_generator:
        # This would need to be implemented in the rule generator
        rules_active.set(len(getattr(waf_rule_generator, 'active_rules', [])))
    
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)


# ============= PROTECTED ENDPOINTS =============

@app.get("/api/debug/status")
@rate_limit("10/minute")
async def debug_status(current_user: TokenData = require_operator()):
    """Debug endpoint to check system status - requires operator role"""
    
    # Get components safely using component manager
    traffic_collector = component_manager.get_component('traffic_collector')
    ml_engine = component_manager.get_component('ml_engine')
    real_time_processor = component_manager.get_component('real_time_processor')
    
    # Get processing state safely
    with state_lock:
        is_processing = system_state['is_processing']
    
    status = {
        "traffic_collector": {
            "initialized": traffic_collector is not None,
            "is_collecting": getattr(traffic_collector, 'is_collecting', False),
            "collected_requests_count": len(getattr(traffic_collector, 'collected_requests', [])),
            "recent_requests_count": len(traffic_collector.get_recent_requests(100)) if traffic_collector else 0
        },
        "ml_engine": {
            "initialized": ml_engine is not None,
            "is_trained": getattr(ml_engine, 'is_trained', False)
        },
        "real_time_processor": {
            "initialized": real_time_processor is not None
        },
        "processing": {
            "is_processing": is_processing
        },
        "components_status": component_manager.get_status()
    }
    
    return status


@app.post("/api/debug/test-prediction")
@rate_limit("5/minute")
async def test_prediction(current_user: TokenData = require_operator()):
    """Debug endpoint to test ML predictions on sample malicious requests"""
    ml_engine = get_ml_engine()
    if ml_engine is None or not ml_engine.is_trained:
        raise HTTPException(status_code=400, detail="ML engine not trained")
    
    try:
        # Test with clearly malicious requests
        test_requests = [
            {
                'url_length': 30,
                'body_length': 0,
                'headers_count': 5,
                'content_length': 0,
                'has_suspicious_headers': False,
                'contains_sql_patterns': True,
                'contains_xss_patterns': False,
                'method': 'GET',
                'timestamp': '2025-01-20T15:30:00'
            },
            {
                'url_length': 25,
                'body_length': 0,
                'headers_count': 5,
                'content_length': 0,
                'has_suspicious_headers': False,
                'contains_sql_patterns': False,
                'contains_xss_patterns': True,
                'method': 'GET',
                'timestamp': '2025-01-20T15:30:00'
            },
            {
                'url_length': 15,
                'body_length': 0,
                'headers_count': 5,
                'content_length': 0,
                'has_suspicious_headers': False,
                'contains_sql_patterns': False,
                'contains_xss_patterns': False,
                'method': 'GET',
                'timestamp': '2025-01-20T15:30:00'
            }
        ]
        
        predictions = ml_engine.predict_threats(test_requests)
        
        return {
            "predictions": [
                {
                    "threat_score": pred.threat_score,
                    "threat_type": pred.threat_type,
                    "confidence": pred.confidence,
                    "request_features": f"sql:{test_requests[i].get('contains_sql_patterns')}, xss:{test_requests[i].get('contains_xss_patterns')}"
                }
                for i, pred in enumerate(predictions)
            ],
            "threshold_info": {
                "threshold": "score < -0.1 OR confidence > 0.6 OR type != 'normal'",
                "qualified_threats": [
                    i for i, pred in enumerate(predictions)
                    if pred.threat_score < -0.1 or pred.confidence > 0.6 or pred.threat_type != 'normal'
                ]
            }
        }
    
    except Exception as e:
        logger.error(f"Failed to test predictions: {e}")
        raise HTTPException(status_code=500, detail=f"Prediction test failed: {str(e)}")


@app.get("/api/status")
@rate_limit("10/minute")
async def get_system_status(current_user: TokenData = require_viewer()):
    """Get system status - requires authentication"""
    # Get components safely
    traffic_collector = component_manager.get_component('traffic_collector')
    ml_engine = component_manager.get_component('ml_engine')
    real_time_processor = component_manager.get_component('real_time_processor')
    waf_rule_generator = component_manager.get_component('waf_rule_generator')
    nginx_manager = component_manager.get_component('nginx_manager')
    
    # Get processing state safely
    with state_lock:
        is_processing = system_state['is_processing']
    
    return {
        "is_processing": is_processing,
        "traffic_collector": traffic_collector is not None,
        "traffic_collector_collecting": traffic_collector.is_collecting if traffic_collector else False,
        "ml_engine": ml_engine is not None,
        "ml_engine_trained": ml_engine.is_trained if ml_engine else False,
        "real_time_processor": real_time_processor is not None,
        "waf_rule_generator": waf_rule_generator is not None,
        "nginx_manager": nginx_manager is not None,
        "recent_requests_count": len(traffic_collector.collected_requests) if traffic_collector else 0,
        "timestamp": datetime.now().isoformat()
    }


@app.get("/api/health")
@rate_limit("20/minute")
async def get_system_health(current_user: TokenData = require_viewer()):
    """Get comprehensive system health including error recovery status"""
    try:
        # Get component status
        component_status = component_manager.get_status()
        
        # Get degradation status
        degradation_status = degradation_manager.get_degradation_status()
        
        # Get circuit breaker status
        circuit_breaker_status = error_recovery.get_health_status()
        
        # Get processing state
        with state_lock:
            processing_state = system_state.copy()
        
        # Calculate overall health score
        total_components = len(component_status)
        healthy_components = sum(1 for status in component_status.values() if status.get('status') == 'running')
        health_score = (healthy_components / total_components) * 100 if total_components > 0 else 0
        
        # Determine system status
        if health_score >= 90:
            system_status = "healthy"
        elif health_score >= 70:
            system_status = "degraded"
        elif health_score >= 50:
            system_status = "critical"
        else:
            system_status = "failing"
        
        return {
            "system_status": system_status,
            "health_score": round(health_score, 2),
            "processing_state": processing_state,
            "components": component_status,
            "degradation": degradation_status,
            "circuit_breakers": circuit_breaker_status,
            "error_recovery": {
                "fallbacks_available": len(error_recovery.fallback_strategies),
                "features_degraded": len(degradation_status.get('degraded_features', [])),
                "recovery_enabled": True
            },
            "timestamp": datetime.now().isoformat()
        }
    
    except Exception as e:
        logger.error(f"Failed to get system health: {e}")
        raise HTTPException(status_code=500, detail=f"Health check failed: {str(e)}")


@app.post("/api/nodes/add")
@rate_limit("5/minute")
async def add_nginx_node(
    node: SecureNginxNodeModel,
    current_user: TokenData = require_admin()
):
    """Add a new nginx node to the cluster - requires admin role"""
    global nginx_manager
    
    try:
        nginx_node = NginxNode(
            node_id=node.node_id,
            hostname=node.hostname,
            ssh_host=node.ssh_host,
            ssh_port=node.ssh_port,
            ssh_username=node.ssh_username,
            ssh_key_path=node.ssh_key_path,
            nginx_config_path=node.nginx_config_path,
            nginx_reload_command=node.nginx_reload_command,
            api_endpoint=node.api_endpoint
        )
        
        nginx_manager = component_manager.get_component('nginx_manager')
        if nginx_manager is None:
            nginx_manager = NginxManager([nginx_node])
            component_manager.set_component('nginx_manager', nginx_manager)
        else:
            nginx_manager.add_node(nginx_node)
        
        logger.info(f"Node {node.node_id} added by user {current_user.username}")
        return {"message": f"Node {node.node_id} added successfully"}
    
    except Exception as e:
        logger.error(f"Failed to add node {node.node_id}: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to add node: {str(e)}")


@app.get("/api/nodes")
@rate_limit("20/minute")
async def list_nginx_nodes(current_user: TokenData = require_viewer()):
    """List all nginx nodes - requires authentication"""
    nginx_manager = component_manager.get_component('nginx_manager')
    if nginx_manager is None:
        return {"nodes": []}
    
    return {
        "nodes": [node.to_dict() for node in nginx_manager.nodes.values()],
        "total_nodes": len(nginx_manager.nodes)
    }


@app.get("/api/nodes/status")
@rate_limit("20/minute")
async def get_cluster_status(current_user: TokenData = require_viewer()):
    """Get status of all nginx nodes - requires authentication"""
    nginx_manager = component_manager.get_component('nginx_manager')
    if nginx_manager is None:
        raise HTTPException(status_code=404, detail="No nginx manager configured")
    
    try:
        status = await nginx_manager.get_cluster_status()
        return status
    except Exception as e:
        logger.error(f"Failed to get cluster status: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get cluster status: {str(e)}")


@app.post("/api/training/start")
@rate_limit("3/minute")
async def start_training(
    request: SecureTrainingRequest,
    current_user: TokenData = require_operator()
):
    """Start ML model training - requires operator role"""
    ml_engine = component_manager.get_component('ml_engine')
    if ml_engine is None:
        raise HTTPException(status_code=500, detail="ML engine not initialized")
    
    try:
        logger.info(f"Training started by user {current_user.username}")
        ml_engine.train_models(request.training_data, request.labels)
        return {
            "message": "Training completed successfully",
            "is_trained": ml_engine.is_trained,
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        logger.error(f"Training failed: {e}")
        raise HTTPException(status_code=500, detail=f"Training failed: {str(e)}")


@app.post("/api/traffic/start-collection")
@rate_limit("5/minute")
async def start_traffic_collection(
    node_urls: List[str],
    current_user: TokenData = require_operator()
):
    """Start collecting traffic from nginx nodes - requires operator role"""
    
    try:
        # Validate URLs
        if not node_urls:
            raise HTTPException(status_code=400, detail="At least one node URL required")
        
        for url in node_urls:
            if not url.startswith(('http://', 'https://')):
                raise HTTPException(status_code=400, detail=f"Invalid URL format: {url}")
        
        traffic_collector = TrafficCollector(node_urls)
        component_manager.set_component('traffic_collector', traffic_collector)
        
        # Start collection in background
        asyncio.create_task(traffic_collector.start_collection())
        
        logger.info(f"Traffic collection started by user {current_user.username} for nodes: {node_urls}")
        return {
            "message": "Traffic collection started",
            "nodes": node_urls,
            "timestamp": datetime.now().isoformat()
        }
    
    except Exception as e:
        logger.error(f"Failed to start traffic collection: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to start traffic collection: {str(e)}")


@app.get("/api/traffic/stats")
@rate_limit("30/minute")
async def get_traffic_stats(current_user: TokenData = require_viewer()):
    """Get traffic collection statistics - requires authentication"""
    traffic_collector = component_manager.get_component('traffic_collector')
    if traffic_collector is None:
        return {"message": "Traffic collection not started", "total_requests": 0}
    
    try:
        recent_requests = traffic_collector.get_recent_requests(100)
        
        return {
            "total_requests": len(traffic_collector.collected_requests),
            "recent_requests": len(recent_requests),
            "is_collecting": traffic_collector.is_collecting,
            "timestamp": datetime.now().isoformat()
        }
    
    except Exception as e:
        logger.error(f"Failed to get traffic stats: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get traffic stats: {str(e)}")


@app.post("/api/processing/start")
@rate_limit("3/minute")
async def start_real_time_processing(current_user: TokenData = require_operator()):
    """Start real-time processing of traffic"""
    logger.info("API ENDPOINT: Starting real-time processing...")
    
    # Use proper synchronization for state management
    with state_lock:
        if system_state['is_processing']:
            raise HTTPException(status_code=400, detail="Real-time processing is already running")
        
        # Check component availability with proper locking
        ml_engine = component_manager.get_component('ml_engine')
        traffic_collector = component_manager.get_component('traffic_collector')
        
        if ml_engine is None or not ml_engine.is_trained:
            logger.error("API ENDPOINT: ML engine is not trained!")
            raise HTTPException(status_code=400, detail="ML engine must be trained first")
        
        if traffic_collector is None:
            logger.error("API ENDPOINT: Traffic collector is not initialized!")
            raise HTTPException(status_code=400, detail="Traffic collector must be initialized first")
        
        # Initialize real-time processor if needed
        real_time_processor = component_manager.get_component('real_time_processor')
        if real_time_processor is None:
            try:
                real_time_processor = RealTimeProcessor(ml_engine)
                component_manager.set_component('real_time_processor', real_time_processor)
                logger.info("API ENDPOINT: Created new RealTimeProcessor")
            except Exception as e:
                logger.error(f"Failed to create RealTimeProcessor: {e}")
                raise HTTPException(status_code=500, detail=f"Failed to initialize real-time processor: {str(e)}")
        
        # Set processing flag with proper synchronization
        system_state['is_processing'] = True
        logger.info("API ENDPOINT: Real-time processing flag set to True")
    
    # Start background tasks with error handling
    try:
        logger.info("API ENDPOINT: Creating traffic processing task...")
        asyncio.create_task(process_traffic_continuously())
        logger.info("API ENDPOINT: Creating threat processing task...")
        asyncio.create_task(process_threats_continuously())
        logger.info("API ENDPOINT: Both tasks created!")
    except Exception as e:
        # Rollback processing state if task creation fails
        with state_lock:
            system_state['is_processing'] = False
        logger.error(f"Failed to start background tasks: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to start background processing: {str(e)}")
    
    return {
        "message": "Real-time processing started",
        "timestamp": datetime.now().isoformat()
    }


async def process_traffic_continuously():
    """Continuously process traffic from the traffic collector"""
    logger.info("Starting continuous traffic processing...")
    
    # Get current processing state with proper synchronization
    def is_processing_active():
        with state_lock:
            return system_state['is_processing']
    
    while is_processing_active():
        try:
            # Get components safely
            traffic_collector = component_manager.get_component('traffic_collector')
            real_time_processor = component_manager.get_component('real_time_processor')
            
            if traffic_collector and real_time_processor and hasattr(traffic_collector, 'collected_requests'):
                logger.debug(f"Traffic collector has {len(traffic_collector.collected_requests)} collected requests")
                
                # Get recent requests and process a copy to avoid race conditions
                requests_to_process = traffic_collector.get_recent_requests(100)
                logger.debug(f"Found {len(requests_to_process)} requests to process")
                
                if requests_to_process:
                    # Process on a copy and remove processed requests afterward
                    processed_count = 0
                    
                    for request in requests_to_process:
                        try:
                            # Check if we should continue processing
                            if not is_processing_active():
                                logger.info("Processing stopped during request processing")
                                break
                                
                            # Use node_id from the request
                            node_id = request.node_id
                            logger.debug(f"Processing request with node_id: {node_id} from {request.url}")
                            
                            # Process the request with ML engine
                            request_dict = request.to_dict()
                            predictions = await real_time_processor.process_requests([request_dict])
                            prediction = predictions[0] if predictions else None
                            
                            # Extract status code (simulate based on URL)
                            status = '200'
                            if 'admin' in request.url or 'backup' in request.url:
                                status = '403'
                            elif 'nonexistent' in request.url:
                                status = '404'
                            elif prediction and (prediction.threat_score < -0.1 or prediction.confidence > 0.6):
                                status = '403'  # Block threats
                            
                            # Increment metrics
                            print(f"Incrementing metrics: node_id={node_id}, status={status}")
                            requests_total.labels(node_id=node_id, status=status).inc()
                            
                            # Check for threats with updated threshold
                            if prediction and (prediction.threat_score < -0.1 or prediction.confidence > 0.6 or prediction.threat_type != 'normal'):
                                threat_type = prediction.threat_type
                                if threat_type == 'normal':
                                    # Override with pattern-based detection
                                    if request._check_sql_patterns():
                                        threat_type = 'sql_injection'
                                    elif request._check_xss_patterns():
                                        threat_type = 'xss_attack'
                                    elif 'admin' in request.url or 'backup' in request.url or 'config' in request.url:
                                        threat_type = 'unauthorized_access'
                                    elif '/etc/' in request.url or '/.env' in request.url:
                                        threat_type = 'file_access'
                                
                                threats_detected.labels(threat_type=threat_type).inc()
                                print(f"Threat detected: {threat_type} (score: {prediction.threat_score:.3f}, confidence: {prediction.confidence:.3f})")
                            
                            processed_count += 1
                            
                        except Exception as e:
                            logger.error(f"Error processing individual request: {e}")
                            traceback.print_exc()
                    
                    # Clear processed requests to avoid reprocessing
                    if processed_count > 0:
                        traffic_collector.collected_requests = traffic_collector.collected_requests[processed_count:]
                else:
                    print("No requests to process, continuing...")
            else:
                print("Traffic collector not available")
                
        except Exception as e:
            print(f"Error in processing cycle: {e}")
            traceback.print_exc()
        
        # Update active rules count
        waf_rule_generator = component_manager.get_component('waf_rule_generator')
        if waf_rule_generator:
            rules_active.set(len(getattr(waf_rule_generator, 'active_rules', [])))
        
        await asyncio.sleep(2)  # Process every 2 seconds


async def process_threats_continuously():
    """Continuously process threats and generate rules"""
    logger.info("THREAT PROCESSOR: Starting threat processing loop!")
    
    # Get current processing state with proper synchronization
    def is_processing_active():
        with state_lock:
            return system_state['is_processing']
    
    while is_processing_active():
        try:
            # Get components safely
            traffic_collector = component_manager.get_component('traffic_collector')
            real_time_processor = component_manager.get_component('real_time_processor')
            waf_rule_generator = component_manager.get_component('waf_rule_generator')
            
            logger.debug(f"THREAT PROCESSOR: Components check - traffic_collector: {traffic_collector is not None}, real_time_processor: {real_time_processor is not None}, waf_rule_generator: {waf_rule_generator is not None}")
            
            if traffic_collector and real_time_processor and waf_rule_generator:
                # Get recent requests
                recent_requests = traffic_collector.get_recent_requests(100)
                logger.info(f"THREAT PROCESSOR: Threat processor found {len(recent_requests)} recent requests")
                
                if recent_requests:
                    # Check if we should continue processing
                    if not is_processing_active():
                        logger.info("THREAT PROCESSOR: Processing stopped during threat analysis")
                        break
                    
                    # Convert to dict format for ML processing
                    request_dicts = [req.to_dict() for req in recent_requests]
                    
                    # Detect threats
                    logger.info(f"THREAT PROCESSOR: Processing {len(request_dicts)} requests for threat detection...")
                    threats = await real_time_processor.process_requests(request_dicts)
                    logger.info(f"THREAT PROCESSOR: Detected {len(threats)} threats")
                    
                    if threats:
                        # Generate WAF rules
                        threat_patterns = real_time_processor.get_threat_patterns()
                        threat_dicts = [threat.to_dict() for threat in threats]
                        
                        logger.info(f"THREAT PROCESSOR: Generating rules from {len(threat_dicts)} threats...")
                        new_rules = waf_rule_generator.generate_rules_from_threats(
                            threat_dicts, threat_patterns
                        )
                        logger.info(f"THREAT PROCESSOR: Generated {len(new_rules)} new WAF rules")
                        
                        if new_rules and nginx_manager:
                            # Deploy rules to nginx nodes
                            logger.info(f"THREAT PROCESSOR: Deploying {len(new_rules)} rules to nginx nodes...")
                            nginx_config = waf_rule_generator.generate_nginx_config(new_rules)
                            await nginx_manager.deploy_rules_to_all_nodes(nginx_config)
                            logger.info("THREAT PROCESSOR: Rules deployed successfully")
                    else:
                        logger.debug("THREAT PROCESSOR: No threats detected in this cycle")
                else:
                    logger.debug("THREAT PROCESSOR: No recent requests for threat processing")
            else:
                missing = []
                if not traffic_collector: missing.append("traffic_collector")
                if not real_time_processor: missing.append("real_time_processor") 
                if not waf_rule_generator: missing.append("waf_rule_generator")
                logger.warning(f"THREAT PROCESSOR: Threat processing skipped - missing: {missing}")
                
            # Clean up old data (temporarily disabled for debugging)
            # if traffic_collector:
            #     traffic_collector.clear_old_requests(60)
        
        except Exception as e:
            logger.error(f"THREAT PROCESSOR: Error in threat processing cycle: {e}")
            traceback.print_exc()
        
        await asyncio.sleep(10)  # Process every 10 seconds
    
    logger.info("THREAT PROCESSOR: Threat processing loop ended!")


@app.get("/api/threats")
@rate_limit("20/minute")
async def get_recent_threats(current_user: TokenData = require_viewer()) -> ThreatResponse:
    """Get recent threat detections - requires authentication"""
    real_time_processor = component_manager.get_component('real_time_processor')
    if real_time_processor is None:
        return ThreatResponse(threats=[], total_threats=0, threat_patterns={})
    
    threats = [threat.to_dict() for threat in real_time_processor.recent_threats]
    threat_patterns = real_time_processor.get_threat_patterns()
    
    return ThreatResponse(
        threats=threats,
        total_threats=len(threats),
        threat_patterns=threat_patterns
    )


@app.get("/api/rules")
@rate_limit("20/minute")
async def get_active_rules(current_user: TokenData = require_viewer()):
    """Get currently active WAF rules - requires authentication"""
    waf_rule_generator = component_manager.get_component('waf_rule_generator')
    if waf_rule_generator is None:
        return {"rules": [], "total_rules": 0}
    
    active_rules = waf_rule_generator.get_active_rules()
    
    return {
        "rules": [rule.to_dict() for rule in active_rules],
        "total_rules": len(active_rules),
        "timestamp": datetime.now().isoformat()
    }


@app.post("/api/rules/deploy")
@rate_limit("3/minute")
async def deploy_rules(
    request: SecureRuleDeploymentRequest,
    current_user: TokenData = require_admin()
):
    """Deploy WAF rules to nginx nodes - requires admin role"""
    nginx_manager = component_manager.get_component('nginx_manager')
    if nginx_manager is None:
        raise HTTPException(status_code=404, detail="No nginx manager configured")
    
    waf_rule_generator = component_manager.get_component('waf_rule_generator')
    if waf_rule_generator is None:
        raise HTTPException(status_code=500, detail="WAF rule generator not initialized")
    
    try:
        # Convert dict rules back to WAFRule objects if needed
        rules = waf_rule_generator.get_active_rules()
        
        rule_optimizer = component_manager.get_component('rule_optimizer')
        if rule_optimizer:
            try:
                rules = rule_optimizer.optimize_rules(rules)
                logger.info("Rules optimized successfully")
            except Exception as e:
                logger.warning(f"Rule optimization failed: {e}, proceeding with original rules")
        
        # Generate nginx configuration with validation
        try:
            nginx_config = waf_rule_generator.generate_nginx_config(rules)
            
            # Validate nginx configuration before deployment
            if hasattr(nginx_manager, '_validate_nginx_config'):
                if not nginx_manager._validate_nginx_config(nginx_config):
                    raise HTTPException(status_code=400, detail="Generated nginx configuration is invalid")
            
        except Exception as e:
            logger.error(f"Failed to generate nginx configuration: {e}")
            raise HTTPException(status_code=500, detail=f"Configuration generation failed: {str(e)}")
        
        # Deploy to specified nodes or all nodes with comprehensive error handling
        try:
            if request.node_ids:
                # Deploy to specific nodes (would need to implement selective deployment)
                deployment_results = await nginx_manager.deploy_rules_to_all_nodes(nginx_config)
            else:
                deployment_results = await nginx_manager.deploy_rules_to_all_nodes(nginx_config)
            
            # Check deployment results
            failed_deployments = [node_id for node_id, success in deployment_results.items() if not success]
            if failed_deployments:
                logger.warning(f"Deployment failed for nodes: {failed_deployments}")
                if len(failed_deployments) == len(deployment_results):
                    raise HTTPException(status_code=500, detail="Deployment failed on all nodes")
        
        except Exception as e:
            logger.error(f"Deployment error: {e}")
            raise HTTPException(status_code=500, detail=f"Deployment failed: {str(e)}")
        
        logger.info(f"Rules deployed by user {current_user.username}")
        return {
            "message": "Rules deployment initiated",
            "deployment_results": deployment_results,
            "total_rules": len(rules),
            "timestamp": datetime.now().isoformat()
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Unexpected error during rule deployment: {e}")
        raise HTTPException(status_code=500, detail=f"Deployment error: {str(e)}")


@app.get("/api/config/nginx")
@rate_limit("10/minute")
async def get_nginx_config(current_user: TokenData = require_operator()):
    """Generate and return nginx configuration - requires operator role"""
    waf_rule_generator = component_manager.get_component('waf_rule_generator')
    if waf_rule_generator is None:
        raise HTTPException(status_code=500, detail="WAF rule generator not initialized")
    
    try:
        active_rules = waf_rule_generator.get_active_rules()
        nginx_config = waf_rule_generator.generate_nginx_config(active_rules)
        
        return {
            "config": nginx_config,
            "total_rules": len(active_rules),
            "timestamp": datetime.now().isoformat()
        }
    
    except Exception as e:
        logger.error(f"Failed to generate nginx config: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to generate nginx config: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to generate nginx config: {str(e)}")


@app.post("/api/processing/stop")
@rate_limit("5/minute")
async def stop_processing(current_user: TokenData = require_operator()):
    """Stop real-time processing - requires operator role"""
    try:
        with state_lock:
            if not system_state['is_processing']:
                raise HTTPException(status_code=400, detail="Real-time processing is not currently running")
            
            system_state['is_processing'] = False
            logger.info(f"Real-time processing stopped by user {current_user.username}")
        
        # Allow some time for background tasks to gracefully stop
        await asyncio.sleep(1)
        
        return {
            "message": "Real-time processing stopped",
            "timestamp": datetime.now().isoformat()
        }
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to stop processing: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to stop processing: {str(e)}")


@app.get("/api/stats")
@rate_limit("20/minute")
async def get_system_stats(current_user: TokenData = require_viewer()):
    """Get overall system statistics - requires authentication"""
    try:
        # Get components safely
        ml_engine = component_manager.get_component('ml_engine')
        traffic_collector = component_manager.get_component('traffic_collector')
        real_time_processor = component_manager.get_component('real_time_processor')
        waf_rule_generator = component_manager.get_component('waf_rule_generator')
        nginx_manager = component_manager.get_component('nginx_manager')
        
        # Get processing state safely
        with state_lock:
            is_processing = system_state['is_processing']
        
        stats = {
            "timestamp": datetime.now().isoformat(),
            "components": {
                "ml_engine_trained": ml_engine is not None and ml_engine.is_trained,
                "traffic_collection_active": traffic_collector is not None and traffic_collector.is_collecting,
                "real_time_processing": is_processing,
                "nginx_nodes_count": len(nginx_manager.nodes) if nginx_manager else 0
            },
            "traffic": {
                "total_requests": len(traffic_collector.collected_requests) if traffic_collector else 0,
                "recent_requests": len(traffic_collector.get_recent_requests(100)) if traffic_collector else 0
            },
            "threats": {
                "total_threats": len(real_time_processor.recent_threats) if real_time_processor else 0
            },
            "rules": {
                "active_rules": len(waf_rule_generator.get_active_rules()) if waf_rule_generator else 0
            }
        }
        
        return stats
    
    except Exception as e:
        logger.error(f"Failed to get system stats: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get system stats: {str(e)}")


async def process_traffic_continuously():
    """Continuously process traffic from the traffic collector"""
    global traffic_collector, real_time_processor, is_processing
    
    logger.info("Starting continuous traffic processing...")
    
    while is_processing:
        try:
            logger.debug(f"Processing cycle - is_processing: {is_processing}")
            
            if traffic_collector and hasattr(traffic_collector, 'collected_requests'):
                logger.debug(f"Traffic collector has {len(traffic_collector.collected_requests)} collected requests")
                
                # Get recent requests to process
                recent_requests = traffic_collector.get_recent_requests(100)
                
                if recent_requests and real_time_processor:
                    logger.debug(f"Processing {len(recent_requests)} recent requests")
                    
                    # Process requests for threats
                    for request in recent_requests:
                        try:
                            features = traffic_collector.extract_features(request)
                            prediction = real_time_processor.process_request(features)
                            
                            if prediction and prediction.threat_score < -0.1:
                                logger.info(f"Threat detected: {prediction.threat_type} (score: {prediction.threat_score})")
                                threats_detected.labels(threat_type=prediction.threat_type).inc()
                                
                        except Exception as e:
                            logger.error(f"Error processing request: {e}")
                            continue
                
                else:
                    logger.debug("No recent requests or real_time_processor not available")
            
            else:
                logger.debug("Traffic collector not available or no collected_requests attribute")
            
            # Sleep between processing cycles
            await asyncio.sleep(1)
            
        except Exception as e:
            logger.error(f"Error in traffic processing loop: {e}")
            await asyncio.sleep(5)  # Wait longer on error
    
    logger.info("Traffic processing stopped")


async def process_threats_continuously():
    """Continuously process detected threats and generate rules"""
    global real_time_processor, waf_rule_generator, is_processing
    
    logger.info("Starting continuous threat processing...")
    
    while is_processing:
        try:
            if real_time_processor and waf_rule_generator:
                # Get recent threats
                recent_threats = real_time_processor.get_recent_threats(limit=50)
                
                if recent_threats:
                    logger.debug(f"Processing {len(recent_threats)} recent threats for rule generation")
                    
                    # Generate rules based on threats
                    new_rules = waf_rule_generator.generate_rules_from_threats(recent_threats)
                    
                    if new_rules:
                        logger.info(f"Generated {len(new_rules)} new WAF rules")
                        # Update active rules count metric
                        rules_active.set(len(waf_rule_generator.get_active_rules()))
            
            # Sleep between threat processing cycles
            await asyncio.sleep(10)
            
        except Exception as e:
            logger.error(f"Error in threat processing loop: {e}")
            await asyncio.sleep(30)  # Wait longer on error
    
    logger.info("Threat processing stopped")


# ============= TLS/HTTPS CONFIGURATION =============

def create_ssl_context():
    """Create SSL context for HTTPS"""
    if not config.security.use_https:
        return None
    
    try:
        ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        ssl_context.load_cert_chain(
            config.security.ssl_cert_path,
            config.security.ssl_key_path
        )
        ssl_context.check_hostname = False
        ssl_context.verify_mode = config.security.ssl_verify_mode
        
        logger.info("SSL context created successfully")
        return ssl_context
    
    except Exception as e:
        logger.error(f"Failed to create SSL context: {e}")
        raise


# ============= SERVER STARTUP =============

if __name__ == "__main__":
    # Create SSL context if HTTPS is enabled
    ssl_context = create_ssl_context()
    
    # Configure uvicorn
    uvicorn_config = {
        "host": config.api_host,
        "port": config.api_port,
        "log_level": config.log_level.lower(),
        "access_log": True,
        "server_header": False,  # Security: don't reveal server info
        "date_header": False     # Security: don't reveal server time
    }
    
    if ssl_context:
        uvicorn_config["ssl_context"] = ssl_context
        logger.info(f"Starting HTTPS server on {config.api_host}:{config.api_port}")
    else:
        logger.info(f"Starting HTTP server on {config.api_host}:{config.api_port}")
    
    if config.api_debug:
        logger.warning("Debug mode enabled - disable in production!")
        uvicorn_config["reload"] = True
    
    # Start the server
    uvicorn.run(app, **uvicorn_config)
