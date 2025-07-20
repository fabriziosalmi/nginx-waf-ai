"""
Main API Module

FastAPI-based API for the nginx WAF AI system with comprehensive security.
"""

import asyncio
import os
import ssl
import threading
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

# Thread-safe locks for global variables
processing_lock = threading.Lock()
component_lock = threading.Lock()

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifespan context manager for startup/shutdown"""
    # Startup
    logger.info("Starting Nginx WAF AI system...")
    await startup_components()
    
    yield
    
    # Shutdown
    logger.info("Shutting down Nginx WAF AI system...")
    await shutdown_components()


# Create FastAPI app with security middleware
app = FastAPI(
    title="Nginx WAF AI",
    description="Real-time machine learning WAF rule generator for nginx",
    version="0.1.0",
    lifespan=lifespan,
    docs_url="/docs" if config.api_debug else None,  # Disable docs in production
    redoc_url="/redoc" if config.api_debug else None
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

# Global components with thread safety
traffic_collector: Optional[TrafficCollector] = None
ml_engine: Optional[MLEngine] = None
real_time_processor: Optional[RealTimeProcessor] = None
waf_rule_generator: Optional[WAFRuleGenerator] = None
nginx_manager: Optional[NginxManager] = None
rule_optimizer: Optional[RuleOptimizer] = None

# Background task status
is_processing = False


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
    """Initialize system components"""
    global ml_engine, waf_rule_generator, rule_optimizer, traffic_collector
    
    try:
        with component_lock:
            logger.info("Initializing ML engine...")
            ml_engine = MLEngine()
            
            logger.info("Initializing WAF rule generator...")
            waf_rule_generator = WAFRuleGenerator()
            
            logger.info("Initializing rule optimizer...")
            rule_optimizer = RuleOptimizer()
            
            # Initialize traffic collector with environment variable
            nginx_nodes_env = os.getenv('NGINX_NODES', '')
            logger.info(f"NGINX_NODES environment variable: '{nginx_nodes_env}'")
            
            if nginx_nodes_env:
                node_urls = [url.strip() for url in nginx_nodes_env.split(',') if url.strip()]
                logger.info(f"Parsed node URLs: {node_urls}")
                if node_urls:
                    traffic_collector = TrafficCollector(node_urls)
                    # Start collection in background
                    asyncio.create_task(traffic_collector.start_collection())
                    logger.info(f"Traffic collection started for nodes: {node_urls}")
            else:
                logger.warning("No NGINX_NODES environment variable found")
            
            logger.info("Nginx WAF AI system components initialized successfully")
    
    except Exception as e:
        logger.error(f"Failed to initialize components: {e}")
        raise


async def shutdown_components():
    """Shutdown system components gracefully"""
    global is_processing, traffic_collector
    
    logger.info("Shutting down background processing...")
    is_processing = False
    
    if traffic_collector:
        logger.info("Stopping traffic collection...")
        traffic_collector.is_collecting = False
    
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
async def list_users(current_user: TokenData = require_admin()):
    """List all users (admin only)"""
    try:
        return auth_manager.get_user_stats()
    except Exception as e:
        logger.error(f"User listing error: {e}")
        raise HTTPException(status_code=500, detail="Failed to list users")


# ============= PUBLIC ENDPOINTS =============

@app.get("/")
@limiter.limit("30/minute")
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
@limiter.limit("60/minute")
async def health_check():
    """Health check endpoint"""
    try:
        with component_lock:
            return {
                "status": "healthy",
                "components": {
                    "ml_engine": ml_engine is not None and getattr(ml_engine, 'is_trained', False),
                    "traffic_collector": traffic_collector is not None,
                    "waf_generator": waf_rule_generator is not None,
                    "nginx_manager": nginx_manager is not None,
                    "authentication": True,
                    "rate_limiting": True
                },
                "timestamp": datetime.now().isoformat()
            }
    except Exception as e:
        logger.error(f"Health check error: {e}")
        return {"status": "unhealthy", "error": str(e)}
    
    if nginx_nodes_env:
        node_urls = [url.strip() for url in nginx_nodes_env.split(',') if url.strip()]
        print(f"Parsed node URLs: {node_urls}")
        if node_urls:
            traffic_collector = TrafficCollector(node_urls)
            # Start collection in background
            asyncio.create_task(traffic_collector.start_collection())
            print(f"Traffic collection started for nodes: {node_urls}")
    else:
        print("No NGINX_NODES environment variable found")
    
    print("Nginx WAF AI system initialized")


@app.get("/")
async def root():
    """Root endpoint"""
    return {
        "message": "Nginx WAF AI System",
        "version": "0.1.0",
        "status": "running",
        "timestamp": datetime.now().isoformat()
    }


@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "components": {
            "ml_engine": ml_engine is not None and ml_engine.is_trained,
            "traffic_collector": traffic_collector is not None,
            "waf_generator": waf_rule_generator is not None,
            "nginx_manager": nginx_manager is not None
        },
        "timestamp": datetime.now().isoformat()
    }


@app.get("/api/debug/status")
async def debug_status():
    """Debug endpoint to check system status"""
    global traffic_collector, ml_engine, real_time_processor, is_processing
    
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
        }
    }
    
    return status

@app.post("/api/debug/test-prediction")
async def test_prediction():
    """Debug endpoint to test ML predictions on sample malicious requests"""
    if ml_engine is None or not ml_engine.is_trained:
        raise HTTPException(status_code=400, detail="ML engine not trained")
    
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


@app.get("/api/status")
async def get_system_status():
    """Get system status for debugging"""
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


@app.get("/metrics")
async def get_metrics():
    """Prometheus metrics endpoint"""
    # Update gauge metrics
    if nginx_manager:
        nodes_registered.set(len(nginx_manager.nodes))
    
    if waf_rule_generator:
        # This would need to be implemented in the rule generator
        rules_active.set(0)  # Placeholder
    
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)


@app.post("/api/nodes/add")
async def add_nginx_node(node: NginxNodeModel):
    """Add a new nginx node to the cluster"""
    global nginx_manager
    
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
    
    if nginx_manager is None:
        nginx_manager = NginxManager([nginx_node])
    else:
        nginx_manager.add_node(nginx_node)
    
    return {"message": f"Node {node.node_id} added successfully"}


@app.get("/api/nodes")
async def list_nginx_nodes():
    """List all nginx nodes"""
    if nginx_manager is None:
        return {"nodes": []}
    
    return {
        "nodes": [node.to_dict() for node in nginx_manager.nodes.values()],
        "total_nodes": len(nginx_manager.nodes)
    }


@app.get("/api/nodes/status")
async def get_cluster_status():
    """Get status of all nginx nodes"""
    if nginx_manager is None:
        raise HTTPException(status_code=404, detail="No nginx manager configured")
    
    status = await nginx_manager.get_cluster_status()
    return status


@app.post("/api/training/start")
async def start_training(request: TrainingRequest):
    """Start ML model training"""
    if ml_engine is None:
        raise HTTPException(status_code=500, detail="ML engine not initialized")
    
    try:
        ml_engine.train_models(request.training_data, request.labels)
        return {
            "message": "Training completed successfully",
            "is_trained": ml_engine.is_trained,
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Training failed: {str(e)}")


@app.post("/api/traffic/start-collection")
async def start_traffic_collection(node_urls: List[str]):
    """Start collecting traffic from nginx nodes"""
    global traffic_collector
    
    traffic_collector = TrafficCollector(node_urls)
    
    # Start collection in background
    asyncio.create_task(traffic_collector.start_collection())
    
    return {
        "message": "Traffic collection started",
        "nodes": node_urls,
        "timestamp": datetime.now().isoformat()
    }


@app.get("/api/traffic/stats")
async def get_traffic_stats():
    """Get traffic collection statistics"""
    if traffic_collector is None:
        return {"message": "Traffic collection not started", "total_requests": 0}
    
    recent_requests = traffic_collector.get_recent_requests(100)
    
    return {
        "total_requests": len(traffic_collector.collected_requests),
        "recent_requests": len(recent_requests),
        "is_collecting": traffic_collector.is_collecting,
        "timestamp": datetime.now().isoformat()
    }


@app.post("/api/processing/start")
async def start_real_time_processing():
    """Start real-time processing of traffic"""
    global real_time_processor, is_processing
    
    logger.info("API ENDPOINT: Starting real-time processing...")
    
    if ml_engine is None or not ml_engine.is_trained:
        logger.error("API ENDPOINT: ML engine is not trained!")
        raise HTTPException(status_code=400, detail="ML engine must be trained first")
    
    if traffic_collector is None:
        logger.error("API ENDPOINT: Traffic collector is not initialized!")
        raise HTTPException(status_code=400, detail="Traffic collector must be initialized first")
    
    if real_time_processor is None:
        real_time_processor = RealTimeProcessor(ml_engine)
        logger.info("API ENDPOINT: Created new RealTimeProcessor")
    
    # Set processing flag first
    is_processing = True
    logger.info(f"API ENDPOINT: Set is_processing to {is_processing}")
    
    # Start background tasks to process collected traffic and threats
    logger.info("API ENDPOINT: Creating traffic processing task...")
    asyncio.create_task(process_traffic_continuously())
    logger.info("API ENDPOINT: Creating threat processing task...")
    asyncio.create_task(process_threats_continuously())
    logger.info("API ENDPOINT: Both tasks created!")
    
    return {
        "message": "Real-time processing started",
        "timestamp": datetime.now().isoformat()
    }


async def process_traffic_continuously():
    """Continuously process traffic from the traffic collector"""
    global traffic_collector, real_time_processor, is_processing
    
    while is_processing:
        try:
            print(f"Processing cycle - is_processing: {is_processing}")
            if traffic_collector and hasattr(traffic_collector, 'collected_requests'):
                print(f"Traffic collector has {len(traffic_collector.collected_requests)} collected requests")
                
                # Get recent requests and process a copy to avoid race conditions
                requests_to_process = traffic_collector.get_recent_requests(100)
                print(f"Found {len(requests_to_process)} requests to process")
                
                if requests_to_process:
                    # Process on a copy and remove processed requests afterward
                    processed_count = 0
                    
                    for request in requests_to_process:
                        try:
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
                            import traceback
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
            import traceback
            traceback.print_exc()
        
        # Update active rules count
        if waf_rule_generator:
            rules_active.set(len(getattr(waf_rule_generator, 'active_rules', [])))
        
        await asyncio.sleep(2)  # Process every 2 seconds


async def process_threats_continuously():
    """Continuously process threats and generate rules"""
    global is_processing
    
    logger.info("THREAT PROCESSOR: Starting threat processing loop!")
    
    while is_processing:
        try:
            logger.debug(f"THREAT PROCESSOR: Threat processing cycle - is_processing: {is_processing}")
            logger.debug(f"THREAT PROCESSOR: Components check - traffic_collector: {traffic_collector is not None}, real_time_processor: {real_time_processor is not None}, waf_rule_generator: {waf_rule_generator is not None}")
            
            if traffic_collector and real_time_processor and waf_rule_generator:
                # Get recent requests
                recent_requests = traffic_collector.get_recent_requests(100)
                logger.info(f"THREAT PROCESSOR: Threat processor found {len(recent_requests)} recent requests")
                
                if recent_requests:
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
            import traceback
            traceback.print_exc()
        
        await asyncio.sleep(10)  # Process every 10 seconds
    
    logger.info("THREAT PROCESSOR: Threat processing loop ended!")


@app.get("/api/threats")
async def get_recent_threats() -> ThreatResponse:
    """Get recent threat detections"""
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
async def get_active_rules():
    """Get currently active WAF rules"""
    if waf_rule_generator is None:
        return {"rules": [], "total_rules": 0}
    
    active_rules = waf_rule_generator.get_active_rules()
    
    return {
        "rules": [rule.to_dict() for rule in active_rules],
        "total_rules": len(active_rules),
        "timestamp": datetime.now().isoformat()
    }


@app.post("/api/rules/deploy")
async def deploy_rules(request: RuleDeploymentRequest):
    """Deploy WAF rules to nginx nodes"""
    if nginx_manager is None:
        raise HTTPException(status_code=404, detail="No nginx manager configured")
    
    if waf_rule_generator is None:
        raise HTTPException(status_code=500, detail="WAF rule generator not initialized")
    
    # Convert dict rules back to WAFRule objects if needed
    rules = waf_rule_generator.get_active_rules()
    
    if rule_optimizer:
        rules = rule_optimizer.optimize_rules(rules)
    
    # Generate nginx configuration
    nginx_config = waf_rule_generator.generate_nginx_config(rules)
    
    # Deploy to specified nodes or all nodes
    if request.node_ids:
        # Deploy to specific nodes (would need to implement selective deployment)
        deployment_results = await nginx_manager.deploy_rules_to_all_nodes(nginx_config)
    else:
        deployment_results = await nginx_manager.deploy_rules_to_all_nodes(nginx_config)
    
    return {
        "message": "Rules deployment initiated",
        "deployment_results": deployment_results,
        "total_rules": len(rules),
        "timestamp": datetime.now().isoformat()
    }


@app.get("/api/config/nginx")
async def get_nginx_config():
    """Generate and return nginx configuration"""
    if waf_rule_generator is None:
        raise HTTPException(status_code=500, detail="WAF rule generator not initialized")
    
    active_rules = waf_rule_generator.get_active_rules()
    nginx_config = waf_rule_generator.generate_nginx_config(active_rules)
    
    return {
        "config": nginx_config,
        "total_rules": len(active_rules),
        "timestamp": datetime.now().isoformat()
    }


@app.post("/api/processing/stop")
async def stop_processing():
    """Stop real-time processing"""
    global is_processing
    is_processing = False
    
    return {
        "message": "Real-time processing stopped",
        "timestamp": datetime.now().isoformat()
    }


@app.get("/api/stats")
async def get_system_stats():
    """Get overall system statistics"""
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
            "recent_threats": len(real_time_processor.recent_threats) if real_time_processor else 0
        },
        "rules": {
            "active_rules": len(waf_rule_generator.get_active_rules()) if waf_rule_generator else 0,
            "deployment_history": len(nginx_manager.deployment_history) if nginx_manager else 0
        }
    }
    
    return stats


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
