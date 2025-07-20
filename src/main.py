"""
Main API Module

FastAPI-based API for the nginx WAF AI system.
"""

from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Dict, Optional
import asyncio
from datetime import datetime
import uvicorn

from .traffic_collector import TrafficCollector, HttpRequest
from .ml_engine import MLEngine, RealTimeProcessor, ThreatPrediction
from .waf_rule_generator import WAFRuleGenerator, WAFRule, RuleOptimizer
from .nginx_manager import NginxManager, NginxNode


app = FastAPI(
    title="Nginx WAF AI",
    description="Real-time machine learning WAF rule generator for nginx",
    version="0.1.0"
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global components
traffic_collector: Optional[TrafficCollector] = None
ml_engine: Optional[MLEngine] = None
real_time_processor: Optional[RealTimeProcessor] = None
waf_rule_generator: Optional[WAFRuleGenerator] = None
nginx_manager: Optional[NginxManager] = None
rule_optimizer: Optional[RuleOptimizer] = None

# Background task status
is_processing = False


# Pydantic models for API
class NginxNodeModel(BaseModel):
    node_id: str
    hostname: str
    ssh_host: str
    ssh_port: int = 22
    ssh_username: str
    ssh_key_path: Optional[str] = None
    nginx_config_path: str = "/etc/nginx/conf.d"
    nginx_reload_command: str = "sudo systemctl reload nginx"
    api_endpoint: Optional[str] = None


class TrainingRequest(BaseModel):
    training_data: List[Dict]
    labels: Optional[List[str]] = None


class ThreatResponse(BaseModel):
    threats: List[Dict]
    total_threats: int
    threat_patterns: Dict[str, int]


class RuleDeploymentRequest(BaseModel):
    rules: List[Dict]
    node_ids: Optional[List[str]] = None


@app.on_event("startup")
async def startup_event():
    """Initialize components on startup"""
    global ml_engine, waf_rule_generator, rule_optimizer
    
    ml_engine = MLEngine()
    waf_rule_generator = WAFRuleGenerator()
    rule_optimizer = RuleOptimizer()
    
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
async def start_real_time_processing(background_tasks: BackgroundTasks):
    """Start real-time threat processing"""
    global real_time_processor, is_processing
    
    if ml_engine is None or not ml_engine.is_trained:
        raise HTTPException(status_code=400, detail="ML engine must be trained first")
    
    if traffic_collector is None:
        raise HTTPException(status_code=400, detail="Traffic collection must be started first")
    
    real_time_processor = RealTimeProcessor(ml_engine)
    is_processing = True
    
    # Start processing in background
    background_tasks.add_task(process_threats_continuously)
    
    return {
        "message": "Real-time processing started",
        "timestamp": datetime.now().isoformat()
    }


async def process_threats_continuously():
    """Continuously process threats and generate rules"""
    global is_processing
    
    while is_processing:
        try:
            if traffic_collector and real_time_processor and waf_rule_generator:
                # Get recent requests
                recent_requests = traffic_collector.get_recent_requests(100)
                
                if recent_requests:
                    # Convert to dict format for ML processing
                    request_dicts = [req.to_dict() for req in recent_requests]
                    
                    # Detect threats
                    threats = await real_time_processor.process_requests(request_dicts)
                    
                    if threats:
                        # Generate WAF rules
                        threat_patterns = real_time_processor.get_threat_patterns()
                        threat_dicts = [threat.to_dict() for threat in threats]
                        
                        new_rules = waf_rule_generator.generate_rules_from_threats(
                            threat_dicts, threat_patterns
                        )
                        
                        if new_rules and nginx_manager:
                            # Deploy rules to nginx nodes
                            nginx_config = waf_rule_generator.generate_nginx_config(new_rules)
                            await nginx_manager.deploy_rules_to_all_nodes(nginx_config)
                
                # Clean up old data
                traffic_collector.clear_old_requests(60)
        
        except Exception as e:
            print(f"Error in continuous processing: {e}")
        
        await asyncio.sleep(10)  # Process every 10 seconds


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
