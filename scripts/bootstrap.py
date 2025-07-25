#!/usr/bin/env python3
"""
Bootstrap script for WAF AI system in Docker Compose environment.
This script will:
1. Wait for all services to be ready
2. Register nginx nodes
3. Start traffic collection
4. Train ML model with initial data
5. Start real-time processing
6. Verify metrics flow to monitoring
"""

import asyncio
import aiohttp
import json
import time
import logging
from typing import List, Dict
import sys
import os

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Configuration
WAF_API_BASE = "http://localhost:8000"
GRAFANA_BASE = "http://localhost:3000"
PROMETHEUS_BASE = "http://localhost:9090"

# Default credentials
DEFAULT_USERNAME = "admin"
DEFAULT_PASSWORD = "admin123"

# Nginx nodes configuration for Docker Compose
NGINX_NODES = [
    {
        "node_id": "nginx-node-1",
        "hostname": "nginx-node-1",
        "ssh_host": "nginx-node-1",
        "ssh_port": 22,
        "ssh_username": "root",
        "ssh_key_path": "/dev/null",  # Not used in Docker
        "nginx_config_path": "/etc/nginx/conf.d",
        "nginx_reload_command": "nginx -s reload",
        "api_endpoint": "http://log-server-1:8080"
    },
    {
        "node_id": "nginx-node-2", 
        "hostname": "nginx-node-2",
        "ssh_host": "nginx-node-2",
        "ssh_port": 22,
        "ssh_username": "root",
        "ssh_key_path": "/dev/null",  # Not used in Docker
        "nginx_config_path": "/etc/nginx/conf.d",
        "nginx_reload_command": "nginx -s reload",
        "api_endpoint": "http://log-server-2:8080"
    }
]

# Training data for initial ML model
TRAINING_DATA = [
    # SQL Injection samples
    {"url": "/login?user=admin' OR '1'='1'", "method": "GET", "contains_sql_patterns": True, "contains_xss_patterns": False, "url_length": 35, "suspicious_keywords": 1},
    {"url": "/search?q=' UNION SELECT * FROM users--", "method": "GET", "contains_sql_patterns": True, "contains_xss_patterns": False, "url_length": 40, "suspicious_keywords": 2},
    {"url": "/admin/users.php?id=1'; DROP TABLE users;--", "method": "GET", "contains_sql_patterns": True, "contains_xss_patterns": False, "url_length": 45, "suspicious_keywords": 2},
    
    # XSS samples
    {"url": "/search?q=<script>alert('xss')</script>", "method": "GET", "contains_sql_patterns": False, "contains_xss_patterns": True, "url_length": 42, "suspicious_keywords": 1},
    {"url": "/comment?text=<img src=x onerror=alert(1)>", "method": "POST", "contains_sql_patterns": False, "contains_xss_patterns": True, "url_length": 43, "suspicious_keywords": 1},
    {"url": "/profile?name=<iframe src=javascript:alert()>", "method": "GET", "contains_sql_patterns": False, "contains_xss_patterns": True, "url_length": 45, "suspicious_keywords": 1},
    
    # Directory traversal
    {"url": "/files?path=../../../etc/passwd", "method": "GET", "contains_sql_patterns": False, "contains_xss_patterns": False, "url_length": 32, "suspicious_keywords": 1},
    {"url": "/download?file=..\\..\\windows\\system32\\config\\sam", "method": "GET", "contains_sql_patterns": False, "contains_xss_patterns": False, "url_length": 52, "suspicious_keywords": 1},
    
    # Normal requests
    {"url": "/", "method": "GET", "contains_sql_patterns": False, "contains_xss_patterns": False, "url_length": 1, "suspicious_keywords": 0},
    {"url": "/api/status", "method": "GET", "contains_sql_patterns": False, "contains_xss_patterns": False, "url_length": 11, "suspicious_keywords": 0},
    {"url": "/login", "method": "GET", "contains_sql_patterns": False, "contains_xss_patterns": False, "url_length": 6, "suspicious_keywords": 0},
    {"url": "/dashboard", "method": "GET", "contains_sql_patterns": False, "contains_xss_patterns": False, "url_length": 10, "suspicious_keywords": 0},
    {"url": "/products?category=electronics", "method": "GET", "contains_sql_patterns": False, "contains_xss_patterns": False, "url_length": 30, "suspicious_keywords": 0},
    {"url": "/search?q=laptop", "method": "GET", "contains_sql_patterns": False, "contains_xss_patterns": False, "url_length": 17, "suspicious_keywords": 0},
    {"url": "/api/users", "method": "GET", "contains_sql_patterns": False, "contains_xss_patterns": False, "url_length": 10, "suspicious_keywords": 0},
    {"url": "/contact", "method": "POST", "contains_sql_patterns": False, "contains_xss_patterns": False, "url_length": 8, "suspicious_keywords": 0}
]

# Labels: 1 = malicious, 0 = benign
TRAINING_LABELS = [1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0]

class WAFBootstrap:
    def __init__(self):
        self.session = None
        self.auth_token = None
        
    async def __aenter__(self):
        self.session = aiohttp.ClientSession()
        return self
        
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()
    
    async def wait_for_service(self, url: str, timeout: int = 300) -> bool:
        """Wait for a service to be ready"""
        logger.info(f"Waiting for {url} to be ready...")
        start_time = time.time()
        
        while time.time() - start_time < timeout:
            try:
                async with self.session.get(url, timeout=aiohttp.ClientTimeout(total=5)) as resp:
                    if resp.status == 200:
                        logger.info(f"✓ {url} is ready")
                        return True
            except Exception:
                pass
            await asyncio.sleep(5)
        
        logger.error(f"✗ {url} failed to become ready within {timeout}s")
        return False
    
    async def authenticate(self) -> bool:
        """Authenticate with WAF API"""
        try:
            auth_data = {
                "username": DEFAULT_USERNAME,
                "password": DEFAULT_PASSWORD
            }
            
            async with self.session.post(
                f"{WAF_API_BASE}/auth/login",
                json=auth_data,
                timeout=aiohttp.ClientTimeout(total=10)
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    self.auth_token = data.get("access_token")
                    logger.info("✓ Authentication successful")
                    return True
                else:
                    logger.error(f"✗ Authentication failed: {resp.status}")
                    return False
        except Exception as e:
            logger.error(f"✗ Authentication error: {e}")
            return False
    
    async def api_call(self, method: str, endpoint: str, data: Dict = None) -> Dict:
        """Make authenticated API call"""
        headers = {}
        if self.auth_token:
            headers["Authorization"] = f"Bearer {self.auth_token}"
        
        kwargs = {
            "headers": headers,
            "timeout": aiohttp.ClientTimeout(total=30)
        }
        
        if data:
            kwargs["json"] = data
        
        async with self.session.request(method, f"{WAF_API_BASE}{endpoint}", **kwargs) as resp:
            if resp.status in [200, 201]:
                return await resp.json()
            else:
                text = await resp.text()
                raise Exception(f"API call failed: {resp.status} - {text}")
    
    async def register_nodes(self) -> bool:
        """Register nginx nodes"""
        logger.info("Registering nginx nodes...")
        
        try:
            for node in NGINX_NODES:
                try:
                    await self.api_call("POST", "/api/nodes/add", node)
                    logger.info(f"✓ Registered node: {node['node_id']}")
                except Exception as e:
                    logger.warning(f"Could not register {node['node_id']}: {e}")
            
            # Verify nodes are registered
            nodes_data = await self.api_call("GET", "/api/nodes")
            registered_nodes = len(nodes_data.get("nodes", []))
            logger.info(f"✓ Total registered nodes: {registered_nodes}")
            return True
            
        except Exception as e:
            logger.error(f"✗ Failed to register nodes: {e}")
            return False
    
    async def start_traffic_collection(self) -> bool:
        """Start traffic collection"""
        logger.info("Starting traffic collection...")
        
        try:
            result = await self.api_call("POST", "/api/traffic/start-collection")
            logger.info("✓ Traffic collection started")
            return True
        except Exception as e:
            logger.warning(f"Could not start traffic collection: {e}")
            return False
    
    async def train_ml_model(self) -> bool:
        """Train ML model with initial data"""
        logger.info("Training ML model with initial data...")
        
        try:
            training_request = {
                "training_data": TRAINING_DATA,
                "labels": TRAINING_LABELS
            }
            
            result = await self.api_call("POST", "/api/training/start", training_request)
            logger.info("✓ ML model training started")
            
            # Wait a moment for training to complete
            await asyncio.sleep(10)
            
            # Check model status
            try:
                debug_status = await self.api_call("GET", "/api/debug/status")
                if debug_status.get("ml_engine", {}).get("model_trained"):
                    logger.info("✓ ML model training completed")
                else:
                    logger.warning("⚠ ML model training may still be in progress")
            except Exception:
                logger.warning("⚠ Could not verify ML model status")
            
            return True
            
        except Exception as e:
            logger.error(f"✗ Failed to train ML model: {e}")
            return False
    
    async def start_processing(self) -> bool:
        """Start real-time processing"""
        logger.info("Starting real-time processing...")
        
        try:
            result = await self.api_call("POST", "/api/processing/start")
            logger.info("✓ Real-time processing started")
            return True
        except Exception as e:
            logger.warning(f"Could not start real-time processing: {e}")
            return False
    
    async def verify_system_status(self) -> bool:
        """Verify system is working correctly"""
        logger.info("Verifying system status...")
        
        try:
            # Check health
            health = await self.api_call("GET", "/health")
            logger.info(f"✓ System health: {health.get('status', 'unknown')}")
            
            # Check stats
            stats = await self.api_call("GET", "/api/stats")
            logger.info(f"✓ System stats retrieved")
            
            # Check components
            debug_status = await self.api_call("GET", "/api/debug/status")
            components = debug_status.get("components", {})
            
            for component, status in components.items():
                status_icon = "✓" if status else "✗"
                logger.info(f"{status_icon} {component}: {status}")
            
            return True
            
        except Exception as e:
            logger.error(f"✗ Failed to verify system status: {e}")
            return False
    
    async def wait_for_traffic_data(self, timeout: int = 120) -> bool:
        """Wait for traffic data to start flowing"""
        logger.info("Waiting for traffic data...")
        
        start_time = time.time()
        while time.time() - start_time < timeout:
            try:
                traffic_stats = await self.api_call("GET", "/api/traffic/stats")
                total_requests = traffic_stats.get("total_requests", 0)
                
                if total_requests > 0:
                    logger.info(f"✓ Traffic data flowing: {total_requests} requests")
                    return True
                    
            except Exception:
                pass
            
            await asyncio.sleep(10)
        
        logger.warning("⚠ No traffic data detected yet")
        return False

async def main():
    """Main bootstrap function"""
    logger.info("🚀 Starting WAF AI System Bootstrap")
    logger.info("=" * 50)
    
    async with WAFBootstrap() as bootstrap:
        # Wait for core services
        services_ready = await asyncio.gather(
            bootstrap.wait_for_service(f"{WAF_API_BASE}/health"),
            bootstrap.wait_for_service(f"{PROMETHEUS_BASE}/-/ready"),
            bootstrap.wait_for_service(f"{GRAFANA_BASE}/api/health"),
            return_exceptions=True
        )
        
        if not all(services_ready):
            logger.error("✗ Some services failed to start")
            return False
        
        # Authenticate
        if not await bootstrap.authenticate():
            logger.error("✗ Authentication failed")
            return False
        
        # Bootstrap steps
        logger.info("\n📋 Executing bootstrap steps...")
        logger.info("-" * 30)
        
        steps = [
            ("Registering nodes", bootstrap.register_nodes),
            ("Starting traffic collection", bootstrap.start_traffic_collection),
            ("Training ML model", bootstrap.train_ml_model),
            ("Starting real-time processing", bootstrap.start_processing),
            ("Verifying system status", bootstrap.verify_system_status)
        ]
        
        success_count = 0
        for step_name, step_func in steps:
            logger.info(f"\n🔄 {step_name}...")
            if await step_func():
                success_count += 1
            else:
                logger.warning(f"⚠ {step_name} had issues but continuing...")
        
        logger.info(f"\n📊 Bootstrap Summary")
        logger.info("-" * 20)
        logger.info(f"✓ Completed steps: {success_count}/{len(steps)}")
        
        # Wait for traffic data
        await bootstrap.wait_for_traffic_data()
        
        # Final status check
        await bootstrap.verify_system_status()
        
        logger.info("\n🎉 WAF AI System Bootstrap Complete!")
        logger.info("=" * 50)
        logger.info("📊 Access points:")
        logger.info(f"   • WAF Dashboard: http://localhost")
        logger.info(f"   • WAF API: {WAF_API_BASE}")
        logger.info(f"   • Grafana: {GRAFANA_BASE} (admin/waf-admin)")
        logger.info(f"   • Prometheus: {PROMETHEUS_BASE}")
        logger.info(f"   • Nginx Node 1: http://localhost:8081")
        logger.info(f"   • Nginx Node 2: http://localhost:8082")
        
        return True

if __name__ == "__main__":
    try:
        result = asyncio.run(main())
        sys.exit(0 if result else 1)
    except KeyboardInterrupt:
        logger.info("\n⏹ Bootstrap interrupted by user")
        sys.exit(1)
    except Exception as e:
        logger.error(f"💥 Bootstrap failed: {e}")
        sys.exit(1)
