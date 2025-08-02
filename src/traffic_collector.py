"""
Traffic Collector Module

Handles collection and preprocessing of HTTP traffic from multiple sources.
"""

import asyncio
import json
from typing import Dict, List, Optional
from dataclasses import dataclass
from datetime import datetime
import httpx
from loguru import logger

# Import prometheus metrics for real-time updates
try:
    from prometheus_client import Gauge
    METRICS_AVAILABLE = True
    
    # Metrics (imported from main.py to avoid conflicts)
    traffic_volume = Gauge('waf_traffic_volume_total', 'Total traffic volume processed')
    recent_requests_gauge = Gauge('waf_recent_requests', 'Recent requests processed')
    
except ImportError:
    METRICS_AVAILABLE = False
    logger.warning("Prometheus metrics not available")


@dataclass
class HttpRequest:
    """Represents an HTTP request with relevant metadata"""
    timestamp: datetime
    method: str
    url: str
    headers: Dict[str, str]
    body: Optional[str]
    source_ip: str
    user_agent: str
    content_length: int
    node_id: str = 'nginx-node-1'  # Add node_id field with default
    
    def to_dict(self) -> Dict:
        """Convert to dictionary for ML processing"""
        return {
            'timestamp': self.timestamp.isoformat(),
            'method': self.method,
            'url': self.url,
            'headers_count': len(self.headers),
            'body_length': len(self.body) if self.body else 0,
            'source_ip': self.source_ip,
            'user_agent': self.user_agent,
            'content_length': self.content_length,
            'node_id': self.node_id,
            'has_suspicious_headers': self._check_suspicious_headers(),
            'url_length': len(self.url),
            'contains_sql_patterns': self._check_sql_patterns(),
            'contains_xss_patterns': self._check_xss_patterns()
        }
    
    def _check_suspicious_headers(self) -> bool:
        """Check for suspicious header patterns"""
        suspicious_patterns = ['script', 'javascript:', 'vbscript:', 'onload', 'onerror']
        headers_str = ' '.join(self.headers.values()).lower()
        return any(pattern in headers_str for pattern in suspicious_patterns)
    
    def _check_sql_patterns(self) -> bool:
        """Check for SQL injection patterns"""
        sql_patterns = ['union select', 'or 1=1', "or '1'='1", 'drop table', 'select * from']
        url_lower = self.url.lower()
        body_lower = (self.body or '').lower()
        combined = f"{url_lower} {body_lower}"
        return any(pattern in combined for pattern in sql_patterns)
    
    def _check_xss_patterns(self) -> bool:
        """Check for XSS patterns"""
        xss_patterns = ['<script', 'javascript:', 'onerror=', 'onload=']
        url_lower = self.url.lower()
        body_lower = (self.body or '').lower()
        combined = f"{url_lower} {body_lower}"
        return any(pattern in combined for pattern in xss_patterns)


class TrafficCollector:
    """Collects HTTP traffic from multiple nginx nodes"""
    
    def __init__(self, nodes: List[str]):
        self.nodes = nodes
        self.collected_requests: List[HttpRequest] = []
        self.is_collecting = False
        
    async def start_collection(self):
        """Start collecting traffic from all nodes"""
        self.is_collecting = True
        logger.info(f"Starting traffic collection from {len(self.nodes)} nodes")
        
        tasks = [self._collect_from_node(node) for node in self.nodes]
        await asyncio.gather(*tasks)
    
    async def _collect_from_node(self, node_url: str):
        """Collect traffic from a specific nginx node"""
        async with httpx.AsyncClient() as client:
            while self.is_collecting:
                try:
                    # Try different endpoint paths
                    endpoints = [
                        f"{node_url}/api/logs",
                        f"{node_url}/api/traffic-logs", 
                        f"{node_url}"
                    ]
                    
                    logs_collected = False
                    for endpoint in endpoints:
                        try:
                            response = await client.get(endpoint, timeout=5.0)
                            if response.status_code == 200:
                                data = response.json()
                                
                                # Handle different response formats
                                logs = []
                                if isinstance(data, dict):
                                    logs = data.get('logs', data.get('data', []))
                                elif isinstance(data, list):
                                    logs = data
                                
                                for log_entry in logs:
                                    request = self._parse_log_entry(log_entry, node_url)
                                    if request:
                                        self.collected_requests.append(request)
                                        # Update metrics in real-time
                                        self._update_metrics(request)
                                        logger.debug(f"Collected request from {node_url}: {request.method} {request.url}")
                                    else:
                                        logger.warning(f"Failed to parse log entry: {log_entry}")
                                
                                logger.info(f"Collected {len(logs)} log entries from {node_url}, total stored: {len(self.collected_requests)}")
                                
                                if logs:
                                    logs_collected = True
                                    break
                                    
                        except Exception as e:
                            logger.debug(f"Endpoint {endpoint} failed: {e}")
                            continue
                    
                    if not logs_collected:
                        logger.warning(f"No logs collected from {node_url}")
                        
                except Exception as e:
                    logger.error(f"Error collecting from {node_url}: {e}")
                
                await asyncio.sleep(5)  # Collect every 5 seconds
    
    def _parse_log_entry(self, log_entry: Dict, node_url: str) -> Optional[HttpRequest]:
        """Parse a log entry into an HttpRequest object"""
        try:
            # Handle timestamp with timezone
            timestamp_str = log_entry.get('timestamp', datetime.now().isoformat())
            if '+' in timestamp_str and timestamp_str.endswith('+00:00'):
                # Convert +00:00 to Z for proper ISO format
                timestamp_str = timestamp_str.replace('+00:00', 'Z')
            elif 'T' not in timestamp_str:
                # If no time component, add it
                timestamp_str = datetime.now().isoformat()
            
            try:
                timestamp = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
            except ValueError:
                # Fallback to current time if parsing fails
                timestamp = datetime.now()
            
            # Determine node_id from the source URL
            node_id = 'nginx-node-1'  # default
            if 'log-server-2' in node_url:
                node_id = 'nginx-node-2'
            
            logger.debug(f"Assigning node_id {node_id} for request from {node_url}")
            
            return HttpRequest(
                timestamp=timestamp,
                method=log_entry.get('method', 'GET'),
                url=log_entry.get('url', ''),
                headers=log_entry.get('headers', {}),
                body=log_entry.get('body'),
                source_ip=log_entry.get('source_ip', ''),
                user_agent=log_entry.get('user_agent', ''),
                content_length=log_entry.get('content_length', 0),
                node_id=node_id  # Add node_id field
            )
        except Exception as e:
            logger.error(f"Error parsing log entry: {e}")
            return None
    
    def _update_metrics(self, request: HttpRequest):
        """Update Prometheus metrics with real-time data"""
        if METRICS_AVAILABLE:
            try:
                # Update request counter (assume status 200 for now since log entry might not have status)
                status = '200'  # Default status for collected requests
                requests_total.labels(node_id=request.node_id, status=status).inc()
                
                # Update volume gauge
                traffic_volume.set(len(self.collected_requests))
                
                # Update recent requests gauge
                recent_requests.set(len(self.get_recent_requests(100)))
                
            except Exception as e:
                logger.warning(f"Failed to update metrics: {e}")
    
    def get_recent_requests(self, limit: int = 1000) -> List[HttpRequest]:
        """Get the most recent requests for ML processing"""
        return self.collected_requests[-limit:] if len(self.collected_requests) > limit else self.collected_requests
    
    def clear_old_requests(self, max_age_minutes: int = 60):
        """Clear requests older than specified minutes"""
        cutoff_time = datetime.now().timestamp() - (max_age_minutes * 60)
        self.collected_requests = [
            req for req in self.collected_requests 
            if req.timestamp.timestamp() > cutoff_time
        ]
