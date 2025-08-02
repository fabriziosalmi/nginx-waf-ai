"""
Metrics Module

Centralized Prometheus metrics definitions to avoid duplicates.
"""

from prometheus_client import Counter, Histogram, Gauge

# Request metrics
requests_total = Counter('waf_requests_total', 'Total number of requests processed', ['node_id', 'status'])
threats_detected = Counter('waf_threats_detected_total', 'Total number of threats detected', ['threat_type'])
auth_attempts = Counter('waf_auth_attempts_total', 'Authentication attempts', ['status'])

# System metrics
nodes_registered = Gauge('waf_nodes_registered', 'Number of registered nginx nodes')
rules_active = Gauge('waf_rules_active', 'Number of active WAF rules')
traffic_volume = Gauge('waf_traffic_volume_total', 'Total traffic volume processed')
recent_requests = Gauge('waf_recent_requests', 'Recent requests processed')

# Performance metrics  
request_duration = Histogram('waf_request_duration_seconds', 'Request processing duration')
rule_generation_duration = Histogram('waf_rule_generation_duration_seconds', 'WAF rule generation duration')

# Initialize metrics with zero values
nodes_registered.set(0)
rules_active.set(0)
traffic_volume.set(0)
recent_requests.set(0)
