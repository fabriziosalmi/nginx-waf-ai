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
processing_time = Histogram('waf_processing_time_seconds', 'WAF processing time', ['component'])

# Security metrics
blocked_requests = Counter('waf_blocked_requests_total', 'Total blocked requests', ['node_id', 'reason'])
sql_injection_attempts = Counter('waf_sql_injection_attempts_total', 'SQL injection attempts detected', ['node_id'])
xss_attempts = Counter('waf_xss_attempts_total', 'XSS attempts detected', ['node_id'])
path_traversal_attempts = Counter('waf_path_traversal_attempts_total', 'Path traversal attempts detected', ['node_id'])
scanner_attempts = Counter('waf_scanner_attempts_total', 'Scanner attempts detected', ['node_id'])

# Additional system metrics
ml_model_accuracy = Gauge('waf_ml_model_accuracy', 'ML model accuracy score')
rules_deployed = Counter('waf_rules_deployed_total', 'Total rules deployed', ['node_id'])
configuration_reloads = Counter('waf_configuration_reloads_total', 'Configuration reloads', ['node_id', 'status'])

# Initialize metrics with zero values
nodes_registered.set(0)
rules_active.set(0)
traffic_volume.set(0)
recent_requests.set(0)
ml_model_accuracy.set(0)
