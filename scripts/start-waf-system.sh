#!/bin/bash

# WAF AI System Startup Script
# This script trains the ML model and starts all WAF components

set -e

# Configuration
WAF_API_URL="http://localhost:8000"
PROMETHEUS_URL="http://localhost:9090"
GRAFANA_URL="http://localhost:3000"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging function
log() {
    echo -e "${BLUE}[$(date '+%Y-%m-%d %H:%M:%S')]${NC} $1"
}

success() {
    echo -e "${GREEN}[$(date '+%Y-%m-%d %H:%M:%S')] ✅ $1${NC}"
}

warning() {
    echo -e "${YELLOW}[$(date '+%Y-%m-%d %H:%M:%S')] ⚠️  $1${NC}"
}

error() {
    echo -e "${RED}[$(date '+%Y-%m-%d %H:%M:%S')] ❌ $1${NC}"
}

# Wait for service to be ready
wait_for_service() {
    local url=$1
    local service_name=$2
    local max_attempts=30
    local attempt=1
    
    log "Waiting for $service_name to be ready..."
    
    while [ $attempt -le $max_attempts ]; do
        if curl -s "$url" > /dev/null 2>&1; then
            success "$service_name is ready!"
            return 0
        fi
        
        echo -n "."
        sleep 2
        attempt=$((attempt + 1))
    done
    
    error "$service_name failed to start after $((max_attempts * 2)) seconds"
    return 1
}

# Check if WAF API is responding
check_waf_status() {
    log "Checking WAF API status..."
    
    if response=$(curl -s "$WAF_API_URL/api/status" 2>/dev/null); then
        echo "$response" | jq '.' 2>/dev/null || echo "$response"
        return 0
    else
        error "WAF API is not responding"
        return 1
    fi
}

# Train ML model with sample data
train_ml_model() {
    log "Training ML model with sample data..."
    
    # Create comprehensive training data with various attack patterns
    training_data='{
  "training_data": [
    {
      "timestamp": "2025-07-20T21:45:00",
      "method": "GET",
      "url": "/",
      "headers_count": 5,
      "body_length": 0,
      "source_ip": "192.168.1.1",
      "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
      "content_length": 0,
      "has_suspicious_headers": false,
      "url_length": 1,
      "contains_sql_patterns": false,
      "contains_xss_patterns": false
    },
    {
      "timestamp": "2025-07-20T21:45:01",
      "method": "GET",
      "url": "/api/products",
      "headers_count": 4,
      "body_length": 0,
      "source_ip": "192.168.1.2",
      "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
      "content_length": 0,
      "has_suspicious_headers": false,
      "url_length": 13,
      "contains_sql_patterns": false,
      "contains_xss_patterns": false
    },
    {
      "timestamp": "2025-07-20T21:45:02",
      "method": "GET", 
      "url": "/api/users?id=1'\'' OR '\''1'\''='\''1",
      "headers_count": 4,
      "body_length": 0,
      "source_ip": "10.0.0.100",
      "user_agent": "sqlmap/1.6.12",
      "content_length": 0,
      "has_suspicious_headers": false,
      "url_length": 30,
      "contains_sql_patterns": true,
      "contains_xss_patterns": false
    },
    {
      "timestamp": "2025-07-20T21:45:03",
      "method": "GET",
      "url": "/search?q=<script>alert(\"xss\")</script>",
      "headers_count": 3,
      "body_length": 0,
      "source_ip": "172.16.0.50",
      "user_agent": "BadBot/1.0",
      "content_length": 0,
      "has_suspicious_headers": false,
      "url_length": 35,
      "contains_sql_patterns": false,
      "contains_xss_patterns": true
    },
    {
      "timestamp": "2025-07-20T21:45:04",
      "method": "GET",
      "url": "/admin/config.php",
      "headers_count": 2,
      "body_length": 0,
      "source_ip": "203.0.113.42",
      "user_agent": "Nmap NSE",
      "content_length": 0,
      "has_suspicious_headers": false,
      "url_length": 17,
      "contains_sql_patterns": false,
      "contains_xss_patterns": false
    },
    {
      "timestamp": "2025-07-20T21:45:05",
      "method": "GET",
      "url": "/../../../etc/passwd",
      "headers_count": 3,
      "body_length": 0,
      "source_ip": "198.51.100.25",
      "user_agent": "DirBuster",
      "content_length": 0,
      "has_suspicious_headers": false,
      "url_length": 18,
      "contains_sql_patterns": false,
      "contains_xss_patterns": false
    },
    {
      "timestamp": "2025-07-20T21:45:06",
      "method": "POST",
      "url": "/api/login",
      "headers_count": 6,
      "body_length": 150,
      "source_ip": "192.168.1.10",
      "user_agent": "curl/7.68.0",
      "content_length": 150,
      "has_suspicious_headers": false,
      "url_length": 10,
      "contains_sql_patterns": false,
      "contains_xss_patterns": false
    },
    {
      "timestamp": "2025-07-20T21:45:07",
      "method": "GET",
      "url": "/api/search?q=test'\'' UNION SELECT * FROM users--",
      "headers_count": 4,
      "body_length": 0,
      "source_ip": "10.0.0.200",
      "user_agent": "python-requests/2.28.1",
      "content_length": 0,
      "has_suspicious_headers": false,
      "url_length": 45,
      "contains_sql_patterns": true,
      "contains_xss_patterns": false
    }
  ],
  "labels": ["normal", "normal", "sql_injection", "xss", "unauthorized_access", "file_access", "normal", "sql_injection"]
}'
    
    if response=$(curl -s -X POST -H "Content-Type: application/json" \
        -d "$training_data" \
        "$WAF_API_URL/api/training/start" 2>/dev/null); then
        
        if echo "$response" | grep -q "Training completed successfully"; then
            success "ML model training completed successfully"
            echo "$response" | jq '.' 2>/dev/null || echo "$response"
        else
            error "ML model training failed: $response"
            return 1
        fi
    else
        error "Failed to communicate with WAF API for training"
        return 1
    fi
}

# Start real-time processing
start_processing() {
    log "Starting real-time processing..."
    
    if response=$(curl -s -X POST "$WAF_API_URL/api/processing/start" 2>/dev/null); then
        if echo "$response" | grep -q "Real-time processing started"; then
            success "Real-time processing started successfully"
            echo "$response" | jq '.' 2>/dev/null || echo "$response"
        else
            error "Failed to start real-time processing: $response"
            return 1
        fi
    else
        error "Failed to communicate with WAF API for processing start"
        return 1
    fi
}

# Register nginx nodes (if available)
register_nodes() {
    log "Registering nginx nodes..."
    
    # Try to register known nodes
    nodes=("nginx-node-1:8081" "nginx-node-2:8082")
    
    for node in "${nodes[@]}"; do
        node_data="{\"node_url\": \"http://$node\", \"ssh_config\": {\"host\": \"$node\", \"port\": 22, \"username\": \"nginx\"}}"
        
        if response=$(curl -s -X POST -H "Content-Type: application/json" \
            -d "$node_data" \
            "$WAF_API_URL/api/nodes/register" 2>/dev/null); then
            
            if echo "$response" | grep -q "registered successfully"; then
                success "Node $node registered successfully"
            else
                warning "Node $node registration response: $response"
            fi
        else
            warning "Failed to register node $node (this is optional)"
        fi
    done
}

# Show system status
show_status() {
    log "System Status:"
    echo "=================="
    
    # WAF API Status
    if check_waf_status; then
        success "WAF API is operational"
    else
        error "WAF API has issues"
    fi
    
    # Check Prometheus
    if curl -s "$PROMETHEUS_URL/-/healthy" > /dev/null 2>&1; then
        success "Prometheus is healthy"
    else
        warning "Prometheus may not be ready"
    fi
    
    # Check Grafana
    if curl -s "$GRAFANA_URL/api/health" > /dev/null 2>&1; then
        success "Grafana is accessible"
    else
        warning "Grafana may not be ready"
    fi
    
    echo "=================="
    echo -e "${BLUE}Access URLs:${NC}"
    echo "  WAF API:    $WAF_API_URL/docs"
    echo "  Prometheus: $PROMETHEUS_URL"
    echo "  Grafana:    $GRAFANA_URL (admin/admin)"
    echo "=================="
}

# Main execution
main() {
    echo -e "${GREEN}"
    echo "=========================================="
    echo "       WAF AI System Startup Script      "
    echo "=========================================="
    echo -e "${NC}"
    
    # Wait for WAF API to be ready
    wait_for_service "$WAF_API_URL/api/status" "WAF API"
    
    # Train ML model
    train_ml_model
    
    # Start processing
    start_processing
    
    # Register nodes (optional)
    register_nodes
    
    # Show final status
    show_status
    
    success "WAF AI system is now fully operational!"
    echo ""
    echo -e "${YELLOW}Next steps:${NC}"
    echo "1. Open Grafana at $GRAFANA_URL"
    echo "2. Navigate to the 'Unified WAF Monitoring' dashboard"
    echo "3. Monitor real-time traffic and threat detection"
    echo "4. Check generated WAF rules at $WAF_API_URL/api/rules"
    echo ""
}

# Run main function
main "$@"
