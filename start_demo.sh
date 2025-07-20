#!/bin/bash
# Full Stack Demo Startup Script

echo "🛡️  nginx WAF AI - Full Stack Demo"
echo "=================================="
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

print_step() {
    echo -e "${BLUE}$1${NC}"
}

print_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

print_error() {
    echo -e "${RED}❌ $1${NC}"
}

# Check if Docker and Docker Compose are available
print_step "Checking prerequisites..."

if ! command -v docker &> /dev/null; then
    print_error "Docker is not installed"
    exit 1
fi

if ! command -v docker-compose &> /dev/null && ! docker compose version &> /dev/null; then
    print_error "Docker Compose is not installed"
    exit 1
fi

print_success "Docker and Docker Compose are available"

# Create necessary directories
print_step "Creating necessary directories..."
mkdir -p docker/nginx-node-1/logs
mkdir -p docker/nginx-node-2/logs
mkdir -p docker/shared/waf-rules
mkdir -p logs
mkdir -p models
print_success "Directories created"

# Stop any existing containers
print_step "Stopping existing containers..."
docker-compose down -v 2>/dev/null || true
print_success "Cleaned up existing containers"

# Build and start the stack
print_step "Building and starting the full stack..."
if docker-compose up --build -d; then
    print_success "Stack started successfully"
else
    print_error "Failed to start stack"
    exit 1
fi

# Wait for services to be ready
print_step "Waiting for services to be ready..."
sleep 10

# Check service health
print_step "Checking service health..."

services=(
    "waf-api:8000:WAF AI API"
    "nginx-node-1:8081:Nginx Node 1" 
    "nginx-node-2:8082:Nginx Node 2"
    "log-server-1:8080:Log Server 1"
    "log-server-2:8083:Log Server 2"
    "redis:6379:Redis"
    "prometheus:9090:Prometheus"
    "grafana:3000:Grafana"
)

all_healthy=true

for service in "${services[@]}"; do
    IFS=':' read -r host port name <<< "$service"
    
    if curl -s -f "http://localhost:$port" > /dev/null 2>&1 || 
       curl -s -f "http://localhost:$port/health" > /dev/null 2>&1; then
        print_success "$name is healthy (port $port)"
    else
        print_warning "$name is not responding (port $port)"
        all_healthy=false
    fi
done

echo ""
print_step "Setting up WAF AI system..."

# Register nginx nodes with WAF AI
sleep 5  # Give WAF API more time to start

register_node() {
    local node_id=$1
    local ssh_host=$2
    local api_endpoint=$3
    
    curl -s -X POST http://localhost:8000/api/nodes/add \
        -H "Content-Type: application/json" \
        -d "{
            \"node_id\": \"$node_id\",
            \"hostname\": \"$node_id\",
            \"ssh_host\": \"$ssh_host\",
            \"ssh_port\": 22,
            \"ssh_username\": \"nginx\",
            \"nginx_config_path\": \"/etc/nginx/conf.d\",
            \"nginx_reload_command\": \"nginx -s reload\",
            \"api_endpoint\": \"$api_endpoint\"
        }" > /dev/null 2>&1
}

print_step "Registering nginx nodes..."
register_node "nginx-node-1" "nginx-node-1" "http://log-server-1:8080"
register_node "nginx-node-2" "nginx-node-2" "http://log-server-2:8080"
print_success "Nginx nodes registered"

# Train the ML model
print_step "Training ML model..."
curl -s -X POST http://localhost:8000/api/training/start \
    -H "Content-Type: application/json" \
    -d '{
        "training_data": [
            {
                "timestamp": "2024-01-01T10:00:00Z",
                "method": "GET",
                "url": "/login?id=1'\'' OR '\''1'\''='\''1",
                "headers_count": 5,
                "body_length": 0,
                "source_ip": "192.168.1.100",
                "user_agent": "sqlmap/1.0",
                "content_length": 0
            },
            {
                "timestamp": "2024-01-01T10:01:00Z",
                "method": "GET",
                "url": "/search?q=normal+query",
                "headers_count": 6,
                "body_length": 0,
                "source_ip": "192.168.1.50",
                "user_agent": "Mozilla/5.0",
                "content_length": 0
            }
        ],
        "labels": ["malicious", "benign"]
    }' > /dev/null 2>&1

print_success "ML model trained"

# Start traffic collection
print_step "Starting traffic collection..."
curl -s -X POST http://localhost:8000/api/traffic/start-collection \
    -H "Content-Type: application/json" \
    -d '["http://log-server-1:8080", "http://log-server-2:8080"]' > /dev/null 2>&1

print_success "Traffic collection started"

# Start real-time processing
print_step "Starting real-time processing..."
curl -s -X POST http://localhost:8000/api/processing/start > /dev/null 2>&1
print_success "Real-time processing started"

echo ""
echo "🎉 Full Stack Demo is Ready!"
echo "=========================="
echo ""
echo "🌐 Web Services:"
echo "   • WAF AI API:      http://localhost:8000"
echo "   • API Docs:        http://localhost:8000/docs"
echo "   • Nginx Node 1:    http://localhost:8081"
echo "   • Nginx Node 2:    http://localhost:8082"
echo "   • Grafana:         http://localhost:3000 (admin/waf-admin)"
echo "   • Prometheus:      http://localhost:9090"
echo ""
echo "🔧 Monitoring:"
echo "   • Log Server 1:    http://localhost:8080"
echo "   • Log Server 2:    http://localhost:8083"
echo "   • Redis:           localhost:6379"
echo ""
echo "🧪 Testing Commands:"
echo "   # Check system status"
echo "   curl http://localhost:8000/api/stats"
echo ""
echo "   # Test nginx nodes"
echo "   curl http://localhost:8081/"
echo "   curl http://localhost:8082/"
echo ""
echo "   # Test attack detection (these should be blocked/detected)"
echo "   curl \"http://localhost:8081/api/users?id=1' OR 1=1--\""
echo "   curl \"http://localhost:8082/search?q=<script>alert('xss')</script>\""
echo ""
echo "   # Run full demo"
echo "   python demo.py"
echo ""
echo "   # View logs"
echo "   docker-compose logs -f waf-api"
echo "   docker-compose logs -f traffic-generator"
echo ""
echo "🛑 To stop the demo:"
echo "   docker-compose down -v"
echo ""

if [ "$all_healthy" = true ]; then
    print_success "All services are healthy and ready for testing!"
else
    print_warning "Some services may need more time to start. Check with 'docker-compose ps'"
fi
