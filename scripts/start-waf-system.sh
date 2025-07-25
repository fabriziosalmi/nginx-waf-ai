#!/bin/bash

# WAF AI System Startup Script
# This script starts the entire WAF AI system and runs the bootstrap process

set -e

echo "🚀 Starting WAF AI System"
echo "=========================="

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${GREEN}✓${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}⚠${NC} $1"
}

print_error() {
    echo -e "${RED}✗${NC} $1"
}

print_info() {
    echo -e "${BLUE}ℹ${NC} $1"
}

# Check if Docker and Docker Compose are available
command -v docker >/dev/null 2>&1 || { print_error "Docker is required but not installed. Aborting."; exit 1; }
command -v docker-compose >/dev/null 2>&1 || { print_error "Docker Compose is required but not installed. Aborting."; exit 1; }

# Check if already running
if docker-compose ps | grep -q "Up"; then
    print_warning "Some services are already running. Stopping them first..."
    docker-compose down
fi

print_info "Starting Docker Compose services..."
echo "This may take a few minutes for first-time setup..."

# Start services in background
docker-compose up -d

print_status "Docker services started"

# Wait for services to be ready
print_info "Waiting for services to initialize..."
sleep 30

# Check service health
print_info "Checking service health..."

# Function to check if service is responding
check_service() {
    local service_name=$1
    local url=$2
    local max_attempts=30
    local attempt=1
    
    print_info "Checking $service_name..."
    
    while [ $attempt -le $max_attempts ]; do
        if curl -s -f "$url" > /dev/null 2>&1; then
            print_status "$service_name is ready"
            return 0
        fi
        
        printf "."
        sleep 2
        attempt=$((attempt + 1))
    done
    
    print_warning "$service_name is not responding after $max_attempts attempts"
    return 1
}

# Check core services
check_service "WAF API" "http://localhost:8000/health"
check_service "Grafana" "http://localhost:3000/api/health"
check_service "Prometheus" "http://localhost:9090/-/ready"
check_service "Nginx Node 1" "http://localhost:8081"
check_service "Nginx Node 2" "http://localhost:8082"

print_info "Installing Python dependencies for bootstrap..."
pip3 install aiohttp requests > /dev/null 2>&1 || {
    print_warning "Could not install Python dependencies. Trying with user install..."
    pip3 install --user aiohttp requests > /dev/null 2>&1
}

# Run bootstrap script
print_info "Running system bootstrap..."
echo "This will:"
echo "  • Register nginx nodes"
echo "  • Start traffic collection" 
echo "  • Train ML model with sample data"
echo "  • Start real-time processing"
echo "  • Verify system connectivity"
echo ""

if python3 scripts/bootstrap.py; then
    print_status "Bootstrap completed successfully!"
else
    print_warning "Bootstrap completed with some warnings. System should still be functional."
fi

echo ""
print_status "WAF AI System is ready!"
echo "========================"
echo ""
echo "📊 Access Points:"
echo "  • WAF Dashboard:  http://localhost"
echo "  • WAF API:        http://localhost:8000"
echo "  • Grafana:        http://localhost:3000 (admin/waf-admin)"
echo "  • Prometheus:     http://localhost:9090"
echo "  • Nginx Node 1:   http://localhost:8081"
echo "  • Nginx Node 2:   http://localhost:8082"
echo ""
echo "🔧 Management:"
echo "  • View logs:      docker-compose logs -f"
echo "  • Stop system:    docker-compose down"
echo "  • Restart:        docker-compose restart"
echo ""
echo "📈 The traffic generator is now sending requests to the nginx nodes."
echo "📊 Grafana dashboards should populate with data in 1-2 minutes."
echo ""

# Optional: Open browser tabs
if command -v xdg-open >/dev/null 2>&1; then
    print_info "Opening dashboard in browser..."
    xdg-open "http://localhost" > /dev/null 2>&1 &
    xdg-open "http://localhost:3000" > /dev/null 2>&1 &
elif command -v open >/dev/null 2>&1; then
    print_info "Opening dashboard in browser..."
    open "http://localhost" > /dev/null 2>&1 &
    open "http://localhost:3000" > /dev/null 2>&1 &
fi

print_status "Setup complete! 🎉"
