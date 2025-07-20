# Docker Compose Stack - Full WAF AI Demo

## Overview
This Docker Compose stack provides a complete, working demonstration of the nginx WAF AI system with:

- **2 Nginx nodes** simulating production web servers
- **WAF AI API** for threat detection and rule generation  
- **Log servers** providing API access to nginx logs
- **Traffic generator** creating realistic traffic with attacks
- **Redis** for caching and data storage
- **Prometheus + Grafana** for monitoring and visualization

## Architecture

```
┌─────────────────┐    ┌─────────────────┐
│   Nginx Node 1  │    │   Nginx Node 2  │
│   Port: 8081    │    │   Port: 8082    │
└─────┬───────────┘    └─────┬───────────┘
      │                      │
      ▼                      ▼
┌─────────────────┐    ┌─────────────────┐
│  Log Server 1   │    │  Log Server 2   │
│   Port: 8080    │    │   Port: 8083    │
└─────┬───────────┘    └─────┬───────────┘
      │                      │
      └──────┬─────────────┬─┘
             ▼             ▼
      ┌─────────────────────┐
      │     WAF AI API      │
      │     Port: 8000      │
      └─────────┬───────────┘
                │
      ┌─────────▼───────────┐
      │       Redis         │
      │     Port: 6379      │
      └─────────────────────┘

┌─────────────────┐    ┌─────────────────┐
│ Traffic Gen.    │    │   Monitoring    │
│ (Background)    │    │ Grafana: 3000   │
│                 │    │ Prometheus: 9090│
└─────────────────┘    └─────────────────┘
```

## Quick Start

### 1. Start the Full Stack
```bash
# Start everything
./start_demo.sh

# Or manually:
docker-compose up --build -d
```

### 2. Verify Services
```bash
# Check all containers are running
docker-compose ps

# Check service health
curl http://localhost:8000/health
curl http://localhost:8081/
curl http://localhost:8082/
```

### 3. View the Web Interfaces
- **WAF AI API**: http://localhost:8000/docs
- **Nginx Node 1**: http://localhost:8081
- **Nginx Node 2**: http://localhost:8082  
- **Grafana Dashboard**: http://localhost:3000 (admin/waf-admin)
- **Prometheus Metrics**: http://localhost:9090

## Services Description

### WAF AI API (Port 8000)
The main application providing:
- Machine learning threat detection
- WAF rule generation
- Nginx node management
- Real-time processing coordination

**Key Endpoints:**
- `GET /health` - Health check
- `GET /docs` - Interactive API documentation
- `POST /api/training/start` - Train ML models
- `GET /api/stats` - System statistics
- `POST /api/nodes/add` - Register nginx nodes

### Nginx Nodes (Ports 8081, 8082)
Two nginx instances simulating production web servers:

**Node 1 Features:**
- General web application
- API endpoints: `/api/users`, `/api/login`, `/api/search`
- Admin panel: `/admin/`
- Rate limiting and security headers

**Node 2 Features:**
- E-commerce application  
- API endpoints: `/api/products`, `/api/orders`, `/api/cart`
- Dashboard: `/dashboard/`
- Different security configuration

### Log Servers (Ports 8080, 8083)
Provide API access to nginx access logs:
- Parse nginx log format
- Expose structured data via REST API
- Generate sample traffic when no logs exist
- Support multiple endpoint formats

### Traffic Generator (Background)
Continuously generates realistic traffic:
- **90% normal requests** - typical user behavior
- **10% attack requests** - SQL injection, XSS, directory traversal
- Configurable request rate (default: 5 req/sec)
- Random target selection between nodes

### Monitoring Stack
- **Prometheus**: Metrics collection and alerting
- **Grafana**: Visualization dashboards  
- **Redis**: Caching and session storage

## Testing the System

### 1. Basic Functionality Test
```bash
# Check system status
curl http://localhost:8000/api/stats

# List registered nodes
curl http://localhost:8000/api/nodes

# Check WAF rules
curl http://localhost:8000/api/rules
```

### 2. Attack Simulation
```bash
# SQL Injection attempts (should be detected)
curl "http://localhost:8081/api/users?id=1' OR 1=1--"
curl "http://localhost:8082/api/products?id=' UNION SELECT * FROM users--"

# XSS attempts (should be detected)  
curl "http://localhost:8081/search?q=<script>alert('xss')</script>"
curl "http://localhost:8082/api/cart?item=<img src=x onerror=alert('xss')>"

# Directory traversal
curl "http://localhost:8081/../../../etc/passwd"
curl "http://localhost:8082/.env"
```

### 3. Normal Traffic Test
```bash
# These should work normally
curl http://localhost:8081/
curl http://localhost:8081/api/users
curl http://localhost:8082/api/products
curl http://localhost:8082/dashboard/
```

### 4. ML and Processing Test
```bash
# Start traffic collection
curl -X POST http://localhost:8000/api/traffic/start-collection \
  -H "Content-Type: application/json" \
  -d '["http://log-server-1:8080", "http://log-server-2:8080"]'

# Start real-time processing
curl -X POST http://localhost:8000/api/processing/start

# Check for detected threats
curl http://localhost:8000/api/threats

# Generate nginx configuration
curl http://localhost:8000/api/config/nginx
```

### 5. Run Full Demo
```bash
# Comprehensive test of all features
python demo.py
```

## Monitoring and Logs

### View Container Logs
```bash
# WAF AI API logs
docker-compose logs -f waf-api

# Traffic generator activity
docker-compose logs -f traffic-generator

# Nginx access logs
docker-compose logs -f nginx-node-1
docker-compose logs -f nginx-node-2

# All services
docker-compose logs -f
```

### Grafana Dashboard
1. Open http://localhost:3000
2. Login: admin / waf-admin
3. View pre-configured dashboards for:
   - WAF AI system metrics
   - Nginx traffic statistics  
   - Attack detection rates
   - System performance

### Prometheus Metrics
Visit http://localhost:9090 to query metrics:
- WAF API response times
- Threat detection counts
- Nginx request rates
- Container resource usage

## Configuration

### Environment Variables
Modify `docker-compose.yml` to adjust:

```yaml
environment:
  - REQUEST_RATE=10           # Traffic generator rate
  - ATTACK_PROBABILITY=0.2    # 20% attack traffic
  - LOG_LEVEL=DEBUG          # API logging level
```

### Custom WAF Rules
Add rules to `docker/shared/waf-rules/`:
```bash
# Custom rules are automatically included
echo 'if ($args ~ "badpattern") { return 403; }' > docker/shared/waf-rules/custom.conf
```

### Nginx Configuration
Modify nginx configs in:
- `docker/nginx-node-1/nginx.conf`
- `docker/nginx-node-2/nginx.conf`

## Troubleshooting

### Services Not Starting
```bash
# Check container status
docker-compose ps

# View startup logs
docker-compose logs waf-api
docker-compose logs nginx-node-1

# Restart specific service
docker-compose restart waf-api
```

### WAF API Not Responding
```bash
# Check API health
curl http://localhost:8000/health

# Check if container is running
docker-compose ps waf-api

# View detailed logs
docker-compose logs waf-api
```

### No Traffic Being Generated
```bash
# Check traffic generator logs
docker-compose logs traffic-generator

# Manually test nginx nodes
curl http://localhost:8081/
curl http://localhost:8082/
```

### Database/Redis Issues
```bash
# Restart Redis
docker-compose restart redis

# Check Redis connectivity
docker-compose exec redis redis-cli ping
```

## Cleanup

### Stop All Services
```bash
# Stop and remove containers
docker-compose down

# Remove volumes and data
docker-compose down -v

# Remove images
docker-compose down --rmi all
```

### Reset Demo
```bash
# Complete reset
docker-compose down -v
rm -rf docker/nginx-node-*/logs/*
./start_demo.sh
```

## Production Deployment

To adapt this for production:

1. **Security**: Add TLS, authentication, proper secrets management
2. **Storage**: Use persistent volumes for logs and models  
3. **Networking**: Configure proper network segmentation
4. **Monitoring**: Set up alerting and log aggregation
5. **Backup**: Implement data backup strategies
6. **SSH**: Configure actual SSH access to nginx nodes

## Next Steps

1. Monitor the traffic generator creating realistic attack patterns
2. Watch the WAF AI system detect and learn from threats
3. Observe rule generation and deployment
4. Use Grafana to visualize attack trends
5. Test with your own custom attack patterns
6. Integrate with real nginx infrastructure

The system demonstrates a complete AI-powered WAF solution with real traffic simulation, making it perfect for testing, development, and proof-of-concept demonstrations.
