# WAF AI System - Quick Start Guide

This guide will help you get the complete WAF AI system running with monitoring, metrics, and traffic protection.

## Quick Start

### Option 1: Automated Setup (recommended)

Run the automated startup script:

```bash
chmod +x scripts/start-waf-system.sh
./scripts/start-waf-system.sh
```

This script will:
- Start all Docker services
- Wait for services to be ready
- Install Python dependencies
- Run the automated bootstrap process

### Option 2: Manual Setup

1. **Start Docker services**
   ```bash
   docker-compose up -d
   ```

2. **Wait for services** (about 2-3 minutes)
   ```bash
   docker-compose ps
   docker-compose logs -f waf-api
   ```

3. **Install Python dependencies**
   ```bash
   pip3 install aiohttp requests
   ```

4. **Run bootstrap script**
   ```bash
   python3 scripts/bootstrap.py
   ```

## Access Points

Once the system is running:

| Service | URL | Credentials |
|---------|-----|-------------|
| WAF Dashboard | http://localhost | admin/admin123 |
| WAF API | http://localhost:8000 | - |
| Grafana | http://localhost:3080 | admin/waf-admin |
| Prometheus | http://localhost:9090 | - |
| Nginx Node 1 | http://localhost:8081 | - |
| Nginx Node 2 | http://localhost:8082 | - |

## What Gets Automatically Configured

### Nginx Node Registration
- Two nginx nodes are automatically registered
- Log servers are connected for traffic monitoring
- WAF rule deployment is configured

### Traffic Collection
- Traffic collection starts automatically
- Logs are parsed and processed in real-time
- Metrics are forwarded to Prometheus

### ML Model Training
- Initial model is trained with sample attack patterns
- Includes SQL injection, XSS, and normal traffic samples

### Real-time Processing
- Threat detection engine starts automatically
- Real-time analysis of incoming traffic

### Monitoring Setup
- Grafana dashboards are pre-configured
- Prometheus metrics collection is active
- Log aggregation through Loki and Promtail

## System Management

### View Logs
```bash
# All services
docker-compose logs -f

# Specific service
docker-compose logs -f waf-api
docker-compose logs -f grafana
```

### Restart Services
```bash
docker-compose restart
docker-compose restart waf-api
```

### Stop System
```bash
docker-compose down
```

### Clean Reset
```bash
# Stop and remove all data
docker-compose down -v
```

## Monitoring and Metrics

### Grafana Dashboards

1. Open Grafana: http://localhost:3080
2. Login: admin/waf-admin
3. Navigate to Dashboards
4. View "WAF System Overview" dashboard

The dashboard shows:
- Threat detection metrics
- Traffic volume and patterns
- Node health and status

### Prometheus Metrics

Raw metrics at: http://localhost:9090

Key metrics:
- `waf_threats_detected_total`
- `waf_requests_processed_total`
- `waf_rules_active`
- `waf_nodes_registered`

## Threat Detection

### Supported threat types
- SQL injection
- Cross-Site Scripting (XSS)
- Directory traversal
- Brute force patterns

### Traffic Analysis
- Request parsing (URL, method, headers, body)
- Pattern matching
- Anomaly detection via Isolation Forest

## Traffic Generation

The system includes a traffic generator that simulates:
- Normal user traffic (90%)
- Attack patterns (10%)

This ensures data flows immediately for testing.

## Troubleshooting

### Services not starting
```bash
docker ps
docker-compose logs waf-api
```

### No data in Grafana
- Wait 2-3 minutes for metrics to populate
- Check if traffic generator is running
- Verify Prometheus targets are up

### Authentication issues
- Default credentials: admin/admin123
- Try clearing browser cache

### Port conflicts
```bash
lsof -i :8000  # WAF API
lsof -i :3080  # Grafana
lsof -i :9090  # Prometheus
```

### Bootstrap issues

If automated bootstrap fails:

```bash
# Run manual bootstrap
python3 scripts/bootstrap.py

# Test API connectivity
curl http://localhost:8000/health

# Check authentication
curl -X POST http://localhost:8000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin123"}'
```

## Next Steps

1. Explore the Dashboard: navigate through different tabs
2. Review Threats: check the threat detection page
3. Monitor Traffic: watch real-time traffic analysis
4. Customize Rules: add your own WAF rules
5. Tune ML Model: train with your specific data

## Support

For issues or questions:
1. Check the logs: `docker-compose logs -f`
2. Review this documentation
3. Check the API documentation: http://localhost:8000/docs
4. Verify system status: http://localhost:8000/api/debug/status

## System Architecture

```
+------------------+    +------------------+    +------------------+
|   Web Browser    |    |  Nginx Node 1    |    |  Nginx Node 2    |
|  (Dashboard)     |    |   Port 8081      |    |   Port 8082      |
+------------------+    +------------------+    +------------------+
         |                       |                       |
+------------------+    +------------------+    +------------------+
|   WAF API        |    |  Log Server 1    |    |  Log Server 2    |
|   Port 8000      |    |   Port 8080      |    |   Port 8083      |
+------------------+    +------------------+    +------------------+
         |                       |                       |
         |                       +----------+------------+
         |                                  |
+------------------+    +------------------+    +------------------+
|    Grafana       |    |   Prometheus     |    |      Loki        |
|   Port 3080      |    |   Port 9090      |    |   Port 3100      |
+------------------+    +------------------+    +------------------+
```
