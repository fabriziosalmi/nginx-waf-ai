# WAF AI System - Quick Start Guide

This guide will help you get the complete WAF AI system running with full monitoring, metrics, and protection capabilities.

## 🚀 Quick Start

### Option 1: Automated Setup (Recommended)

Run the automated startup script that handles everything:

```bash
chmod +x scripts/start-waf-system.sh
./scripts/start-waf-system.sh
```

This script will:
- Start all Docker services
- Wait for services to be ready
- Install Python dependencies
- Run the automated bootstrap process
- Open the dashboards in your browser

### Option 2: Manual Setup

If you prefer to set up step by step:

1. **Start Docker Services**
   ```bash
   docker-compose up -d
   ```

2. **Wait for Services** (about 2-3 minutes)
   ```bash
   # Check status
   docker-compose ps
   
   # Wait for health checks
   docker-compose logs -f waf-api
   ```

3. **Install Python Dependencies**
   ```bash
   pip3 install aiohttp requests
   ```

4. **Run Bootstrap Script**
   ```bash
   python3 scripts/bootstrap.py
   ```

## 📊 Access Points

Once the system is running, you can access:

| Service | URL | Credentials |
|---------|-----|-------------|
| **WAF Dashboard** | http://localhost | admin/admin123 |
| **WAF API** | http://localhost:8000 | admin/admin123 |
| **Grafana** | http://localhost:3000 | admin/waf-admin |
| **Prometheus** | http://localhost:9090 | - |
| **Nginx Node 1** | http://localhost:8081 | - |
| **Nginx Node 2** | http://localhost:8082 | - |

## 🎯 What Gets Automatically Configured

### 1. Nginx Nodes Registration
- Two nginx nodes are automatically registered
- Log servers are connected for traffic monitoring
- WAF rules deployment is configured

### 2. Traffic Collection
- Traffic collection is started automatically
- Logs are parsed and processed in real-time
- Metrics are forwarded to Prometheus

### 3. ML Model Training
- Initial model is trained with sample attack patterns
- Includes SQL injection, XSS, and normal traffic samples
- Model is ready for real-time threat detection

### 4. Real-time Processing
- Threat detection engine is started
- Real-time analysis of incoming traffic
- Automatic threat scoring and logging

### 5. Monitoring Setup
- Grafana dashboards are pre-configured
- Prometheus metrics collection is active
- Log aggregation through Loki and Promtail

## 🔧 System Management

### View Logs
```bash
# All services
docker-compose logs -f

# Specific service
docker-compose logs -f waf-api
docker-compose logs -f grafana
docker-compose logs -f traffic-generator
```

### Restart Services
```bash
# Restart all
docker-compose restart

# Restart specific service
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

# Remove images (optional)
docker-compose down -v --rmi all
```

## 📈 Monitoring and Metrics

### Grafana Dashboards

1. **Open Grafana**: http://localhost:3000
2. **Login**: admin/waf-admin
3. **Navigate to Dashboards**
4. **View**: "WAF System Overview" dashboard

The dashboard shows:
- Real-time threat detection metrics
- Traffic volume and patterns
- ML model performance
- Node health and status
- Security events timeline

### Prometheus Metrics

Raw metrics are available at: http://localhost:9090

Key metrics include:
- `waf_threats_detected_total`
- `waf_requests_processed_total`
- `waf_rules_active`
- `waf_nodes_registered`
- `waf_model_accuracy`

## 🛡️ Security Features

### Threat Detection
- **SQL Injection** detection and blocking
- **Cross-Site Scripting (XSS)** prevention
- **Directory Traversal** protection
- **Brute Force** attack mitigation

### Machine Learning
- **Adaptive Learning**: Model improves with new data
- **Real-time Scoring**: Instant threat assessment
- **Confidence Levels**: Adjustable threat thresholds
- **False Positive Reduction**: Smart pattern recognition

### Traffic Analysis
- **Request Parsing**: Full HTTP request analysis
- **Pattern Matching**: Signature-based detection
- **Behavioral Analysis**: Anomaly detection
- **Rate Limiting**: Automatic throttling

## 🔄 Traffic Generation

The system includes a traffic generator that simulates:
- **Normal user traffic** (90%)
- **Attack patterns** (10%)
- **Realistic request patterns**
- **Various attack types**

This ensures you see data flowing immediately and can test the system.

## 🐛 Troubleshooting

### Common Issues

1. **Services not starting**
   ```bash
   # Check Docker status
   docker ps
   
   # Check logs for errors
   docker-compose logs waf-api
   ```

2. **No data in Grafana**
   - Wait 2-3 minutes for metrics to populate
   - Check if traffic generator is running
   - Verify Prometheus targets are up

3. **Authentication issues**
   - Default credentials: admin/admin123
   - Check browser localStorage for tokens
   - Try clearing browser cache

4. **Port conflicts**
   ```bash
   # Check what's using ports
   lsof -i :8000  # WAF API
   lsof -i :3000  # Grafana
   lsof -i :9090  # Prometheus
   ```

### Bootstrap Issues

If the automated bootstrap fails:

1. **Run manual bootstrap**
   ```bash
   python3 scripts/bootstrap.py
   ```

2. **Use the UI bootstrap**
   - Open http://localhost
   - Login with admin/admin123
   - Click "Initialize System" button

3. **Check individual steps**
   ```bash
   # Test API connectivity
   curl http://localhost:8000/health
   
   # Check authentication
   curl -X POST http://localhost:8000/auth/login \
     -H "Content-Type: application/json" \
     -d '{"username":"admin","password":"admin123"}'
   ```

## 📚 Next Steps

1. **Explore the Dashboard**: Navigate through different tabs
2. **Review Threats**: Check the threats detection page
3. **Monitor Traffic**: Watch real-time traffic analysis
4. **Customize Rules**: Add your own WAF rules
5. **Tune ML Model**: Train with your specific data
6. **Set up Alerts**: Configure Grafana alerting

## 🆘 Support

For issues or questions:
1. Check the logs: `docker-compose logs -f`
2. Review this documentation
3. Check the API documentation: http://localhost:8000/docs
4. Verify system status: http://localhost:8000/api/debug/status

## 🎯 System Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Web Browser   │    │  Nginx Node 1   │    │  Nginx Node 2   │
│  (Dashboard)    │    │   Port 8081     │    │   Port 8082     │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         │                       │                       │
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   WAF API       │    │  Log Server 1   │    │  Log Server 2   │
│   Port 8000     │    │   Port 8080     │    │   Port 8083     │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         │                       └───────┬───────────────┘
         │                               │
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│    Grafana      │    │   Prometheus    │    │      Loki       │
│   Port 3000     │    │   Port 9090     │    │   Port 3100     │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         └───────────────────────┼───────────────────────┘
                                 │
                    ┌─────────────────┐
                    │ Traffic Generator│
                    │ (Simulates Attacks)│
                    └─────────────────┘
```

The system provides complete end-to-end security monitoring with real-time threat detection, machine learning-based analysis, and comprehensive observability through Grafana and Prometheus.
