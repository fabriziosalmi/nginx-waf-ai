# 🛡️ Nginx WAF AI - Production Ready

A production-ready AI-powered Web Application Firewall (WAF) system using machine learning for real-time threat detection. All monitoring and visualization is handled through **Grafana dashboards**.

## 🏗️ Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Nginx Node 1  │    │   Nginx Node 2  │    │  Traffic Gen    │
│   Port 8081     │    │   Port 8082     │    │  (Attacks)      │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         └───────────┬───────────┘                       │
                     │                                   │
┌─────────────────┐  │  ┌─────────────────┐             │
│  Log Server 1   │  │  │  Log Server 2   │             │
│   Port 8080     │  │  │   Port 8083     │             │
└─────────────────┘  │  └─────────────────┘             │
         │           │           │                       │
         └───────────┼───────────┘                       │
                     │                                   │
         ┌─────────────────┐                            │
         │   WAF AI API    │ ←──────────────────────────┘
         │   Port 8000     │
         └─────────────────┘
                     │
         ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
         │     Redis       │    │   Prometheus    │    │      Loki       │
         │   Port 6379     │    │   Port 9090     │    │   Port 3100     │
         └─────────────────┘    └─────────────────┘    └─────────────────┘
                                         │                       │
                                         └───────┬───────────────┘
                                                 │
                                    ┌─────────────────┐
                                    │    Grafana      │
                                    │   Port 3080     │
                                    └─────────────────┘
```

## 🚀 Quick Start

### Prerequisites
- Docker and Docker Compose
- 8GB+ RAM recommended
- Ports 3080, 8000, 8081, 8082, 9090, 6379 available

### 1. Clone and Start
```bash
git clone <repository-url>
cd nginx-waf-ai
docker-compose up -d
```

### 2. Access Grafana Dashboard
- **URL**: http://localhost:3080
- **Username**: admin  
- **Password**: waf-admin

### 3. Initialize the System
```bash
# Create admin user
curl -X POST http://localhost:8000/auth/users \
  -H "Content-Type: application/json" \
  -d '{
    "username": "admin",
    "email": "admin@example.com", 
    "password": "admin123",
    "role": "admin"
  }'

# Login to get token
curl -X POST http://localhost:8000/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "admin",
    "password": "admin123"
  }'

# Add nginx nodes (use your token)
curl -X POST http://localhost:8000/api/nodes/add \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "node_id": "nginx-node-1",
    "hostname": "nginx-node-1",
    "ssh_host": "nginx-node-1",
    "ssh_port": 22,
    "ssh_username": "root",
    "nginx_config_path": "/etc/nginx/conf.d"
  }'

# Start traffic collection
curl -X POST http://localhost:8000/api/traffic/start-collection \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '["http://log-server-1:8080", "http://log-server-2:8080"]'

# Train ML model (generates synthetic data if no real traffic)
curl -X POST http://localhost:8000/api/training/start \
  -H "Authorization: Bearer YOUR_TOKEN"

# Start real-time processing
curl -X POST http://localhost:8000/api/processing/start \
  -H "Authorization: Bearer YOUR_TOKEN"
```

## 📊 Monitoring & Dashboards

### Grafana Dashboards
The system includes pre-configured Grafana dashboards:

1. **Unified WAF Monitoring** - Main dashboard with:
   - Threat detection metrics
   - Traffic analysis
   - System health
   - Rule deployment status

2. **Infrastructure Status** - System components:
   - Container health
   - Resource usage
   - Network performance

### Prometheus Metrics
Available at http://localhost:9090/graph

Key metrics:
- `waf_threats_detected_total` - Threats by type
- `waf_requests_total` - Total requests by node/status
- `waf_traffic_volume_total` - Traffic volume
- `waf_rules_active` - Active WAF rules
- `waf_nodes_registered` - Registered nginx nodes

### Log Aggregation
Loki collects logs from all nginx nodes at http://localhost:3100

## 🎯 Core Features

### Real-Time Threat Detection
- **SQL Injection** detection
- **XSS Attack** identification  
- **Directory Traversal** prevention
- **Brute Force** protection
- **Anomaly Detection** using ML

### Machine Learning Engine
- **Supervised Learning** with threat classification
- **Unsupervised Learning** for anomaly detection
- **Real-time Processing** of HTTP requests
- **Adaptive Learning** from traffic patterns
- **Synthetic Training Data** generation

### WAF Rule Management
- **Dynamic Rule Generation** from ML insights
- **Automatic Deployment** to nginx nodes
- **Rule Optimization** and conflict resolution
- **Live Configuration Updates**

### Security & Authentication
- **JWT-based Authentication** 
- **Role-based Access Control** (Admin/Operator/Viewer)
- **Rate Limiting** protection
- **Security Headers** middleware
- **IP Blocking** and whitelisting

## 🔧 Configuration

### Environment Variables
Key configuration in `docker-compose.yml`:

```yaml
waf-api:
  environment:
    - REDIS_URL=redis://redis:6379
    - LOG_LEVEL=INFO
    - NGINX_NODES=http://log-server-1:8080,http://log-server-2:8080
    - WAF_CORS_ORIGINS=http://localhost:3080,http://127.0.0.1:3080
```

### Traffic Generator Settings
Control attack simulation:
```yaml
traffic-generator:
  environment:
    - ATTACK_PROBABILITY=0.1  # 10% malicious traffic
    - REQUEST_RATE=5          # requests per second
```

## 🛠️ API Endpoints

### Authentication
- `POST /auth/login` - User login
- `POST /auth/users` - Create user (admin)
- `GET /auth/users` - List users (admin)

### System Management  
- `GET /health` - System health check
- `GET /metrics` - Prometheus metrics
- `GET /api/stats` - System statistics
- `GET /api/debug/status` - Debug information (admin)

### ML Training & Processing
- `POST /api/training/start` - Train ML models (operator)
- `POST /api/processing/start` - Start real-time processing (operator)
- `GET /api/threats` - Get detected threats (viewer)

### Traffic & Rules
- `POST /api/traffic/start-collection` - Start traffic collection (operator)
- `GET /api/traffic/stats` - Traffic statistics (viewer)
- `GET /api/rules` - Get active WAF rules (viewer)
- `POST /api/rules/deploy` - Deploy rules to nodes (operator)

### Node Management
- `POST /api/nodes/add` - Add nginx node (admin)
- `GET /api/nodes` - List nodes (viewer)

## 🧪 Testing Attack Scenarios

The traffic generator simulates realistic attacks:

```bash
# Test SQL injection detection
curl "http://localhost:8081/api/users?id=1' OR 1=1--"

# Test XSS detection  
curl "http://localhost:8081/search?q=<script>alert('xss')</script>"

# Test directory traversal
curl "http://localhost:8081/api/file?path=../../../etc/passwd"

# Normal traffic
curl "http://localhost:8081/"
curl "http://localhost:8081/api/products"
```

## 📈 Production Deployment

### Security Hardening
1. **Change default passwords** in docker-compose.yml
2. **Use HTTPS** with proper certificates
3. **Configure firewall** rules
4. **Set up log rotation**
5. **Enable backup strategies**

### Scaling Considerations
- **Horizontal scaling**: Add more nginx nodes
- **Database scaling**: Use external Redis cluster
- **Load balancing**: Add load balancer for WAF API
- **Monitoring scaling**: Use Prometheus federation

### Performance Tuning
- **Adjust traffic collection frequency**
- **Optimize ML model parameters**
- **Configure proper resource limits**
- **Use SSD storage for logs**

## 🔍 Troubleshooting

### Common Issues

1. **ML Training Fails**
   ```bash
   # Check if traffic collection is active
   curl -H "Authorization: Bearer YOUR_TOKEN" http://localhost:8000/api/traffic/stats
   
   # If no traffic, training will use synthetic data
   ```

2. **No Threats Detected**
   - Ensure traffic generator is running
   - Check ML model is trained
   - Verify real-time processing is active

3. **Grafana Dashboard Empty**
   - Wait 30-60 seconds for metrics to populate
   - Check Prometheus targets: http://localhost:9090/targets
   - Verify WAF API is exposing metrics: http://localhost:8000/metrics

4. **Authentication Issues**
   - Create user first with `/auth/users`
   - Use JWT token in Authorization header
   - Check token hasn't expired

## 📝 Development

### Adding New Threat Detection
1. Update `src/training_data_generator.py` with new patterns
2. Modify `src/traffic_collector.py` pattern detection
3. Add new threat types to ML engine
4. Update Grafana dashboards for new metrics

### Custom Rules
1. Extend `src/waf_rule_generator.py`
2. Add rule templates in nginx configuration
3. Update deployment logic in `src/nginx_manager.py`

## 🤝 Contributing

1. Fork the repository
2. Create feature branch: `git checkout -b feature/new-feature`
3. Commit changes: `git commit -am 'Add new feature'`
4. Push to branch: `git push origin feature/new-feature`
5. Submit Pull Request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🙏 Acknowledgments

- Built with FastAPI, scikit-learn, and modern security practices
- Inspired by modern WAF solutions and ML-driven security
- Grafana dashboards for comprehensive monitoring
- Docker containerization for easy deployment
