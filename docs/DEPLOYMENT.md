# Deployment Guide

This guide covers deploying the Nginx WAF AI system in production environments.

## Prerequisites

- Python 3.8+
- Docker and Docker Compose (optional)
- SSH access to nginx nodes
- Redis (for production scaling)

## Production Deployment

### 1. Environment Setup

```bash
# Create dedicated user
sudo useradd -m -s /bin/bash nginx-waf-ai

# Create application directory
sudo mkdir -p /opt/nginx-waf-ai
sudo chown nginx-waf-ai:nginx-waf-ai /opt/nginx-waf-ai

# Switch to application user
sudo su - nginx-waf-ai
cd /opt/nginx-waf-ai

# Clone and setup
git clone <repository-url> .
./setup.sh
```

### 2. Configuration

Create production configuration:

```bash
cp config/waf_ai_config.json config/production_config.json
```

Edit production settings:
```json
{
  "api_host": "127.0.0.1",
  "api_port": 8000,
  "api_debug": false,
  "log_level": "INFO",
  "log_file": "/var/log/nginx-waf-ai/waf_ai.log",
  "ml_model_path": "/opt/nginx-waf-ai/models/production_model.joblib",
  "threat_threshold": -0.3,
  "confidence_threshold": 0.85,
  "retrain_interval_hours": 12,
  "max_active_rules": 200,
  "deployment_timeout_seconds": 60
}
```

### 3. SSL/TLS Setup (Recommended)

For production, use a reverse proxy like nginx:

```nginx
# /etc/nginx/sites-available/waf-ai-api
server {
    listen 443 ssl http2;
    server_name waf-ai.example.com;
    
    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;
    
    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

### 4. Systemd Service

```bash
sudo cp examples/nginx-waf-ai.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable nginx-waf-ai
sudo systemctl start nginx-waf-ai
```

### 5. Logging Setup

```bash
# Create log directory
sudo mkdir -p /var/log/nginx-waf-ai
sudo chown nginx-waf-ai:nginx-waf-ai /var/log/nginx-waf-ai

# Setup log rotation
sudo tee /etc/logrotate.d/nginx-waf-ai << EOF
/var/log/nginx-waf-ai/*.log {
    daily
    missingok
    rotate 30
    compress
    delaycompress
    notifempty
    copytruncate
    su nginx-waf-ai nginx-waf-ai
}
EOF
```

## Docker Deployment

### 1. Production Docker Compose

```yaml
version: '3.8'

services:
  nginx-waf-ai:
    build: .
    ports:
      - "127.0.0.1:8000:8000"
    volumes:
      - ./config:/app/config:ro
      - ./models:/app/models
      - /var/log/nginx-waf-ai:/app/logs
      - ~/.ssh:/root/.ssh:ro
    environment:
      - WAF_AI_HOST=0.0.0.0
      - WAF_AI_PORT=8000
      - WAF_AI_LOG_LEVEL=INFO
      - WAF_AI_MODEL_PATH=/app/models/production_model.joblib
    restart: unless-stopped
    depends_on:
      - redis
    
  redis:
    image: redis:7-alpine
    command: redis-server --appendonly yes --requirepass ${REDIS_PASSWORD}
    volumes:
      - redis_data:/data
    environment:
      - REDIS_PASSWORD=${REDIS_PASSWORD}
    restart: unless-stopped
    
  nginx-proxy:
    image: nginx:alpine
    ports:
      - "443:443"
      - "80:80"
    volumes:
      - ./nginx-proxy.conf:/etc/nginx/nginx.conf:ro
      - ./ssl:/etc/ssl/certs:ro
    depends_on:
      - nginx-waf-ai
    restart: unless-stopped

volumes:
  redis_data:
```

### 2. Environment Variables

```bash
# .env.production
REDIS_PASSWORD=your_secure_redis_password
```

## Monitoring and Alerting

### 1. Health Check Endpoint

The system provides health checks at:
- `GET /health` - Basic health status
- `GET /api/stats` - Detailed system statistics

### 2. Prometheus Metrics

Add to your monitoring stack:

```yaml
# prometheus.yml
scrape_configs:
  - job_name: 'nginx-waf-ai'
    static_configs:
      - targets: ['localhost:8000']
    metrics_path: '/metrics'
    scrape_interval: 30s
```

### 3. Alerting Rules

```yaml
# alerting_rules.yml
groups:
  - name: nginx-waf-ai
    rules:
      - alert: WAFAIDown
        expr: up{job="nginx-waf-ai"} == 0
        for: 1m
        annotations:
          summary: "Nginx WAF AI is down"
          
      - alert: HighThreatVolume
        expr: threat_detection_rate > 100
        for: 5m
        annotations:
          summary: "High threat detection rate"
          
      - alert: ModelNotTrained
        expr: ml_model_trained == 0
        for: 1m
        annotations:
          summary: "ML model is not trained"
```

## Security Considerations

### 1. SSH Key Management

```bash
# Generate dedicated SSH key for WAF AI
ssh-keygen -t ed25519 -f /opt/nginx-waf-ai/.ssh/waf_ai_key -N ""

# Distribute public key to nginx nodes
ssh-copy-id -i /opt/nginx-waf-ai/.ssh/waf_ai_key.pub nginx@nginx-node-1
```

### 2. API Authentication

For production, implement API authentication:

```python
# In production, add authentication middleware
from fastapi import HTTPException, Depends
from fastapi.security import HTTPBearer

security = HTTPBearer()

async def verify_token(token: str = Depends(security)):
    if not validate_token(token.credentials):
        raise HTTPException(status_code=401, detail="Invalid token")
```

### 3. Network Security

- Use VPN or private networks for communication between WAF AI and nginx nodes
- Implement rate limiting on API endpoints
- Use firewall rules to restrict access

## High Availability Setup

### 1. Load Balancer Configuration

```nginx
upstream waf_ai_backend {
    server waf-ai-1:8000;
    server waf-ai-2:8000;
    server waf-ai-3:8000;
}

server {
    listen 443 ssl;
    server_name waf-ai.example.com;
    
    location / {
        proxy_pass http://waf_ai_backend;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

### 2. Database Setup

For shared state across instances:

```python
# Use Redis for shared state
import redis

redis_client = redis.Redis(
    host='redis-cluster.example.com',
    port=6379,
    password='secure_password',
    decode_responses=True
)
```

## Backup and Recovery

### 1. Model Backup

```bash
#!/bin/bash
# backup_models.sh

BACKUP_DIR="/opt/backups/nginx-waf-ai"
MODEL_DIR="/opt/nginx-waf-ai/models"
DATE=$(date +%Y%m%d_%H%M%S)

mkdir -p $BACKUP_DIR
tar -czf $BACKUP_DIR/models_$DATE.tar.gz -C $MODEL_DIR .

# Keep only last 7 days of backups
find $BACKUP_DIR -name "models_*.tar.gz" -mtime +7 -delete
```

### 2. Configuration Backup

```bash
# Include in your regular backup routine
/opt/nginx-waf-ai/config/
/var/log/nginx-waf-ai/
```

## Performance Tuning

### 1. Python Optimization

```bash
# Use production WSGI server
pip install gunicorn

# Start with optimized settings
gunicorn src.main:app \
  --workers 4 \
  --worker-class uvicorn.workers.UvicornWorker \
  --bind 0.0.0.0:8000 \
  --access-logfile /var/log/nginx-waf-ai/access.log \
  --error-logfile /var/log/nginx-waf-ai/error.log
```

### 2. Resource Limits

```ini
# /etc/systemd/system/nginx-waf-ai.service
[Service]
MemoryLimit=2G
CPUQuota=200%
TasksMax=1000
```

## Troubleshooting

### 1. Common Issues

**Model not loading:**
```bash
# Check model file permissions
ls -la /opt/nginx-waf-ai/models/
# Retrain if necessary
python3 cli.py train -d data/training_data.json
```

**SSH deployment failures:**
```bash
# Test SSH connectivity
ssh -i ~/.ssh/waf_ai_key nginx@nginx-node-1 "nginx -t"
# Check nginx syntax
```

**High memory usage:**
```bash
# Monitor memory usage
python3 -c "
import psutil
process = psutil.Process()
print(f'Memory: {process.memory_info().rss / 1024 / 1024:.1f} MB')
"
```

### 2. Log Analysis

```bash
# Monitor real-time logs
tail -f /var/log/nginx-waf-ai/waf_ai.log

# Search for errors
grep -i error /var/log/nginx-waf-ai/waf_ai.log

# Monitor threat detection
grep "threat detected" /var/log/nginx-waf-ai/waf_ai.log | tail -20
```

## Maintenance

### 1. Regular Tasks

- Model retraining (weekly/monthly based on threat landscape)
- Log rotation and cleanup
- Security updates
- Performance monitoring
- Backup verification

### 2. Updates

```bash
# Update process
cd /opt/nginx-waf-ai
git pull origin main
pip install -r requirements.txt
sudo systemctl restart nginx-waf-ai
```

For more detailed information, refer to the main README.md file.
