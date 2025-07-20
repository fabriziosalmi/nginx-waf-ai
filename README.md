# Nginx WAF AI

A real-time machine learning system that analyzes HTTP traffic from nginx nodes and automatically generates and deploys WAF (Web Application Firewall) rules to protect against threats.

## Overview

This system collects HTTP traffic signals from one or multiple nginx nodes, leverages real-time machine learning to detect threats and anomalies, then automatically generates and applies WAF rules to nginx nodes to block malicious traffic.

### Key Features

- **Real-time Traffic Analysis**: Continuous monitoring of HTTP requests from multiple nginx nodes
- **Machine Learning Threat Detection**: Uses anomaly detection and classification to identify threats
- **Automated Rule Generation**: Converts ML predictions into nginx-compatible WAF rules
- **Multi-node Deployment**: Distributes rules across multiple nginx instances
- **RESTful API**: Complete API for system management and monitoring
- **Command-line Interface**: CLI tools for training, deployment, and management

## Architecture

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Nginx Nodes   │───▶│  Traffic         │───▶│  ML Engine      │
│                 │    │  Collector       │    │                 │
└─────────────────┘    └──────────────────┘    └─────────────────┘
                                                         │
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Nginx Nodes   │◀───│  Rule Deployment │◀───│  WAF Rule       │
│                 │    │  Manager         │    │  Generator      │
└─────────────────┘    └──────────────────┘    └─────────────────┘
```

## Components

### 1. Traffic Collector (`src/traffic_collector.py`)
- Collects HTTP requests from nginx access logs or API endpoints
- Extracts security-relevant features (URL patterns, headers, payload characteristics)
- Preprocesses data for ML analysis

### 2. ML Engine (`src/ml_engine.py`)
- **Anomaly Detection**: Uses Isolation Forest to detect unusual traffic patterns
- **Threat Classification**: Random Forest classifier for specific threat types (SQL injection, XSS, etc.)
- **Real-time Processing**: Continuous analysis of incoming traffic
- **Incremental Learning**: Model updates with new threat data

### 3. WAF Rule Generator (`src/waf_rule_generator.py`)
- Converts ML predictions into nginx configuration rules
- Supports multiple rule types: IP blocking, URL pattern blocking, rate limiting
- Rule optimization and deduplication
- Expiration and lifecycle management

### 4. Nginx Manager (`src/nginx_manager.py`)
- Manages nginx configurations across multiple nodes
- SSH and API-based deployment methods
- Configuration validation and rollback capabilities
- Health monitoring and status reporting

### 5. API Server (`src/main.py`)
- FastAPI-based REST API for system control
- Endpoints for training, monitoring, and rule management
- Real-time status and metrics

## Installation

1. **Clone the repository**:
```bash
git clone <repository-url>
cd nginx-waf-ai
```

2. **Install dependencies**:
```bash
pip install -r requirements.txt
```

3. **Configure the system**:
```bash
python cli.py init-config --config-file config/waf_ai_config.json
```

## Quick Start

### 1. Train the ML Model

Prepare training data (JSON format with HTTP request features):
```bash
python cli.py train --training-data data/training_requests.json --labels data/threat_labels.json
```

### 2. Configure Nginx Nodes

Create a nodes configuration file (`config/nginx_nodes.json`):
```json
[
  {
    "node_id": "nginx-1",
    "hostname": "web-server-1",
    "ssh_host": "192.168.1.10",
    "ssh_username": "admin",
    "ssh_key_path": "~/.ssh/nginx_key",
    "nginx_config_path": "/etc/nginx/conf.d",
    "api_endpoint": "http://192.168.1.10:8080"
  }
]
```

### 3. Start the API Server

```bash
python cli.py serve --host 0.0.0.0 --port 8000
```

### 4. Start Traffic Collection and Processing

Via API:
```bash
# Add nginx nodes
curl -X POST "http://localhost:8000/api/nodes/add" \
  -H "Content-Type: application/json" \
  -d @config/nginx_nodes.json

# Start traffic collection
curl -X POST "http://localhost:8000/api/traffic/start-collection" \
  -H "Content-Type: application/json" \
  -d '["http://192.168.1.10:8080"]'

# Start real-time processing
curl -X POST "http://localhost:8000/api/processing/start"
```

### 5. Monitor and Deploy Rules

```bash
# Check system status
curl http://localhost:8000/api/stats

# Get recent threats
curl http://localhost:8000/api/threats

# Deploy generated rules
curl -X POST http://localhost:8000/api/rules/deploy
```

## CLI Usage

### Training
```bash
# Train ML models
python cli.py train -d training_data.json -l labels.json -o models/waf_model.joblib
```

### Traffic Collection
```bash
# Collect traffic and detect threats
python cli.py collect -n config/nginx_nodes.json -m models/waf_model.joblib -d 300
```

### Rule Generation
```bash
# Generate rules from threat data
python cli.py generate-rules -t threats.json -o rules/waf_rules.conf
```

### Deployment
```bash
# Deploy rules to nginx nodes
python cli.py deploy -n config/nginx_nodes.json -r rules/waf_rules.conf

# Check node status
python cli.py status -n config/nginx_nodes.json
```

## API Documentation

Once the server is running, visit `http://localhost:8000/docs` for interactive API documentation.

### Key Endpoints

- `POST /api/nodes/add` - Add nginx node to cluster
- `GET /api/nodes/status` - Check cluster status
- `POST /api/training/start` - Train ML models
- `POST /api/traffic/start-collection` - Start traffic collection
- `POST /api/processing/start` - Start real-time threat processing
- `GET /api/threats` - Get recent threats
- `GET /api/rules` - Get active WAF rules
- `POST /api/rules/deploy` - Deploy rules to nginx nodes

## Configuration

### Environment Variables

```bash
# API Configuration
WAF_AI_HOST=0.0.0.0
WAF_AI_PORT=8000
WAF_AI_DEBUG=false

# ML Configuration
WAF_AI_MODEL_PATH=models/waf_model.joblib
WAF_AI_THREAT_THRESHOLD=-0.5
WAF_AI_CONFIDENCE_THRESHOLD=0.8

# Traffic Collection
WAF_AI_COLLECTION_INTERVAL=1
WAF_AI_MAX_REQUESTS=10000

# Rule Management
WAF_AI_RULE_EXPIRY=24
WAF_AI_MAX_RULES=100

# Nginx Management
WAF_AI_NGINX_CONFIG_PATH=/etc/nginx/conf.d
WAF_AI_NGINX_RELOAD=sudo systemctl reload nginx
```

### Configuration File

Generate a configuration file:
```bash
python cli.py init-config --config-file config/waf_ai_config.json
```

## Security Considerations

1. **SSH Key Management**: Use dedicated SSH keys for nginx node access
2. **API Security**: Implement authentication and rate limiting in production
3. **Network Security**: Use VPN or private networks for node communication
4. **Logging**: Enable comprehensive logging for security auditing
5. **Rule Validation**: Always test nginx configurations before deployment

## Monitoring and Alerting

The system provides metrics for:
- Traffic collection rates
- Threat detection counts
- Rule deployment status
- Nginx node health
- ML model performance

Integration with monitoring systems like Prometheus is recommended for production deployments.

## Development

### Running Tests
```bash
pytest tests/
```

### Code Formatting
```bash
black src/ tests/
flake8 src/ tests/
mypy src/
```

### Contributing

1. Fork the repository
2. Create a feature branch
3. Make changes with tests
4. Submit a pull request

## License

[Add your license information here]

## Support

[Add support contact information]
