# nginx WAF AI - Testing Guide

## Overview
This guide explains how to test the nginx WAF AI system comprehensively. The system includes unit tests, API tests, integration tests, and full workflow demonstrations.

## Prerequisites
- Python 3.12+ with virtual environment activated
- API server running on http://localhost:8000
- All dependencies installed (run `./setup.sh` if needed)

## Testing Methods

### 1. Unit Tests
Test individual components and functions:

```bash
# Run all unit tests
pytest tests/ -v

# Run specific test files
pytest tests/test_traffic_collector.py -v
pytest tests/test_ml_engine.py -v

# Run with coverage
pytest tests/ --cov=src --cov-report=html
```

Expected output: All tests should pass
```
=================== test session starts ===================
collected 12 items

tests/test_ml_engine.py::test_ml_engine_initialization PASSED
tests/test_ml_engine.py::test_feature_extraction PASSED
tests/test_ml_engine.py::test_training_models PASSED
tests/test_ml_engine.py::test_threat_detection PASSED
tests/test_traffic_collector.py::test_traffic_collector_initialization PASSED
tests/test_traffic_collector.py::test_extract_features PASSED
tests/test_traffic_collector.py::test_sql_injection_detection PASSED
tests/test_traffic_collector.py::test_xss_detection PASSED
tests/test_traffic_collector.py::test_start_collection PASSED
tests/test_traffic_collector.py::test_stop_collection PASSED
tests/test_traffic_collector.py::test_get_stats PASSED
tests/test_traffic_collector.py::test_filter_requests PASSED

=================== 12 passed in 2.35s ===================
```

### 2. API Tests

#### A. Basic API Test
Quick validation of key endpoints:

```bash
python test_api.py
```

#### B. Individual Endpoint Tests

**Health Check:**
```bash
curl http://localhost:8000/health
```

**System Stats:**
```bash
curl http://localhost:8000/api/stats
```

**Add Node:**
```bash
curl -X POST http://localhost:8000/api/nodes/add \
  -H "Content-Type: application/json" \
  -d '{
    "node_id": "test-node",
    "hostname": "test-server",
    "ssh_host": "127.0.0.1",
    "ssh_port": 22,
    "ssh_username": "test",
    "nginx_config_path": "/tmp/nginx",
    "nginx_reload_command": "echo reload",
    "api_endpoint": "http://localhost:8080"
  }'
```

**Train ML Model:**
```bash
curl -X POST http://localhost:8000/api/training/start \
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
  }'
```

**Start Traffic Collection:**
```bash
curl -X POST http://localhost:8000/api/traffic/start-collection \
  -H "Content-Type: application/json" \
  -d '["http://localhost:8080/api/logs"]'
```

**Start Processing:**
```bash
curl -X POST http://localhost:8000/api/processing/start
```

**Get Rules:**
```bash
curl http://localhost:8000/api/rules
```

**Get Nginx Config:**
```bash
curl http://localhost:8000/api/config/nginx
```

### 3. Full System Demonstration
Complete end-to-end workflow test:

```bash
python demo.py
```

This demonstrates:
1. System health and initialization
2. Node registration
3. ML model training
4. Traffic collection setup
5. Real-time processing
6. Configuration generation
7. Node management
8. System cleanup

### 4. CLI Testing
Test the command-line interface:

```bash
# Train model
python cli.py train --data-file data/sample_training_data.json --labels-file data/sample_labels.json

# Start collection
python cli.py collect --nodes http://localhost:8080

# Check status
python cli.py status
```

### 5. Performance Testing

#### Load Testing the API:
```bash
# Install siege if not available: brew install siege (macOS) or apt-get install siege (Ubuntu)
siege -c 10 -t 30s http://localhost:8000/health
```

#### Memory/CPU Monitoring:
```bash
# Monitor server resource usage
top -p $(pgrep -f "uvicorn")

# Or use htop for better visualization
htop -p $(pgrep -f "uvicorn")
```

### 6. Integration Testing

#### Test with Mock Traffic:
1. Create a simple mock HTTP server:
```python
# mock_server.py
from http.server import HTTPServer, BaseHTTPRequestHandler
import json

class MockHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/api/logs':
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            logs = [
                {
                    "timestamp": "2024-01-01T10:00:00Z",
                    "method": "GET",
                    "url": "/admin' OR 1=1--",
                    "source_ip": "192.168.1.100",
                    "user_agent": "BadBot/1.0"
                }
            ]
            self.wfile.write(json.dumps(logs).encode())

if __name__ == '__main__':
    server = HTTPServer(('localhost', 8080), MockHandler)
    server.serve_forever()
```

2. Run the mock server in one terminal:
```bash
python mock_server.py
```

3. Test with the WAF system in another terminal:
```bash
curl -X POST http://localhost:8000/api/traffic/start-collection \
  -H "Content-Type: application/json" \
  -d '["http://localhost:8080/api/logs"]'
```

### 7. Error Testing

#### Test Error Conditions:
```bash
# Test with invalid node
curl -X POST http://localhost:8000/api/nodes/add \
  -H "Content-Type: application/json" \
  -d '{"invalid": "data"}'

# Test training with insufficient data
curl -X POST http://localhost:8000/api/training/start \
  -H "Content-Type: application/json" \
  -d '{"training_data": [], "labels": []}'

# Test starting processing without collection
curl -X POST http://localhost:8000/api/processing/stop
curl -X POST http://localhost:8000/api/processing/start
```

### 8. Docker Testing

#### Test the Dockerized version:
```bash
# Build and run
docker-compose up --build

# Test from outside container
curl http://localhost:8000/health

# Get logs
docker-compose logs waf-api
```

## Expected Results

### Unit Tests
- All 12 tests should pass
- No import errors
- No deprecation warnings (or only minor ones)

### API Tests
- All endpoints return status 200 for valid requests
- Training completes successfully
- System components show as healthy/active
- Configuration generates without errors

### Integration Tests
- Traffic collection connects successfully
- Threat detection processes requests
- Rules generate from detected threats
- Nginx configuration updates correctly

## Troubleshooting

### Common Issues

1. **Import Errors:**
   ```bash
   source .venv/bin/activate
   pip install -r requirements.txt
   ```

2. **Port Already in Use:**
   ```bash
   lsof -ti:8000 | xargs kill -9
   ```

3. **Permission Errors:**
   ```bash
   chmod +x setup.sh demo.py test_api.py
   ```

4. **ML Model Training Fails:**
   - Check data format in `data/sample_training_data.json`
   - Ensure labels match data length
   - Verify Python version compatibility

5. **SSH Connection Issues:**
   - Test nodes use mock endpoints, SSH errors are expected
   - For production, ensure SSH keys and permissions are correct

### Debugging Tips

1. **Enable Verbose Logging:**
   ```bash
   export LOG_LEVEL=DEBUG
   python run_server.py
   ```

2. **Check Server Logs:**
   - Server outputs detailed logs to console
   - Look for ERROR or WARNING messages

3. **Validate Data:**
   ```bash
   python -c "import json; print(json.load(open('data/sample_training_data.json'))[:2])"
   ```

## Success Criteria

✅ **System is Ready for Production When:**
- All unit tests pass (12/12)
- All API endpoints respond correctly
- ML model trains successfully
- Traffic collection starts without errors
- Real-time processing activates
- Nginx configuration generates
- Demo script completes successfully (10/10)

## Next Steps After Testing

1. **Production Deployment:**
   - Configure real nginx nodes
   - Set up proper SSH access
   - Configure systemd services
   - Set up monitoring

2. **Performance Optimization:**
   - Tune ML model parameters
   - Optimize collection intervals
   - Configure caching strategies

3. **Security Hardening:**
   - Enable HTTPS
   - Add authentication
   - Configure firewall rules
   - Set up logging and monitoring
