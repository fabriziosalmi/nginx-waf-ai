#!/bin/bash

# Nginx WAF AI Setup Script

set -e

echo "🚀 Setting up Nginx WAF AI system..."

# Create necessary directories
echo "📁 Creating directories..."
mkdir -p config data models logs examples/waf_rules

# Install Python dependencies
echo "📦 Installing dependencies..."
if command -v python3 &> /dev/null; then
    python3 -m pip install -r requirements.txt
else
    echo "❌ Python 3 is required. Please install Python 3.8+ and try again."
    exit 1
fi

# Generate initial configuration
echo "⚙️  Generating configuration..."
python3 cli.py init-config --config-file config/waf_ai_config.json

# Create example nginx nodes configuration
echo "🖥️  Creating example nginx nodes configuration..."
cat > config/nginx_nodes_example.json << 'EOF'
[
  {
    "node_id": "nginx-local",
    "hostname": "localhost",
    "ssh_host": "127.0.0.1",
    "ssh_port": 22,
    "ssh_username": "nginx",
    "ssh_key_path": "~/.ssh/id_rsa",
    "nginx_config_path": "/etc/nginx/conf.d",
    "nginx_reload_command": "sudo systemctl reload nginx",
    "api_endpoint": "http://localhost:8080"
  }
]
EOF

# Create sample training data
echo "🤖 Creating sample training data..."
cat > data/sample_training_data.json << 'EOF'
[
  {
    "timestamp": "2024-01-01T10:00:00Z",
    "method": "GET",
    "url": "/login?id=1' OR '1'='1",
    "headers_count": 5,
    "body_length": 0,
    "source_ip": "192.168.1.100",
    "user_agent": "sqlmap/1.0",
    "content_length": 0,
    "has_suspicious_headers": false,
    "url_length": 25,
    "contains_sql_patterns": true,
    "contains_xss_patterns": false
  },
  {
    "timestamp": "2024-01-01T10:01:00Z",
    "method": "POST",
    "url": "/comment",
    "headers_count": 6,
    "body_length": 50,
    "source_ip": "192.168.1.101",
    "user_agent": "Mozilla/5.0",
    "content_length": 50,
    "has_suspicious_headers": true,
    "url_length": 8,
    "contains_sql_patterns": false,
    "contains_xss_patterns": true
  },
  {
    "timestamp": "2024-01-01T10:02:00Z",
    "method": "GET",
    "url": "/search?q=normal+query",
    "headers_count": 4,
    "body_length": 0,
    "source_ip": "192.168.1.102",
    "user_agent": "Mozilla/5.0",
    "content_length": 0,
    "has_suspicious_headers": false,
    "url_length": 23,
    "contains_sql_patterns": false,
    "contains_xss_patterns": false
  }
]
EOF

cat > data/sample_labels.json << 'EOF'
[
  "sql_injection",
  "xss_attack", 
  "normal"
]
EOF

# Create example nginx configuration
echo "🔧 Creating example nginx configuration..."
cat > examples/nginx.conf << 'EOF'
events {
    worker_connections 1024;
}

http {
    include       /etc/nginx/mime.types;
    default_type  application/octet-stream;
    
    log_format main '$remote_addr - $remote_user [$time_local] "$request" '
                   '$status $body_bytes_sent "$http_referer" '
                   '"$http_user_agent" "$http_x_forwarded_for"';
    
    access_log /var/log/nginx/access.log main;
    error_log /var/log/nginx/error.log;
    
    # Include WAF rules
    include /etc/nginx/conf.d/*.conf;
    
    server {
        listen 80;
        server_name _;
        
        location / {
            return 200 "Hello from nginx with WAF protection\n";
            add_header Content-Type text/plain;
        }
        
        location /api/status {
            access_log off;
            return 200 "nginx is running\n";
            add_header Content-Type text/plain;
        }
        
        location /api/traffic-logs {
            # Mock endpoint for traffic logs
            return 200 '[]';
            add_header Content-Type application/json;
        }
    }
}
EOF

# Create example systemd service
echo "🔄 Creating systemd service example..."
cat > examples/nginx-waf-ai.service << 'EOF'
[Unit]
Description=Nginx WAF AI Service
After=network.target

[Service]
Type=simple
User=nginx-waf-ai
WorkingDirectory=/opt/nginx-waf-ai
ExecStart=/usr/bin/python3 cli.py serve
Restart=always
RestartSec=10
Environment=PYTHONPATH=/opt/nginx-waf-ai
Environment=WAF_AI_LOG_LEVEL=INFO

[Install]
WantedBy=multi-user.target
EOF

# Create development environment file
echo "🔬 Creating development environment..."
cat > .env.development << 'EOF'
# Development environment configuration
WAF_AI_HOST=0.0.0.0
WAF_AI_PORT=8000
WAF_AI_DEBUG=true
WAF_AI_LOG_LEVEL=DEBUG

# ML Configuration
WAF_AI_MODEL_PATH=models/waf_model.joblib
WAF_AI_THREAT_THRESHOLD=-0.5
WAF_AI_CONFIDENCE_THRESHOLD=0.8

# Traffic Collection
WAF_AI_COLLECTION_INTERVAL=1
WAF_AI_MAX_REQUESTS=1000

# Rule Management
WAF_AI_RULE_EXPIRY=1
WAF_AI_MAX_RULES=50
WAF_AI_OPTIMIZE_RULES=true

# Nginx Management
WAF_AI_NGINX_CONFIG_PATH=./examples/waf_rules
WAF_AI_NGINX_RELOAD=echo "Would reload nginx"
WAF_AI_DEPLOY_TIMEOUT=10
EOF

echo "✅ Setup completed successfully!"
echo ""
echo "📋 Next steps:"
echo "1. Review and customize config/waf_ai_config.json"
echo "2. Update config/nginx_nodes_example.json with your nginx nodes"
echo "3. Train the ML model: python3 cli.py train -d data/sample_training_data.json -l data/sample_labels.json"
echo "4. Start the API server: python3 cli.py serve"
echo "5. Or use Docker: docker-compose up -d"
echo ""
echo "📚 Documentation: See README.md for detailed usage instructions"
echo "🔧 Development: Source .env.development for development environment variables"
