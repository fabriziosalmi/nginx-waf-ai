# Example configuration files

## nginx_nodes.json
{
  "nodes": [
    {
      "node_id": "nginx-web-1",
      "hostname": "web-server-1.example.com",
      "ssh_host": "192.168.1.10",
      "ssh_port": 22,
      "ssh_username": "nginx-admin",
      "ssh_key_path": "/path/to/ssh/keys/nginx_key",
      "nginx_config_path": "/etc/nginx/conf.d",
      "nginx_reload_command": "sudo systemctl reload nginx",
      "api_endpoint": "http://192.168.1.10:8080"
    },
    {
      "node_id": "nginx-web-2", 
      "hostname": "web-server-2.example.com",
      "ssh_host": "192.168.1.11",
      "ssh_port": 22,
      "ssh_username": "nginx-admin",
      "ssh_key_path": "/path/to/ssh/keys/nginx_key",
      "nginx_config_path": "/etc/nginx/conf.d",
      "nginx_reload_command": "sudo systemctl reload nginx",
      "api_endpoint": "http://192.168.1.11:8080"
    }
  ]
}

## training_data.json (sample)
[
  {
    "timestamp": "2024-01-01T10:00:00Z",
    "method": "GET",
    "url": "/login?id=1' OR '1'='1",
    "headers_count": 5,
    "body_length": 0,
    "source_ip": "192.168.1.100",
    "user_agent": "Mozilla/5.0",
    "content_length": 0,
    "has_suspicious_headers": false,
    "url_length": 25,
    "contains_sql_patterns": true,
    "contains_xss_patterns": false
  },
  {
    "timestamp": "2024-01-01T10:01:00Z", 
    "method": "POST",
    "url": "/search",
    "headers_count": 6,
    "body_length": 50,
    "source_ip": "192.168.1.101",
    "user_agent": "Mozilla/5.0",
    "content_length": 50,
    "has_suspicious_headers": false,
    "url_length": 7,
    "contains_sql_patterns": false,
    "contains_xss_patterns": false
  }
]

## labels.json (sample)
[
  "sql_injection",
  "normal"
]
