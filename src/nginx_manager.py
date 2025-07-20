"""
Nginx Manager Module

Handles nginx configuration management and rule deployment across multiple nodes.
"""

import asyncio
import httpx
import paramiko
from typing import List, Dict, Optional
from dataclasses import dataclass
from datetime import datetime
import json
import tempfile
import os


@dataclass
class NginxNode:
    """Represents an nginx node in the cluster"""
    node_id: str
    hostname: str
    ssh_host: str
    ssh_port: int
    ssh_username: str
    ssh_key_path: Optional[str]
    nginx_config_path: str
    nginx_reload_command: str
    api_endpoint: Optional[str] = None
    
    def to_dict(self) -> Dict:
        return {
            'node_id': self.node_id,
            'hostname': self.hostname,
            'ssh_host': self.ssh_host,
            'ssh_port': self.ssh_port,
            'ssh_username': self.ssh_username,
            'nginx_config_path': self.nginx_config_path,
            'nginx_reload_command': self.nginx_reload_command,
            'api_endpoint': self.api_endpoint
        }


class NginxManager:
    """Manages nginx configurations across multiple nodes"""
    
    def __init__(self, nodes: List[NginxNode]):
        self.nodes = {node.node_id: node for node in nodes}
        self.deployment_history = []
    
    async def deploy_rules_to_all_nodes(self, nginx_config: str) -> Dict[str, bool]:
        """Deploy WAF rules to all nginx nodes"""
        deployment_results = {}
        
        print(f"Deploying rules to {len(self.nodes)} nodes...")
        
        # Deploy to all nodes in parallel
        tasks = [
            self._deploy_to_node(node, nginx_config) 
            for node in self.nodes.values()
        ]
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for i, node in enumerate(self.nodes.values()):
            if isinstance(results[i], Exception):
                deployment_results[node.node_id] = False
                print(f"Failed to deploy to {node.node_id}: {results[i]}")
            else:
                deployment_results[node.node_id] = results[i]
                print(f"Deployment to {node.node_id}: {'Success' if results[i] else 'Failed'}")
        
        # Record deployment
        self.deployment_history.append({
            'timestamp': datetime.now().isoformat(),
            'config_content': nginx_config,
            'results': deployment_results
        })
        
        return deployment_results
    
    async def _deploy_to_node(self, node: NginxNode, nginx_config: str) -> bool:
        """Deploy configuration to a specific nginx node"""
        try:
            if node.api_endpoint:
                # Try API-based deployment first
                success = await self._deploy_via_api(node, nginx_config)
                if success:
                    return True
            
            # Fall back to SSH deployment
            return await self._deploy_via_ssh(node, nginx_config)
        
        except Exception as e:
            print(f"Error deploying to {node.node_id}: {e}")
            return False
    
    async def _deploy_via_api(self, node: NginxNode, nginx_config: str) -> bool:
        """Deploy configuration via API"""
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.post(
                    f"{node.api_endpoint}/api/config/deploy",
                    json={
                        'config_content': nginx_config,
                        'config_type': 'waf_rules',
                        'reload_nginx': True
                    },
                    headers={'Content-Type': 'application/json'}
                )
                return response.status_code == 200
        except Exception as e:
            print(f"API deployment failed for {node.node_id}: {e}")
            return False
    
    async def _deploy_via_ssh(self, node: NginxNode, nginx_config: str) -> bool:
        """Deploy configuration via SSH"""
        try:
            # Run SSH deployment in thread pool to avoid blocking
            loop = asyncio.get_event_loop()
            return await loop.run_in_executor(
                None, self._ssh_deploy_sync, node, nginx_config
            )
        except Exception as e:
            print(f"SSH deployment failed for {node.node_id}: {e}")
            return False
    
    def _ssh_deploy_sync(self, node: NginxNode, nginx_config: str) -> bool:
        """Synchronous SSH deployment"""
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        try:
            # Connect to the node
            if node.ssh_key_path:
                ssh.connect(
                    node.ssh_host,
                    port=node.ssh_port,
                    username=node.ssh_username,
                    key_filename=node.ssh_key_path
                )
            else:
                # This would require password authentication
                # In production, you should use key-based auth
                raise ValueError("Password authentication not implemented")
            
            # Create temporary file with configuration
            with tempfile.NamedTemporaryFile(mode='w', suffix='.conf', delete=False) as temp_file:
                temp_file.write(nginx_config)
                temp_file_path = temp_file.name
            
            try:
                # Upload configuration file
                sftp = ssh.open_sftp()
                remote_path = f"{node.nginx_config_path}/waf_rules_auto.conf"
                sftp.put(temp_file_path, remote_path)
                sftp.close()
                
                # Test nginx configuration
                stdin, stdout, stderr = ssh.exec_command("nginx -t")
                exit_code = stdout.channel.recv_exit_status()
                
                if exit_code != 0:
                    error_output = stderr.read().decode()
                    print(f"Nginx config test failed on {node.node_id}: {error_output}")
                    return False
                
                # Reload nginx
                stdin, stdout, stderr = ssh.exec_command(node.nginx_reload_command)
                exit_code = stdout.channel.recv_exit_status()
                
                if exit_code != 0:
                    error_output = stderr.read().decode()
                    print(f"Nginx reload failed on {node.node_id}: {error_output}")
                    return False
                
                return True
            
            finally:
                # Clean up temporary file
                os.unlink(temp_file_path)
        
        except Exception as e:
            print(f"SSH deployment error for {node.node_id}: {e}")
            return False
        
        finally:
            ssh.close()
    
    async def check_node_status(self, node_id: str) -> Dict[str, any]:
        """Check the status of a specific nginx node"""
        if node_id not in self.nodes:
            return {'error': f'Node {node_id} not found'}
        
        node = self.nodes[node_id]
        status = {
            'node_id': node_id,
            'hostname': node.hostname,
            'timestamp': datetime.now().isoformat(),
            'nginx_running': False,
            'config_valid': False,
            'last_reload': None,
            'error': None
        }
        
        try:
            if node.api_endpoint:
                # Check via API
                async with httpx.AsyncClient(timeout=10.0) as client:
                    response = await client.get(f"{node.api_endpoint}/api/status")
                    if response.status_code == 200:
                        api_status = response.json()
                        status.update(api_status)
                        return status
            
            # Check via SSH
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            if node.ssh_key_path:
                ssh.connect(
                    node.ssh_host,
                    port=node.ssh_port,
                    username=node.ssh_username,
                    key_filename=node.ssh_key_path
                )
            
                # Check if nginx is running
                stdin, stdout, stderr = ssh.exec_command("pgrep nginx")
                nginx_running = stdout.channel.recv_exit_status() == 0
                status['nginx_running'] = nginx_running
                
                # Check config validity
                stdin, stdout, stderr = ssh.exec_command("nginx -t")
                config_valid = stdout.channel.recv_exit_status() == 0
                status['config_valid'] = config_valid
                
                ssh.close()
        
        except Exception as e:
            status['error'] = str(e)
        
        return status
    
    async def get_cluster_status(self) -> Dict[str, any]:
        """Get status of all nodes in the cluster"""
        print("Checking cluster status...")
        
        tasks = [self.check_node_status(node_id) for node_id in self.nodes.keys()]
        node_statuses = await asyncio.gather(*tasks)
        
        cluster_status = {
            'timestamp': datetime.now().isoformat(),
            'total_nodes': len(self.nodes),
            'healthy_nodes': 0,
            'unhealthy_nodes': 0,
            'node_details': {}
        }
        
        for status in node_statuses:
            node_id = status['node_id']
            cluster_status['node_details'][node_id] = status
            
            if status.get('nginx_running') and status.get('config_valid') and not status.get('error'):
                cluster_status['healthy_nodes'] += 1
            else:
                cluster_status['unhealthy_nodes'] += 1
        
        return cluster_status
    
    def add_node(self, node: NginxNode):
        """Add a new nginx node to the cluster"""
        self.nodes[node.node_id] = node
        print(f"Added node {node.node_id} to cluster")
    
    def remove_node(self, node_id: str):
        """Remove a nginx node from the cluster"""
        if node_id in self.nodes:
            del self.nodes[node_id]
            print(f"Removed node {node_id} from cluster")
    
    def get_deployment_history(self, limit: int = 10) -> List[Dict]:
        """Get recent deployment history"""
        return self.deployment_history[-limit:] if limit > 0 else self.deployment_history


class ConfigTemplate:
    """Manages nginx configuration templates"""
    
    @staticmethod
    def generate_main_config(waf_rules_config: str) -> str:
        """Generate main nginx configuration with WAF rules"""
        return f"""
# Main nginx configuration with auto-generated WAF rules

events {{
    worker_connections 1024;
}}

http {{
    include       /etc/nginx/mime.types;
    default_type  application/octet-stream;
    
    # Logging
    log_format main '$remote_addr - $remote_user [$time_local] "$request" '
                   '$status $body_bytes_sent "$http_referer" '
                   '"$http_user_agent" "$http_x_forwarded_for"';
    
    access_log /var/log/nginx/access.log main;
    error_log /var/log/nginx/error.log;
    
    # Basic security headers
    add_header X-Frame-Options DENY;
    add_header X-Content-Type-Options nosniff;
    add_header X-XSS-Protection "1; mode=block";
    
    # Include auto-generated WAF rules
    include /etc/nginx/conf.d/waf_rules_auto.conf;
    
    # Server blocks
    server {{
        listen 80;
        server_name _;
        
        location / {{
            # WAF rules are applied here automatically
            proxy_pass http://backend;
        }}
        
        location /api/status {{
            # Status endpoint for health checks
            access_log off;
            return 200 "nginx is running\\n";
            add_header Content-Type text/plain;
        }}
    }}
    
    # Backend upstream
    upstream backend {{
        server 127.0.0.1:8080;
    }}
}}

# WAF Rules Configuration
{waf_rules_config}
"""
    
    @staticmethod
    def generate_waf_include_template() -> str:
        """Generate template for WAF rules inclusion"""
        return """
# WAF Rules Include Template
# This file is automatically generated and updated by the nginx-waf-ai system
# Do not modify manually

# Include the auto-generated WAF rules
include /etc/nginx/conf.d/waf_rules_auto.conf;

# Rate limiting configuration
limit_req_status 429;
limit_conn_status 429;
"""
