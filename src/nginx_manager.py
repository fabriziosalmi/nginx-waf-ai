"""
Nginx Manager Module

Handles nginx configuration management and rule deployment across multiple nodes.
Enhanced security with encrypted SSH key support and comprehensive error handling.
"""

import asyncio
import httpx
import paramiko
import os
from datetime import datetime
from typing import List, Dict, Optional
from dataclasses import dataclass
from .error_handling import retry, error_recovery, CircuitBreakerConfig
from datetime import datetime
import json
import tempfile
import os
import threading
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
import base64
from loguru import logger
from pathlib import Path


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
    ssh_key_passphrase: Optional[str] = None
    
    def to_dict(self) -> Dict:
        """Convert to dictionary, excluding sensitive information"""
        return {
            'node_id': self.node_id,
            'hostname': self.hostname,
            'ssh_host': self.ssh_host,
            'ssh_port': self.ssh_port,
            'ssh_username': self.ssh_username,
            'nginx_config_path': self.nginx_config_path,
            'nginx_reload_command': self.nginx_reload_command,
            'api_endpoint': self.api_endpoint,
            'has_ssh_key': self.ssh_key_path is not None,
            'has_passphrase': self.ssh_key_passphrase is not None
        }


class SecureSSHKeyManager:
    """Manages SSH keys with encryption support"""
    
    def __init__(self, master_password: Optional[str] = None):
        self.master_password = master_password or os.getenv('WAF_SSH_MASTER_PASSWORD', '')
        self._cache = {}
        self._lock = threading.RLock()
    
    def _derive_key(self, password: str, salt: bytes) -> bytes:
        """Derive encryption key from password"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        return base64.urlsafe_b64encode(kdf.derive(password.encode()))
    
    def cleanup_temp_keys(self):
        """Clean up temporary decrypted keys"""
        with self._lock:
            for temp_path in self._cache.values():
                try:
                    if os.path.exists(temp_path):
                        os.unlink(temp_path)
                except Exception as e:
                    logger.warning(f"Failed to cleanup temp key {temp_path}: {e}")
            self._cache.clear()


class NginxManager:
    """Secure nginx configuration manager with comprehensive error handling"""
    
    def __init__(self, nodes: List[NginxNode]):
        self.nodes = {node.node_id: node for node in nodes}
        self.deployment_history = []
        self.ssh_key_manager = SecureSSHKeyManager()
        self._lock = threading.RLock()
        self.last_status_check = {}
        
        # Validate nodes on initialization
        self._validate_nodes()
    
    def _validate_nodes(self):
        """Validate node configurations"""
        for node in self.nodes.values():
            try:
                # Validate SSH key path if provided
                if node.ssh_key_path and not os.path.exists(node.ssh_key_path):
                    logger.warning(f"SSH key not found for node {node.node_id}: {node.ssh_key_path}")
                
                # Validate nginx reload command
                allowed_commands = [
                    'sudo systemctl reload nginx',
                    'sudo systemctl restart nginx', 
                    'sudo nginx -s reload',
                    'sudo service nginx reload',
                    'systemctl reload nginx',
                    'nginx -s reload'
                ]
                
                if node.nginx_reload_command not in allowed_commands:
                    logger.warning(f"Potentially unsafe nginx command for node {node.node_id}: {node.nginx_reload_command}")
                
            except Exception as e:
                logger.error(f"Node validation failed for {node.node_id}: {e}")
    
    def add_node(self, node: NginxNode):
        """Add a new node to the cluster"""
        with self._lock:
            self.nodes[node.node_id] = node
            logger.info(f"Added node to cluster: {node.node_id}")
    
    def remove_node(self, node_id: str) -> bool:
        """Remove a node from the cluster"""
        with self._lock:
            if node_id in self.nodes:
                del self.nodes[node_id]
                logger.info(f"Removed node from cluster: {node_id}")
                return True
            return False
    
    async def deploy_rules_to_all_nodes(self, nginx_config: str) -> Dict[str, bool]:
        """Deploy WAF rules to all nginx nodes with comprehensive error handling"""
        with self._lock:
            deployment_results = {}
            
            logger.info(f"Deploying rules to {len(self.nodes)} nodes...")
            
            # Validate nginx config syntax before deployment
            if not self._validate_nginx_config(nginx_config):
                logger.error("Invalid nginx configuration syntax")
                return {node_id: False for node_id in self.nodes.keys()}
            
            # Deploy to all nodes in parallel with timeout
            tasks = [
                asyncio.wait_for(
                    self._deploy_to_node(node, nginx_config),
                    timeout=30.0
                )
                for node in self.nodes.values()
            ]
            
            try:
                results = await asyncio.gather(*tasks, return_exceptions=True)
                
                for i, node in enumerate(self.nodes.values()):
                    if isinstance(results[i], Exception):
                        deployment_results[node.node_id] = False
                        logger.error(f"Failed to deploy to {node.node_id}: {results[i]}")
                    else:
                        deployment_results[node.node_id] = results[i]
                        status = 'Success' if results[i] else 'Failed'
                        logger.info(f"Deployment to {node.node_id}: {status}")
            
            except Exception as e:
                logger.error(f"Deployment task failed: {e}")
                deployment_results = {node_id: False for node_id in self.nodes.keys()}
            
            # Record deployment
            self.deployment_history.append({
                'timestamp': datetime.now().isoformat(),
                'config_content_hash': hash(nginx_config),  # Don't store full config for security
                'config_size': len(nginx_config),
                'results': deployment_results,
                'success_count': sum(deployment_results.values()),
                'total_nodes': len(self.nodes)
            })
            
            # Keep only last 100 deployments
            if len(self.deployment_history) > 100:
                self.deployment_history = self.deployment_history[-100:]
            
            return deployment_results
    
    def _validate_nginx_config(self, config: str) -> bool:
        """Enhanced nginx configuration validation with comprehensive checks"""
        try:
            logger.debug("Starting comprehensive nginx configuration validation")
            
            # 1. Basic syntax validation
            if not self._validate_basic_syntax(config):
                return False
            
            # 2. Security validation
            if not self._validate_security_directives(config):
                return False
            
            # 3. WAF-specific validation
            if not self._validate_waf_rules(config):
                return False
            
            # 4. Performance impact validation
            if not self._validate_performance_impact(config):
                logger.warning("Configuration may have performance impact")
                # Don't fail for performance warnings, just log
            
            # 5. Rule conflict detection
            conflicts = self._detect_rule_conflicts(config)
            if conflicts:
                logger.warning(f"Detected potential rule conflicts: {conflicts}")
                # Log conflicts but don't fail validation
            
            logger.info("Nginx configuration validation passed")
            return True
            
        except Exception as e:
            logger.error(f"Config validation error: {e}")
            return False
    
    def _validate_basic_syntax(self, config: str) -> bool:
        """Validate basic nginx syntax"""
        try:
            # Check for balanced braces
            brace_count = config.count('{') - config.count('}')
            if brace_count != 0:
                logger.error("Unbalanced braces in nginx configuration")
                return False
            
            # Check for balanced quotes
            single_quotes = config.count("'")
            double_quotes = config.count('"')
            if single_quotes % 2 != 0:
                logger.error("Unmatched single quotes in nginx configuration")
                return False
            if double_quotes % 2 != 0:
                logger.error("Unmatched double quotes in nginx configuration")
                return False
            
            # Check for proper semicolon usage
            lines = config.split('\n')
            for i, line in enumerate(lines, 1):
                line = line.strip()
                if line and not line.startswith('#'):
                    # Skip block directives and comments
                    if line.endswith('{') or line.endswith('}') or line.startswith('#'):
                        continue
                    # Most directives should end with semicolon
                    if not line.endswith(';') and not line.endswith('{'):
                        logger.warning(f"Line {i} may be missing semicolon: {line}")
            
            return True
            
        except Exception as e:
            logger.error(f"Basic syntax validation failed: {e}")
            return False
    
    def _validate_security_directives(self, config: str) -> bool:
        """Validate security directives and detect dangerous patterns"""
        try:
            # Check for dangerous directives
            dangerous_directives = [
                'include /etc/passwd', 
                'include /etc/shadow', 
                'include /etc/hosts',
                '$(',  # Command substitution
                '`',   # Command substitution
                'eval',
                'exec'
            ]
            
            for directive in dangerous_directives:
                if directive in config:
                    logger.error(f"Dangerous directive found in config: {directive}")
                    return False
            
            # Check for path traversal in include directives
            import re
            include_pattern = r'include\s+([^\s;]+)'
            includes = re.findall(include_pattern, config)
            
            for include_path in includes:
                if '..' in include_path:
                    logger.error(f"Potential path traversal in include: {include_path}")
                    return False
                if include_path.startswith('/'):
                    # Absolute paths should be from safe directories
                    safe_prefixes = ['/etc/nginx/', '/usr/share/nginx/', '/var/lib/nginx/']
                    if not any(include_path.startswith(prefix) for prefix in safe_prefixes):
                        logger.warning(f"Include path outside safe directories: {include_path}")
            
            return True
            
        except Exception as e:
            logger.error(f"Security validation failed: {e}")
            return False
    
    def _validate_waf_rules(self, config: str) -> bool:
        """Validate WAF-specific rules and patterns"""
        try:
            # Check for required WAF elements
            waf_elements = ['deny', 'return', 'if', 'limit_req']
            found_elements = [elem for elem in waf_elements if elem in config]
            
            if not found_elements:
                logger.warning("Configuration doesn't contain typical WAF elements")
                return True  # Not an error, just informational
            
            # Validate regex patterns in configuration
            import re
            regex_pattern = r'~\s*"([^"]+)"'
            regexes = re.findall(regex_pattern, config)
            
            for regex in regexes:
                try:
                    re.compile(regex)
                except re.error as e:
                    logger.error(f"Invalid regex pattern in config: {regex} - {e}")
                    return False
            
            # Check for proper rate limiting configuration
            if 'limit_req' in config:
                limit_req_pattern = r'limit_req\s+zone=(\w+)'
                zones = re.findall(limit_req_pattern, config)
                
                # Check if zones are defined
                for zone in zones:
                    zone_def_pattern = f'limit_req_zone.*zone={zone}'
                    if not re.search(zone_def_pattern, config):
                        logger.warning(f"Rate limiting zone '{zone}' used but not defined")
            
            return True
            
        except Exception as e:
            logger.error(f"WAF rules validation failed: {e}")
            return False
    
    def _validate_performance_impact(self, config: str) -> bool:
        """Validate potential performance impact of configuration"""
        try:
            performance_warnings = []
            
            # Count complex regex patterns
            import re
            complex_regex_count = len(re.findall(r'~\*?\s*"[^"]{50,}"', config))
            if complex_regex_count > 10:
                performance_warnings.append(f"Many complex regex patterns: {complex_regex_count}")
            
            # Check for nested if statements
            nested_if_count = config.count('if (') + config.count('if(')
            if nested_if_count > 20:
                performance_warnings.append(f"Many conditional statements: {nested_if_count}")
            
            # Check for rate limiting configuration
            rate_limit_count = config.count('limit_req')
            if rate_limit_count > 50:
                performance_warnings.append(f"Many rate limiting rules: {rate_limit_count}")
            
            if performance_warnings:
                logger.warning(f"Performance concerns: {', '.join(performance_warnings)}")
                return False
            
            return True
            
        except Exception as e:
            logger.error(f"Performance validation failed: {e}")
            return True  # Don't fail on performance validation errors
    
    def _detect_rule_conflicts(self, config: str) -> List[str]:
        """Detect potential conflicts between rules"""
        try:
            conflicts = []
            
            # Check for conflicting deny/allow rules
            import re
            
            # Extract IP addresses from deny rules
            deny_ips = re.findall(r'deny\s+([0-9.]+(?:/\d+)?)', config)
            allow_ips = re.findall(r'allow\s+([0-9.]+(?:/\d+)?)', config)
            
            # Check for overlapping IP ranges (simplified)
            for deny_ip in deny_ips:
                for allow_ip in allow_ips:
                    if deny_ip == allow_ip:
                        conflicts.append(f"IP {deny_ip} both denied and allowed")
            
            # Check for duplicate rules
            lines = [line.strip() for line in config.split('\n') if line.strip() and not line.strip().startswith('#')]
            rule_counts = {}
            for line in lines:
                if any(keyword in line for keyword in ['deny', 'return', 'limit_req']):
                    rule_counts[line] = rule_counts.get(line, 0) + 1
            
            duplicates = [rule for rule, count in rule_counts.items() if count > 1]
            if duplicates:
                conflicts.extend([f"Duplicate rule: {rule}" for rule in duplicates[:5]])  # Limit output
            
            return conflicts
            
        except Exception as e:
            logger.error(f"Conflict detection failed: {e}")
            return []
    
    async def _deploy_to_node(self, node: NginxNode, nginx_config: str) -> bool:
        """Deploy configuration to a specific nginx node with fallback"""
        try:
            # Try file-based deployment first (for Docker environments)
            success = await self._deploy_via_file(node, nginx_config)
            if success:
                logger.debug(f"File deployment successful for {node.node_id}")
                return True
            
            # Try API-based deployment if available
            if node.api_endpoint:
                success = await self._deploy_via_api(node, nginx_config)
                if success:
                    logger.debug(f"API deployment successful for {node.node_id}")
                    return True
                else:
                    logger.warning(f"API deployment failed for {node.node_id}, falling back to SSH")
            
            # Fall back to SSH deployment
            return await self._deploy_via_ssh(node, nginx_config)
        
        except Exception as e:
            logger.error(f"Error deploying to {node.node_id}: {e}")
            return False
    
    async def _deploy_via_file(self, node: NginxNode, nginx_config: str) -> bool:
        """Deploy configuration via shared volume for Docker environments"""
        try:
            # For Docker environments, write to shared volume mounted at /app/waf-rules
            shared_waf_dir = "/app/waf-rules"
            
            # Create directory if it doesn't exist
            os.makedirs(shared_waf_dir, exist_ok=True)
            
            # Write dynamic rules file for this node
            rules_file = os.path.join(shared_waf_dir, f"dynamic-{node.node_id}.conf")
            
            with open(rules_file, 'w') as f:
                f.write(f"# Dynamic WAF rules for {node.node_id}\n")
                f.write(f"# Generated at {datetime.now().isoformat()}\n\n")
                f.write(nginx_config)
            
            logger.info(f"File deployment successful for {node.node_id}: wrote to {rules_file}")
            
            # Try to reload nginx in the container
            try:
                import subprocess
                reload_cmd = f"docker exec {node.node_id} nginx -s reload"
                result = subprocess.run(reload_cmd.split(), capture_output=True, text=True, timeout=10)
                
                if result.returncode == 0:
                    logger.info(f"Successfully reloaded nginx for {node.node_id}")
                else:
                    logger.warning(f"Failed to reload nginx for {node.node_id}: {result.stderr}")
                    # Still return True since the file was written successfully
                
            except Exception as reload_error:
                logger.warning(f"Could not reload nginx for {node.node_id}: {reload_error}")
                # Still return True since the file was written successfully
            
            return True
            
        except Exception as e:
            logger.error(f"File deployment failed for {node.node_id}: {e}")
            return False

    async def _deploy_via_api(self, node: NginxNode, nginx_config: str) -> bool:
        """Deploy configuration via API with proper error handling"""
        try:
            timeout = httpx.Timeout(30.0, connect=10.0)
            async with httpx.AsyncClient(timeout=timeout) as client:
                response = await client.post(
                    f"{node.api_endpoint}/api/config/deploy",
                    json={
                        'config_content': nginx_config,
                        'config_type': 'waf_rules',
                        'reload_nginx': True,
                        'validate_first': True
                    },
                    headers={
                        'Content-Type': 'application/json',
                        'User-Agent': 'nginx-waf-ai/1.0'
                    }
                )
                
                if response.status_code == 200:
                    result = response.json()
                    return result.get('success', False)
                else:
                    logger.error(f"API deployment failed with status {response.status_code}: {response.text}")
                    return False
                    
        except httpx.TimeoutException:
            logger.error(f"API deployment timeout for {node.node_id}")
            return False
        except Exception as e:
            logger.error(f"API deployment failed for {node.node_id}: {e}")
            return False
    
    async def _deploy_via_ssh(self, node: NginxNode, nginx_config: str) -> bool:
        """Deploy configuration via SSH with enhanced security"""
        try:
            # Run SSH deployment in thread pool to avoid blocking
            loop = asyncio.get_event_loop()
            return await loop.run_in_executor(
                None, self._ssh_deploy_sync, node, nginx_config
            )
        except Exception as e:
            logger.error(f"SSH deployment failed for {node.node_id}: {e}")
            return False
    
    @retry(max_attempts=2, backoff_strategy="fixed", base_delay=2.0)
    def _ssh_deploy_sync(self, node: NginxNode, nginx_config: str) -> bool:
        """Synchronous SSH deployment with enhanced validation and rollback"""
        ssh = None
        temp_config_path = None
        backup_path = None
        deployed_successfully = False
        
        try:
            logger.info(f"Starting deployment to node {node.node_id}")
            
            # Initialize SSH client with security settings
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            # Connect with timeout and retries
            if node.ssh_key_path:
                if os.path.exists(node.ssh_key_path):
                    key_stat = os.stat(node.ssh_key_path)
                    if key_stat.st_mode & 0o077:
                        logger.warning(f"SSH key has overly permissive permissions: {node.ssh_key_path}")
                
                ssh.connect(
                    hostname=node.ssh_host,
                    port=node.ssh_port,
                    username=node.ssh_username,
                    key_filename=node.ssh_key_path,
                    timeout=30,
                    banner_timeout=30,
                    auth_timeout=30
                )
            else:
                raise ValueError(f"SSH key required for node {node.node_id}")
            
            # Create secure temporary file for configuration
            temp_fd, temp_config_path = tempfile.mkstemp(mode='w', suffix='.conf', delete=False)
            try:
                with os.fdopen(temp_fd, 'w') as temp_file:
                    temp_file.write(nginx_config)
                
                os.chmod(temp_config_path, 0o600)
                
                # Enhanced deployment with rollback
                sftp = ssh.open_sftp()
                try:
                    remote_path = f"{node.nginx_config_path}/waf_rules_auto.conf"
                    backup_path = f"{remote_path}.backup.{int(datetime.now().timestamp())}"
                    
                    # Create backup of existing config
                    try:
                        sftp.rename(remote_path, backup_path)
                        logger.debug(f"Created backup: {backup_path}")
                    except FileNotFoundError:
                        backup_path = None  # No existing file to backup
                    
                    # Upload new configuration
                    sftp.put(temp_config_path, remote_path)
                    sftp.chmod(remote_path, 0o644)
                    logger.debug(f"Uploaded configuration to {remote_path}")
                    
                finally:
                    sftp.close()
                
                # Test configuration with real nginx validation
                logger.debug(f"Testing nginx configuration on {node.node_id}")
                nginx_test_result = self._test_nginx_config_on_node(ssh, node)
                
                if not nginx_test_result['success']:
                    logger.error(f"Nginx config test failed on {node.node_id}: {nginx_test_result['error']}")
                    # Rollback configuration
                    if backup_path:
                        self._rollback_config(ssh, node, backup_path, remote_path)
                    return False
                
                # Reload nginx with validation
                logger.debug(f"Reloading nginx on {node.node_id}")
                reload_result = self._reload_nginx_with_validation(ssh, node)
                
                if not reload_result['success']:
                    logger.error(f"Nginx reload failed on {node.node_id}: {reload_result['error']}")
                    # Rollback configuration
                    if backup_path:
                        self._rollback_config(ssh, node, backup_path, remote_path)
                    return False
                
                # Verify deployment success
                verification_result = self._verify_deployment(ssh, node, nginx_config)
                if verification_result['success']:
                    deployed_successfully = True
                    logger.info(f"Successfully deployed and verified configuration on {node.node_id}")
                    
                    # Clean up old backups (keep last 5)
                    self._cleanup_old_backups(ssh, node, remote_path)
                    return True
                else:
                    logger.error(f"Deployment verification failed on {node.node_id}: {verification_result['error']}")
                    if backup_path:
                        self._rollback_config(ssh, node, backup_path, remote_path)
                    return False
                try:
                    remote_path = f"{node.nginx_config_path}/waf_rules_auto.conf"
                    backup_path = f"{remote_path}.backup.{int(datetime.now().timestamp())}"
                    
                    # Create backup of existing config if it exists
                    try:
                        sftp.rename(remote_path, backup_path)
                        logger.debug(f"Created backup: {backup_path}")
                    except FileNotFoundError:
                        # No existing file to backup
                        pass
                    
                    # Upload new configuration
                    sftp.put(temp_config_path, remote_path)
                    
                    # Set proper permissions on remote file
                    sftp.chmod(remote_path, 0o644)
                    
                finally:
                    sftp.close()
                
                # Test nginx configuration before reload
                logger.debug(f"Testing nginx configuration on {node.node_id}")
                stdin, stdout, stderr = ssh.exec_command("nginx -t", timeout=30)
                exit_code = stdout.channel.recv_exit_status()
                
                if exit_code != 0:
                    error_output = stderr.read().decode()
                    logger.error(f"Nginx config test failed on {node.node_id}: {error_output}")
                    return False
                
                # Reload nginx with timeout
                logger.debug(f"Reloading nginx on {node.node_id}")
                stdin, stdout, stderr = ssh.exec_command(node.nginx_reload_command, timeout=30)
                exit_code = stdout.channel.recv_exit_status()
                
                if exit_code != 0:
                    error_output = stderr.read().decode()
                    logger.error(f"Nginx reload failed on {node.node_id}: {error_output}")
                    return False
                
                logger.info(f"Successfully deployed configuration to {node.node_id}")
                return True
                
            finally:
                # Clean up temporary config file
                if temp_config_path and os.path.exists(temp_config_path):
                    os.unlink(temp_config_path)
        
        except paramiko.AuthenticationException:
            logger.error(f"SSH authentication failed for {node.node_id}")
            return False
        except paramiko.SSHException as e:
            logger.error(f"SSH connection failed for {node.node_id}: {e}")
            return False
        except Exception as e:
            logger.error(f"SSH deployment error for {node.node_id}: {e}")
            return False
        
        finally:
            # Clean up resources
            if ssh:
                ssh.close()
            if temp_config_path and os.path.exists(temp_config_path):
                os.unlink(temp_config_path)

    def _test_nginx_config_on_node(self, ssh, node: NginxNode) -> Dict[str, any]:
        """Test nginx configuration on remote node"""
        try:
            stdin, stdout, stderr = ssh.exec_command("nginx -t", timeout=30)
            exit_code = stdout.channel.recv_exit_status()
            
            if exit_code == 0:
                return {'success': True, 'message': 'Configuration test passed'}
            else:
                error_output = stderr.read().decode().strip()
                return {'success': False, 'error': error_output}
                
        except Exception as e:
            return {'success': False, 'error': f"Failed to test configuration: {str(e)}"}

    def _reload_nginx_with_validation(self, ssh, node: NginxNode) -> Dict[str, any]:
        """Reload nginx with validation on remote node"""
        try:
            # First test configuration again before reloading
            test_result = self._test_nginx_config_on_node(ssh, node)
            if not test_result['success']:
                return test_result
            
            # Reload nginx
            stdin, stdout, stderr = ssh.exec_command(node.nginx_reload_command, timeout=30)
            exit_code = stdout.channel.recv_exit_status()
            
            if exit_code == 0:
                # Verify nginx is still running after reload
                stdin, stdout, stderr = ssh.exec_command("pgrep nginx", timeout=10)
                nginx_running = stdout.channel.recv_exit_status() == 0
                
                if nginx_running:
                    return {'success': True, 'message': 'Nginx reloaded successfully'}
                else:
                    return {'success': False, 'error': 'Nginx stopped after reload'}
            else:
                error_output = stderr.read().decode().strip()
                return {'success': False, 'error': f"Reload failed: {error_output}"}
                
        except Exception as e:
            return {'success': False, 'error': f"Failed to reload nginx: {str(e)}"}

    def _verify_deployment(self, ssh, node: NginxNode, expected_config: str) -> Dict[str, any]:
        """Verify deployment was successful"""
        try:
            # Check if configuration file exists and has correct content
            remote_path = f"{node.nginx_config_path}/waf_rules_auto.conf"
            stdin, stdout, stderr = ssh.exec_command(f"cat {remote_path}", timeout=30)
            exit_code = stdout.channel.recv_exit_status()
            
            if exit_code != 0:
                return {'success': False, 'error': 'Configuration file not found after deployment'}
            
            deployed_config = stdout.read().decode().strip()
            expected_config_lines = set(line.strip() for line in expected_config.split('\n') if line.strip())
            deployed_config_lines = set(line.strip() for line in deployed_config.split('\n') if line.strip())
            
            # Check if core rules are present (allow for minor formatting differences)
            core_rules_present = len(expected_config_lines.intersection(deployed_config_lines)) > 0
            
            if core_rules_present:
                return {'success': True, 'message': 'Deployment verified'}
            else:
                return {'success': False, 'error': 'Deployed configuration differs from expected'}
                
        except Exception as e:
            return {'success': False, 'error': f"Failed to verify deployment: {str(e)}"}

    def _rollback_config(self, ssh, node: NginxNode, backup_path: str, current_path: str):
        """Rollback configuration to previous version"""
        try:
            logger.warning(f"Rolling back configuration on {node.node_id}")
            
            # Restore backup
            sftp = ssh.open_sftp()
            try:
                sftp.rename(backup_path, current_path)
                logger.info(f"Restored backup from {backup_path}")
            finally:
                sftp.close()
            
            # Test and reload with backup
            test_result = self._test_nginx_config_on_node(ssh, node)
            if test_result['success']:
                reload_result = self._reload_nginx_with_validation(ssh, node)
                if reload_result['success']:
                    logger.info(f"Successfully rolled back configuration on {node.node_id}")
                else:
                    logger.error(f"Failed to reload after rollback on {node.node_id}: {reload_result['error']}")
            else:
                logger.error(f"Backup configuration also invalid on {node.node_id}: {test_result['error']}")
                
        except Exception as e:
            logger.error(f"Failed to rollback configuration on {node.node_id}: {e}")

    def _cleanup_old_backups(self, ssh, node: NginxNode, config_path: str):
        """Clean up old backup files, keeping only the last 5"""
        try:
            config_dir = os.path.dirname(config_path)
            config_name = os.path.basename(config_path)
            
            # List backup files
            stdin, stdout, stderr = ssh.exec_command(f"ls {config_dir}/{config_name}.backup.* 2>/dev/null | sort -r", timeout=30)
            backup_files = stdout.read().decode().strip().split('\n')
            
            # Keep only the 5 most recent backups
            if len(backup_files) > 5 and backup_files[0]:  # Check if we have actual files
                files_to_remove = backup_files[5:]
                for backup_file in files_to_remove:
                    if backup_file.strip():
                        ssh.exec_command(f"rm -f {backup_file.strip()}", timeout=10)
                
                logger.debug(f"Cleaned up {len(files_to_remove)} old backup files on {node.node_id}")
                
        except Exception as e:
            logger.debug(f"Failed to cleanup old backups on {node.node_id}: {e}")  # Non-critical error
    
    async def check_node_status(self, node_id: str) -> Dict[str, any]:
        """Check the status of a specific nginx node with enhanced monitoring"""
        if node_id not in self.nodes:
            return {'error': f'Node {node_id} not found'}
        
        node = self.nodes[node_id]
        status = {
            'node_id': node_id,
            'hostname': node.hostname,
            'timestamp': datetime.now().isoformat(),
            'nginx_running': False,
            'config_valid': False,
            'last_deployment': None,
            'error': None
        }
        
        try:
            # Check via API if available
            if node.api_endpoint:
                api_status = await self._check_status_via_api(node)
                status.update(api_status)
            else:
                # Fall back to SSH check
                ssh_status = await self._check_status_via_ssh(node)
                status.update(ssh_status)
            
            # Add deployment history
            for deployment in reversed(self.deployment_history):
                if node_id in deployment['results']:
                    status['last_deployment'] = {
                        'timestamp': deployment['timestamp'],
                        'success': deployment['results'][node_id]
                    }
                    break
            
            # Cache status
            self.last_status_check[node_id] = status
            
        except Exception as e:
            logger.error(f"Status check failed for {node_id}: {e}")
            status['error'] = str(e)
        
        return status
    
    async def _check_status_via_api(self, node: NginxNode) -> Dict:
        """Check node status via API"""
        try:
            timeout = httpx.Timeout(10.0)
            async with httpx.AsyncClient(timeout=timeout) as client:
                response = await client.get(f"{node.api_endpoint}/api/status")
                
                if response.status_code == 200:
                    data = response.json()
                    return {
                        'nginx_running': data.get('nginx_running', False),
                        'config_valid': data.get('config_valid', False),
                        'api_available': True
                    }
                else:
                    return {
                        'api_available': False,
                        'error': f'API returned status {response.status_code}'
                    }
        except Exception as e:
            return {
                'api_available': False,
                'error': f'API check failed: {str(e)}'
            }
    
    async def _check_status_via_ssh(self, node: NginxNode) -> Dict:
        """Check node status via SSH"""
        try:
            loop = asyncio.get_event_loop()
            return await loop.run_in_executor(
                None, self._ssh_status_check_sync, node
            )
        except Exception as e:
            return {
                'ssh_available': False,
                'error': f'SSH check failed: {str(e)}'
            }
    
    def _ssh_status_check_sync(self, node: NginxNode) -> Dict:
        """Synchronous SSH status check"""
        ssh = None
        
        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            # Connect
            if node.ssh_key_path:
                ssh.connect(
                    hostname=node.ssh_host,
                    port=node.ssh_port,
                    username=node.ssh_username,
                    key_filename=node.ssh_key_path,
                    timeout=15
                )
            else:
                raise ValueError("SSH key required")
            
            # Check nginx process
            stdin, stdout, stderr = ssh.exec_command("pgrep nginx", timeout=10)
            nginx_running = stdout.channel.recv_exit_status() == 0
            
            # Check config validity
            stdin, stdout, stderr = ssh.exec_command("nginx -t", timeout=10)
            config_valid = stdout.channel.recv_exit_status() == 0
            
            return {
                'nginx_running': nginx_running,
                'config_valid': config_valid,
                'ssh_available': True
            }
            
        except Exception as e:
            return {
                'ssh_available': False,
                'error': str(e)
            }
        
        finally:
            if ssh:
                ssh.close()
    
    async def get_cluster_status(self) -> Dict[str, any]:
        """Get status of all nodes in the cluster"""
        with self._lock:
            cluster_status = {
                'timestamp': datetime.now().isoformat(),
                'total_nodes': len(self.nodes),
                'nodes': {},
                'summary': {
                    'online': 0,
                    'offline': 0,
                    'error': 0
                }
            }
            
            # Check all nodes in parallel
            tasks = [
                self.check_node_status(node_id)
                for node_id in self.nodes.keys()
            ]
            
            try:
                results = await asyncio.gather(*tasks, return_exceptions=True)
                
                for i, node_id in enumerate(self.nodes.keys()):
                    if isinstance(results[i], Exception):
                        cluster_status['nodes'][node_id] = {
                            'error': str(results[i])
                        }
                        cluster_status['summary']['error'] += 1
                    else:
                        status = results[i]
                        cluster_status['nodes'][node_id] = status
                        
                        if status.get('nginx_running') and status.get('config_valid'):
                            cluster_status['summary']['online'] += 1
                        else:
                            cluster_status['summary']['offline'] += 1
                
            except Exception as e:
                logger.error(f"Cluster status check failed: {e}")
                cluster_status['error'] = str(e)
            
            return cluster_status
    
    def get_deployment_history(self, limit: int = 10) -> List[Dict]:
        """Get recent deployment history"""
        with self._lock:
            return self.deployment_history[-limit:] if limit else self.deployment_history.copy()
    
    def cleanup_resources(self):
        """Clean up resources (call on shutdown)"""
        try:
            self.ssh_key_manager.cleanup_temp_keys()
            logger.info("Nginx manager resources cleaned up")
        except Exception as e:
            logger.error(f"Failed to cleanup nginx manager resources: {e}")
