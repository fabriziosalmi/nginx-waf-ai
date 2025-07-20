#!/usr/bin/env python3
"""
Unit tests for the Nginx Manager component.

This test suite verifies nginx node management, SSH connectivity,
configuration deployment, and health monitoring functionality.
"""

import pytest
import asyncio
from datetime import datetime
from unittest.mock import Mock, patch, AsyncMock, call
from pathlib import Path

from src.nginx_manager import (
    NginxManager, NginxNode, DeploymentResult,
    ConnectionMethod, NodeStatus
)
from src.waf_rule_generator import WAFRule, RuleType, RuleAction


class TestNginxNode:
    """Test NginxNode data structure and methods"""
    
    def setup_method(self):
        """Set up test fixtures"""
        self.test_node_data = {
            "node_id": "test-node-1",
            "hostname": "web-server-1.example.com",
            "ssh_host": "192.168.1.10",
            "ssh_port": 22,
            "ssh_username": "nginx",
            "ssh_key_path": "/home/nginx/.ssh/id_rsa",
            "nginx_config_path": "/etc/nginx/conf.d",
            "nginx_reload_command": "sudo systemctl reload nginx",
            "api_endpoint": "http://192.168.1.10:8080"
        }
    
    def test_nginx_node_creation(self):
        """Test NginxNode creation from data"""
        node = NginxNode(**self.test_node_data)
        
        assert node.node_id == "test-node-1"
        assert node.hostname == "web-server-1.example.com"
        assert node.ssh_host == "192.168.1.10"
        assert node.ssh_port == 22
        assert node.ssh_username == "nginx"
        assert node.ssh_key_path == "/home/nginx/.ssh/id_rsa"
        assert node.nginx_config_path == "/etc/nginx/conf.d"
        assert node.nginx_reload_command == "sudo systemctl reload nginx"
        assert node.api_endpoint == "http://192.168.1.10:8080"
    
    def test_nginx_node_validation(self):
        """Test NginxNode validation"""
        # Test with missing required fields
        invalid_data = self.test_node_data.copy()
        del invalid_data["node_id"]
        
        with pytest.raises(Exception):
            NginxNode(**invalid_data)
        
        # Test with invalid SSH port
        invalid_port_data = self.test_node_data.copy()
        invalid_port_data["ssh_port"] = "invalid"
        
        with pytest.raises(Exception):
            NginxNode(**invalid_port_data)
    
    def test_nginx_node_to_dict(self):
        """Test converting NginxNode to dictionary"""
        node = NginxNode(**self.test_node_data)
        node_dict = node.to_dict()
        
        assert isinstance(node_dict, dict)
        assert node_dict["node_id"] == "test-node-1"
        assert node_dict["hostname"] == "web-server-1.example.com"
        assert all(key in node_dict for key in self.test_node_data.keys())
    
    def test_nginx_node_connection_string(self):
        """Test SSH connection string generation"""
        node = NginxNode(**self.test_node_data)
        
        conn_str = node.get_ssh_connection_string()
        
        assert "nginx@192.168.1.10" in conn_str
        assert "-p 22" in conn_str or ":22" in conn_str
        assert self.test_node_data["ssh_key_path"] in conn_str


class TestNginxManager:
    """Test NginxManager functionality"""
    
    def setup_method(self):
        """Set up test fixtures"""
        self.manager = NginxManager()
        
        self.test_nodes = [
            NginxNode(
                node_id="node-1",
                hostname="web-1.example.com",
                ssh_host="192.168.1.10",
                ssh_port=22,
                ssh_username="nginx",
                ssh_key_path="/home/nginx/.ssh/id_rsa",
                nginx_config_path="/etc/nginx/conf.d",
                nginx_reload_command="sudo systemctl reload nginx",
                api_endpoint="http://192.168.1.10:8080"
            ),
            NginxNode(
                node_id="node-2",
                hostname="web-2.example.com", 
                ssh_host="192.168.1.11",
                ssh_port=22,
                ssh_username="nginx",
                ssh_key_path="/home/nginx/.ssh/id_rsa",
                nginx_config_path="/etc/nginx/conf.d",
                nginx_reload_command="sudo systemctl reload nginx",
                api_endpoint="http://192.168.1.11:8080"
            )
        ]
        
        self.test_rules = [
            WAFRule(
                rule_id="test-rule-1",
                rule_type=RuleType.URL_PATTERN,
                pattern=".*admin.*",
                action=RuleAction.BLOCK,
                priority=90,
                description="Block admin access"
            ),
            WAFRule(
                rule_id="test-rule-2",
                rule_type=RuleType.IP_BLOCK,
                pattern="192.168.1.100",
                action=RuleAction.BLOCK,
                priority=95,
                description="Block malicious IP"
            )
        ]
    
    def test_add_node(self):
        """Test adding nodes to manager"""
        initial_count = len(self.manager.nodes)
        
        self.manager.add_node(self.test_nodes[0])
        
        assert len(self.manager.nodes) == initial_count + 1
        assert self.test_nodes[0] in self.manager.nodes
    
    def test_add_duplicate_node(self):
        """Test adding duplicate node (should update existing)"""
        self.manager.add_node(self.test_nodes[0])
        initial_count = len(self.manager.nodes)
        
        # Add same node again (same node_id)
        updated_node = NginxNode(
            node_id="node-1",  # Same ID
            hostname="updated-web-1.example.com",  # Different hostname
            ssh_host="192.168.1.10",
            ssh_port=22,
            ssh_username="nginx",
            ssh_key_path="/home/nginx/.ssh/id_rsa",
            nginx_config_path="/etc/nginx/conf.d",
            nginx_reload_command="sudo systemctl reload nginx",
            api_endpoint="http://192.168.1.10:8080"
        )
        
        self.manager.add_node(updated_node)
        
        # Should not increase count (update, not add)
        assert len(self.manager.nodes) == initial_count
        
        # Should have updated hostname
        node = self.manager.get_node("node-1")
        assert node.hostname == "updated-web-1.example.com"
    
    def test_remove_node(self):
        """Test removing nodes from manager"""
        self.manager.add_node(self.test_nodes[0])
        initial_count = len(self.manager.nodes)
        
        self.manager.remove_node("node-1")
        
        assert len(self.manager.nodes) == initial_count - 1
        assert self.manager.get_node("node-1") is None
    
    def test_get_node(self):
        """Test getting node by ID"""
        self.manager.add_node(self.test_nodes[0])
        
        node = self.manager.get_node("node-1")
        assert node is not None
        assert node.node_id == "node-1"
        
        # Test non-existent node
        non_existent = self.manager.get_node("non-existent")
        assert non_existent is None
    
    def test_list_nodes(self):
        """Test listing all nodes"""
        for node in self.test_nodes:
            self.manager.add_node(node)
        
        all_nodes = self.manager.list_nodes()
        
        assert len(all_nodes) == len(self.test_nodes)
        for test_node in self.test_nodes:
            assert any(node.node_id == test_node.node_id for node in all_nodes)


class TestSSHConnectivity:
    """Test SSH connectivity and remote operations"""
    
    def setup_method(self):
        """Set up test fixtures"""
        self.manager = NginxManager()
        self.test_node = self.test_nodes[0]
        self.manager.add_node(self.test_node)
    
    @patch('paramiko.SSHClient')
    def test_ssh_connection_success(self, mock_ssh_client):
        """Test successful SSH connection"""
        mock_client = Mock()
        mock_ssh_client.return_value = mock_client
        mock_client.connect.return_value = None
        
        with self.manager._ssh_connect(self.test_node) as ssh:
            assert ssh is not None
            mock_client.connect.assert_called_once()
    
    @patch('paramiko.SSHClient')
    def test_ssh_connection_failure(self, mock_ssh_client):
        """Test SSH connection failure"""
        mock_client = Mock()
        mock_ssh_client.return_value = mock_client
        mock_client.connect.side_effect = Exception("Connection failed")
        
        with pytest.raises(Exception):
            with self.manager._ssh_connect(self.test_node):
                pass
    
    @patch('paramiko.SSHClient')
    def test_ssh_command_execution(self, mock_ssh_client):
        """Test executing commands via SSH"""
        mock_client = Mock()
        mock_stdin = Mock()
        mock_stdout = Mock()
        mock_stderr = Mock()
        
        mock_ssh_client.return_value = mock_client
        mock_client.exec_command.return_value = (mock_stdin, mock_stdout, mock_stderr)
        mock_stdout.read.return_value = b"nginx: configuration file syntax is ok"
        mock_stdout.channel.recv_exit_status.return_value = 0
        mock_stderr.read.return_value = b""
        
        result = self.manager._execute_ssh_command(self.test_node, "nginx -t")
        
        assert result["success"] == True
        assert "syntax is ok" in result["stdout"]
        assert result["exit_code"] == 0
    
    @patch('paramiko.SSHClient')
    def test_ssh_file_upload(self, mock_ssh_client):
        """Test uploading files via SFTP"""
        mock_client = Mock()
        mock_sftp = Mock()
        
        mock_ssh_client.return_value = mock_client
        mock_client.open_sftp.return_value = mock_sftp
        mock_sftp.put.return_value = None
        
        local_path = "/tmp/test_config.conf"
        remote_path = "/etc/nginx/conf.d/waf_rules.conf"
        
        result = self.manager._upload_file_ssh(self.test_node, local_path, remote_path)
        
        assert result == True
        mock_sftp.put.assert_called_once_with(local_path, remote_path)


class TestConfigurationDeployment:
    """Test configuration deployment functionality"""
    
    def setup_method(self):
        """Set up test fixtures"""
        self.manager = NginxManager()
        
        for node in self.test_nodes:
            self.manager.add_node(node)
    
    @patch('src.nginx_manager.NginxManager._execute_ssh_command')
    @patch('src.nginx_manager.NginxManager._upload_file_ssh')
    async def test_deploy_rules_ssh_success(self, mock_upload, mock_execute):
        """Test successful rule deployment via SSH"""
        # Mock successful operations
        mock_upload.return_value = True
        mock_execute.side_effect = [
            {"success": True, "stdout": "syntax is ok", "exit_code": 0},  # nginx -t
            {"success": True, "stdout": "reloaded", "exit_code": 0}       # reload
        ]
        
        results = await self.manager.deploy_rules(self.test_rules, ["node-1"])
        
        assert len(results) == 1
        assert results[0].success == True
        assert results[0].node_id == "node-1"
        assert mock_upload.called
        assert mock_execute.call_count == 2  # test + reload
    
    @patch('src.nginx_manager.NginxManager._execute_ssh_command')
    @patch('src.nginx_manager.NginxManager._upload_file_ssh')
    async def test_deploy_rules_ssh_syntax_error(self, mock_upload, mock_execute):
        """Test rule deployment with nginx syntax error"""
        # Mock syntax error
        mock_upload.return_value = True
        mock_execute.return_value = {
            "success": False,
            "stdout": "",
            "stderr": "nginx: [emerg] invalid syntax",
            "exit_code": 1
        }
        
        results = await self.manager.deploy_rules(self.test_rules, ["node-1"])
        
        assert len(results) == 1
        assert results[0].success == False
        assert "syntax" in results[0].error_message.lower()
    
    @patch('src.nginx_manager.NginxManager._execute_ssh_command')
    @patch('src.nginx_manager.NginxManager._upload_file_ssh')
    async def test_deploy_rules_upload_failure(self, mock_upload, mock_execute):
        """Test rule deployment with file upload failure"""
        # Mock upload failure
        mock_upload.return_value = False
        
        results = await self.manager.deploy_rules(self.test_rules, ["node-1"])
        
        assert len(results) == 1
        assert results[0].success == False
        assert "upload" in results[0].error_message.lower()
    
    @patch('httpx.AsyncClient')
    async def test_deploy_rules_api_success(self, mock_http_client):
        """Test successful rule deployment via API"""
        mock_client = Mock()
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"status": "success"}
        
        mock_client.post = AsyncMock(return_value=mock_response)
        mock_http_client.return_value.__aenter__.return_value = mock_client
        
        # Configure node for API deployment
        api_node = self.test_nodes[0]
        api_node.connection_method = ConnectionMethod.API
        
        results = await self.manager.deploy_rules(self.test_rules, ["node-1"])
        
        assert len(results) == 1
        assert results[0].success == True
        assert results[0].node_id == "node-1"
    
    @patch('httpx.AsyncClient')
    async def test_deploy_rules_api_failure(self, mock_http_client):
        """Test rule deployment API failure"""
        mock_client = Mock()
        mock_response = Mock()
        mock_response.status_code = 500
        mock_response.text = "Internal Server Error"
        
        mock_client.post = AsyncMock(return_value=mock_response)
        mock_http_client.return_value.__aenter__.return_value = mock_client
        
        # Configure node for API deployment
        api_node = self.test_nodes[0]
        api_node.connection_method = ConnectionMethod.API
        
        results = await self.manager.deploy_rules(self.test_rules, ["node-1"])
        
        assert len(results) == 1
        assert results[0].success == False
        assert "500" in results[0].error_message
    
    async def test_deploy_rules_multiple_nodes(self):
        """Test deploying rules to multiple nodes"""
        with patch('src.nginx_manager.NginxManager._execute_ssh_command') as mock_execute:
            with patch('src.nginx_manager.NginxManager._upload_file_ssh') as mock_upload:
                # Mock successful operations
                mock_upload.return_value = True
                mock_execute.side_effect = [
                    {"success": True, "stdout": "syntax is ok", "exit_code": 0},
                    {"success": True, "stdout": "reloaded", "exit_code": 0},
                    {"success": True, "stdout": "syntax is ok", "exit_code": 0},
                    {"success": True, "stdout": "reloaded", "exit_code": 0}
                ]
                
                results = await self.manager.deploy_rules(self.test_rules, ["node-1", "node-2"])
                
                assert len(results) == 2
                assert all(result.success for result in results)
                assert {result.node_id for result in results} == {"node-1", "node-2"}
    
    async def test_deploy_rules_non_existent_node(self):
        """Test deploying rules to non-existent node"""
        results = await self.manager.deploy_rules(self.test_rules, ["non-existent-node"])
        
        assert len(results) == 1
        assert results[0].success == False
        assert "not found" in results[0].error_message.lower()


class TestHealthMonitoring:
    """Test health monitoring functionality"""
    
    def setup_method(self):
        """Set up test fixtures"""
        self.manager = NginxManager()
        
        for node in self.test_nodes:
            self.manager.add_node(node)
    
    @patch('src.nginx_manager.NginxManager._execute_ssh_command')
    async def test_check_node_health_ssh_healthy(self, mock_execute):
        """Test health check for healthy node via SSH"""
        mock_execute.side_effect = [
            {"success": True, "stdout": "active (running)", "exit_code": 0},  # nginx status
            {"success": True, "stdout": "syntax is ok", "exit_code": 0}       # nginx -t
        ]
        
        health = await self.manager.check_node_health("node-1")
        
        assert health.status == NodeStatus.HEALTHY
        assert health.node_id == "node-1"
        assert health.response_time > 0
    
    @patch('src.nginx_manager.NginxManager._execute_ssh_command')
    async def test_check_node_health_ssh_unhealthy(self, mock_execute):
        """Test health check for unhealthy node via SSH"""
        mock_execute.side_effect = [
            {"success": False, "stdout": "inactive (dead)", "exit_code": 3},  # nginx stopped
            {"success": True, "stdout": "syntax is ok", "exit_code": 0}
        ]
        
        health = await self.manager.check_node_health("node-1")
        
        assert health.status == NodeStatus.UNHEALTHY
        assert health.node_id == "node-1"
        assert "inactive" in health.error_message
    
    @patch('httpx.AsyncClient')
    async def test_check_node_health_api_healthy(self, mock_http_client):
        """Test health check for healthy node via API"""
        mock_client = Mock()
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"status": "healthy"}
        
        mock_client.get = AsyncMock(return_value=mock_response)
        mock_http_client.return_value.__aenter__.return_value = mock_client
        
        # Configure node for API health checks
        api_node = self.test_nodes[0]
        api_node.connection_method = ConnectionMethod.API
        
        health = await self.manager.check_node_health("node-1")
        
        assert health.status == NodeStatus.HEALTHY
        assert health.node_id == "node-1"
    
    @patch('httpx.AsyncClient')
    async def test_check_node_health_api_unhealthy(self, mock_http_client):
        """Test health check for unhealthy node via API"""
        mock_client = Mock()
        mock_response = Mock()
        mock_response.status_code = 503
        mock_response.text = "Service Unavailable"
        
        mock_client.get = AsyncMock(return_value=mock_response)
        mock_http_client.return_value.__aenter__.return_value = mock_client
        
        # Configure node for API health checks
        api_node = self.test_nodes[0]
        api_node.connection_method = ConnectionMethod.API
        
        health = await self.manager.check_node_health("node-1")
        
        assert health.status == NodeStatus.UNHEALTHY
        assert health.node_id == "node-1"
        assert "503" in health.error_message
    
    async def test_check_cluster_health(self):
        """Test cluster-wide health check"""
        with patch('src.nginx_manager.NginxManager.check_node_health') as mock_check:
            # Mock health responses
            mock_check.side_effect = [
                Mock(status=NodeStatus.HEALTHY, node_id="node-1"),
                Mock(status=NodeStatus.UNHEALTHY, node_id="node-2")
            ]
            
            cluster_health = await self.manager.check_cluster_health()
            
            assert cluster_health.overall_status in [NodeStatus.DEGRADED, NodeStatus.UNHEALTHY]
            assert len(cluster_health.node_health) == 2
            assert cluster_health.healthy_nodes == 1
            assert cluster_health.unhealthy_nodes == 1
    
    async def test_check_node_health_non_existent(self):
        """Test health check for non-existent node"""
        health = await self.manager.check_node_health("non-existent-node")
        
        assert health.status == NodeStatus.UNKNOWN
        assert health.node_id == "non-existent-node"
        assert "not found" in health.error_message.lower()


class TestConfigurationValidation:
    """Test nginx configuration validation"""
    
    def setup_method(self):
        """Set up test fixtures"""
        self.manager = NginxManager()
        self.test_node = self.test_nodes[0]
        self.manager.add_node(self.test_node)
    
    def test_validate_nginx_config_syntax(self):
        """Test nginx configuration syntax validation"""
        valid_config = """
        location ~ /admin {
            deny all;
            return 403;
        }
        """
        
        is_valid = self.manager.validate_nginx_config(valid_config)
        assert is_valid == True
        
        invalid_config = """
        location ~ /admin {
            deny all
            # Missing semicolon
            return 403;
        """
        
        is_valid = self.manager.validate_nginx_config(invalid_config)
        assert is_valid == False
    
    @patch('src.nginx_manager.NginxManager._execute_ssh_command')
    async def test_validate_config_on_node(self, mock_execute):
        """Test configuration validation on remote node"""
        mock_execute.return_value = {
            "success": True,
            "stdout": "nginx: configuration file syntax is ok",
            "exit_code": 0
        }
        
        is_valid = await self.manager.validate_config_on_node("node-1", "test config")
        
        assert is_valid == True
        mock_execute.assert_called_once()
    
    @patch('src.nginx_manager.NginxManager._execute_ssh_command')
    async def test_validate_config_on_node_invalid(self, mock_execute):
        """Test invalid configuration validation on remote node"""
        mock_execute.return_value = {
            "success": False,
            "stderr": "nginx: [emerg] invalid number of arguments",
            "exit_code": 1
        }
        
        is_valid = await self.manager.validate_config_on_node("node-1", "invalid config")
        
        assert is_valid == False


class TestRollbackFunctionality:
    """Test configuration rollback functionality"""
    
    def setup_method(self):
        """Set up test fixtures"""
        self.manager = NginxManager()
        self.test_node = self.test_nodes[0]
        self.manager.add_node(self.test_node)
    
    @patch('src.nginx_manager.NginxManager._execute_ssh_command')
    @patch('src.nginx_manager.NginxManager._upload_file_ssh')
    async def test_create_backup_before_deployment(self, mock_upload, mock_execute):
        """Test that backup is created before deployment"""
        mock_upload.return_value = True
        mock_execute.side_effect = [
            {"success": True, "stdout": "backup created", "exit_code": 0},    # backup
            {"success": True, "stdout": "syntax is ok", "exit_code": 0},      # test
            {"success": True, "stdout": "reloaded", "exit_code": 0}           # reload
        ]
        
        results = await self.manager.deploy_rules(self.test_rules, ["node-1"], create_backup=True)
        
        assert len(results) == 1
        assert results[0].success == True
        
        # Verify backup was created
        backup_calls = [call for call in mock_execute.call_args_list if "cp" in str(call) or "backup" in str(call)]
        assert len(backup_calls) > 0
    
    @patch('src.nginx_manager.NginxManager._execute_ssh_command')
    async def test_rollback_configuration(self, mock_execute):
        """Test configuration rollback"""
        mock_execute.side_effect = [
            {"success": True, "stdout": "restored", "exit_code": 0},      # restore backup
            {"success": True, "stdout": "reloaded", "exit_code": 0}       # reload
        ]
        
        result = await self.manager.rollback_configuration("node-1")
        
        assert result.success == True
        assert result.node_id == "node-1"
    
    @patch('src.nginx_manager.NginxManager._execute_ssh_command')
    async def test_rollback_configuration_failure(self, mock_execute):
        """Test configuration rollback failure"""
        mock_execute.return_value = {
            "success": False,
            "stderr": "backup file not found",
            "exit_code": 1
        }
        
        result = await self.manager.rollback_configuration("node-1")
        
        assert result.success == False
        assert "backup" in result.error_message.lower()


# Global test data for other test classes
test_nodes = [
    NginxNode(
        node_id="node-1",
        hostname="web-1.example.com",
        ssh_host="192.168.1.10",
        ssh_port=22,
        ssh_username="nginx",
        ssh_key_path="/home/nginx/.ssh/id_rsa",
        nginx_config_path="/etc/nginx/conf.d",
        nginx_reload_command="sudo systemctl reload nginx",
        api_endpoint="http://192.168.1.10:8080"
    ),
    NginxNode(
        node_id="node-2",
        hostname="web-2.example.com",
        ssh_host="192.168.1.11",
        ssh_port=22,
        ssh_username="nginx",
        ssh_key_path="/home/nginx/.ssh/id_rsa",
        nginx_config_path="/etc/nginx/conf.d",
        nginx_reload_command="sudo systemctl reload nginx",
        api_endpoint="http://192.168.1.11:8080"
    )
]

test_rules = [
    WAFRule(
        rule_id="test-rule-1",
        rule_type=RuleType.URL_PATTERN,
        pattern=".*admin.*",
        action=RuleAction.BLOCK,
        priority=90,
        description="Block admin access"
    ),
    WAFRule(
        rule_id="test-rule-2",
        rule_type=RuleType.IP_BLOCK,
        pattern="192.168.1.100",
        action=RuleAction.BLOCK,
        priority=95,
        description="Block malicious IP"
    )
]
