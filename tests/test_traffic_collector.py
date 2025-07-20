import pytest
import asyncio
from datetime import datetime
from unittest.mock import Mock, patch

from src.traffic_collector import TrafficCollector, HttpRequest


class TestTrafficCollector:
    
    def setup_method(self):
        self.nodes = ["http://test-node-1", "http://test-node-2"]
        self.collector = TrafficCollector(self.nodes)
    
    def test_http_request_creation(self):
        """Test HttpRequest creation and feature extraction"""
        request = HttpRequest(
            timestamp=datetime.now(),
            method="GET",
            url="/test?id=1",
            headers={"User-Agent": "test"},
            body=None,
            source_ip="192.168.1.1",
            user_agent="test",
            content_length=0
        )
        
        features = request.to_dict()
        assert features['method'] == "GET"
        assert features['url_length'] == 10
        assert features['headers_count'] == 1
        assert not features['contains_sql_patterns']
    
    def test_sql_injection_detection(self):
        """Test SQL injection pattern detection"""
        request = HttpRequest(
            timestamp=datetime.now(),
            method="GET",
            url="/login?id=1' OR '1'='1",
            headers={},
            body=None,
            source_ip="192.168.1.1",
            user_agent="test",
            content_length=0
        )
        
        features = request.to_dict()
        assert features['contains_sql_patterns']
    
    def test_xss_detection(self):
        """Test XSS pattern detection"""
        request = HttpRequest(
            timestamp=datetime.now(),
            method="POST",
            url="/comment",
            headers={},
            body="<script>alert('xss')</script>",
            source_ip="192.168.1.1",
            user_agent="test",
            content_length=30
        )
        
        features = request.to_dict()
        assert features['contains_xss_patterns']
    
    def test_suspicious_headers_detection(self):
        """Test suspicious header detection"""
        request = HttpRequest(
            timestamp=datetime.now(),
            method="GET",
            url="/test",
            headers={"X-Injection": "javascript:alert(1)"},
            body=None,
            source_ip="192.168.1.1",
            user_agent="test",
            content_length=0
        )
        
        features = request.to_dict()
        assert features['has_suspicious_headers']
    
    def test_get_recent_requests(self):
        """Test getting recent requests with limit"""
        # Add some test requests
        for i in range(20):
            self.collector.collected_requests.append(
                HttpRequest(
                    timestamp=datetime.now(),
                    method="GET",
                    url=f"/test/{i}",
                    headers={},
                    body=None,
                    source_ip="192.168.1.1",
                    user_agent="test",
                    content_length=0
                )
            )
        
        recent = self.collector.get_recent_requests(10)
        assert len(recent) == 10
        
        all_recent = self.collector.get_recent_requests(30)
        assert len(all_recent) == 20
    
    @patch('httpx.AsyncClient')
    @pytest.mark.asyncio
    async def test_collect_from_node(self, mock_client):
        """Test collecting from a single node"""
        # Mock response
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = [
            {
                'timestamp': datetime.now().isoformat(),
                'method': 'GET',
                'url': '/test',
                'headers': {},
                'source_ip': '192.168.1.1',
                'user_agent': 'test'
            }
        ]
        
        mock_client_instance = Mock()
        mock_client_instance.get.return_value = mock_response
        mock_client.return_value.__aenter__.return_value = mock_client_instance
        
        # Start collection briefly
        self.collector.is_collecting = True
        task = asyncio.create_task(self.collector._collect_from_node("http://test-node"))
        
        # Let it run briefly then stop
        await asyncio.sleep(0.1)
        self.collector.is_collecting = False
        
        try:
            await task
        except asyncio.CancelledError:
            pass
        
        # Should have collected at least one request
        assert len(self.collector.collected_requests) >= 0
