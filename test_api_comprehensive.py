#!/usr/bin/env python3
"""
Comprehensive API Testing Script for Nginx WAF AI

This script systematically tests all endpoints according to the API.md documentation.
It validates functionality, authentication, error handling, and response formats.
"""

import asyncio
import json
import sys
import time
from datetime import datetime
from typing import Dict, List, Any, Optional
import httpx
import argparse


class APITester:
    def __init__(self, base_url: str = "http://localhost:8000", timeout: int = 30):
        self.base_url = base_url.rstrip('/')
        self.timeout = timeout
        self.access_token: Optional[str] = None
        self.api_key: Optional[str] = None
        self.test_results: List[Dict[str, Any]] = []
        
        # Test credentials (these should be configurable or created during testing)
        self.admin_credentials = {"username": "admin", "password": "admin123"}
        self.operator_credentials = {"username": "operator", "password": "operator123"}
        self.viewer_credentials = {"username": "viewer", "password": "viewer123"}
        
    async def log_result(self, test_name: str, endpoint: str, method: str, 
                        status: str, details: str = "", response_data: Any = None):
        """Log test result"""
        result = {
            "timestamp": datetime.now().isoformat(),
            "test_name": test_name,
            "endpoint": endpoint,
            "method": method,
            "status": status,  # PASS, FAIL, SKIP, ERROR
            "details": details,
            "response_data": response_data
        }
        self.test_results.append(result)
        
        status_emoji = {
            "PASS": "✅",
            "FAIL": "❌", 
            "SKIP": "⏭️",
            "ERROR": "💥"
        }
        
        print(f"{status_emoji.get(status, '❓')} {test_name}: {status}")
        if details:
            print(f"   {details}")
        if status in ["FAIL", "ERROR"] and response_data:
            print(f"   Response: {response_data}")
    
    async def make_request(self, method: str, endpoint: str, 
                          headers: Optional[Dict] = None, 
                          json_data: Optional[Dict] = None,
                          params: Optional[Dict] = None) -> httpx.Response:
        """Make HTTP request with proper error handling"""
        url = f"{self.base_url}{endpoint}"
        request_headers = headers or {}
        
        if self.access_token:
            request_headers["Authorization"] = f"Bearer {self.access_token}"
        
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            if method.upper() == "GET":
                return await client.get(url, headers=request_headers, params=params)
            elif method.upper() == "POST":
                return await client.post(url, headers=request_headers, json=json_data)
            elif method.upper() == "PUT":
                return await client.put(url, headers=request_headers, json=json_data)
            elif method.upper() == "DELETE":
                return await client.delete(url, headers=request_headers)
            else:
                raise ValueError(f"Unsupported HTTP method: {method}")
    
    async def authenticate(self, credentials: Dict[str, str]) -> bool:
        """Authenticate and store access token"""
        try:
            response = await self.make_request("POST", "/auth/login", json_data=credentials)
            if response.status_code == 200:
                data = response.json()
                self.access_token = data.get("access_token")
                await self.log_result(
                    f"Authentication ({credentials['username']})", 
                    "/auth/login", "POST", "PASS",
                    f"Token obtained: {self.access_token[:20]}..." if self.access_token else "No token"
                )
                return True
            else:
                await self.log_result(
                    f"Authentication ({credentials['username']})", 
                    "/auth/login", "POST", "FAIL",
                    f"Status: {response.status_code}", response.text
                )
                return False
        except Exception as e:
            await self.log_result(
                f"Authentication ({credentials['username']})", 
                "/auth/login", "POST", "ERROR", str(e)
            )
            return False
    
    async def test_public_endpoints(self):
        """Test public endpoints that don't require authentication"""
        print("\\n🌐 Testing Public Endpoints")
        
        # Test root endpoint
        try:
            response = await self.make_request("GET", "/")
            if response.status_code == 200:
                data = response.json()
                await self.log_result(
                    "Root Endpoint", "/", "GET", "PASS",
                    f"Version: {data.get('version', 'unknown')}"
                )
            else:
                await self.log_result(
                    "Root Endpoint", "/", "GET", "FAIL",
                    f"Status: {response.status_code}", response.text
                )
        except Exception as e:
            await self.log_result("Root Endpoint", "/", "GET", "ERROR", str(e))
        
        # Test health endpoint
        try:
            response = await self.make_request("GET", "/health")
            if response.status_code == 200:
                data = response.json()
                await self.log_result(
                    "Health Check", "/health", "GET", "PASS",
                    f"Status: {data.get('status', 'unknown')}"
                )
            else:
                await self.log_result(
                    "Health Check", "/health", "GET", "FAIL",
                    f"Status: {response.status_code}", response.text
                )
        except Exception as e:
            await self.log_result("Health Check", "/health", "GET", "ERROR", str(e))
    
    async def test_authentication_endpoints(self):
        """Test authentication-related endpoints"""
        print("\\n🔐 Testing Authentication Endpoints")
        
        # Test login with invalid credentials
        try:
            invalid_creds = {"username": "invalid", "password": "wrong"}
            response = await self.make_request("POST", "/auth/login", json_data=invalid_creds)
            if response.status_code == 401:
                await self.log_result(
                    "Invalid Login", "/auth/login", "POST", "PASS",
                    "Correctly rejected invalid credentials"
                )
            else:
                await self.log_result(
                    "Invalid Login", "/auth/login", "POST", "FAIL",
                    f"Expected 401, got {response.status_code}", response.text
                )
        except Exception as e:
            await self.log_result("Invalid Login", "/auth/login", "POST", "ERROR", str(e))
        
        # Test login with valid admin credentials
        auth_success = await self.authenticate(self.admin_credentials)
        if not auth_success:
            await self.log_result(
                "Authentication Setup", "", "", "FAIL",
                "Could not authenticate as admin - remaining tests may fail"
            )
            return False
        
        return True
    
    async def test_system_endpoints(self):
        """Test system status and monitoring endpoints"""
        print("\\n🖥️  Testing System Endpoints")
        
        # Test system status
        try:
            response = await self.make_request("GET", "/api/status")
            if response.status_code == 200:
                data = response.json()
                await self.log_result(
                    "System Status", "/api/status", "GET", "PASS",
                    f"Processing: {data.get('is_processing', False)}"
                )
            else:
                await self.log_result(
                    "System Status", "/api/status", "GET", "FAIL",
                    f"Status: {response.status_code}", response.text
                )
        except Exception as e:
            await self.log_result("System Status", "/api/status", "GET", "ERROR", str(e))
        
        # Test comprehensive health endpoint
        try:
            response = await self.make_request("GET", "/api/health")
            if response.status_code == 200:
                data = response.json()
                health_score = data.get('health_score', 0)
                system_status = data.get('system_status', 'unknown')
                await self.log_result(
                    "System Health", "/api/health", "GET", "PASS",
                    f"Status: {system_status}, Score: {health_score}%"
                )
            else:
                await self.log_result(
                    "System Health", "/api/health", "GET", "FAIL",
                    f"Status: {response.status_code}", response.text
                )
        except Exception as e:
            await self.log_result("System Health", "/api/health", "GET", "ERROR", str(e))
        
        # Test system statistics
        try:
            response = await self.make_request("GET", "/api/stats")
            if response.status_code == 200:
                data = response.json()
                await self.log_result(
                    "System Statistics", "/api/stats", "GET", "PASS",
                    f"Components: {len(data.get('components', {}))}"
                )
            else:
                await self.log_result(
                    "System Statistics", "/api/stats", "GET", "FAIL",
                    f"Status: {response.status_code}", response.text
                )
        except Exception as e:
            await self.log_result("System Statistics", "/api/stats", "GET", "ERROR", str(e))
    
    async def run_all_tests(self):
        """Run all API tests"""
        print("🚀 Starting Nginx WAF AI API Tests")
        print(f"🎯 Target: {self.base_url}")
        print(f"⏱️  Timeout: {self.timeout}s")
        print("=" * 60)
        
        start_time = time.time()
        
        # Test public endpoints first
        await self.test_public_endpoints()
        
        # Test authentication and get admin token
        auth_success = await self.test_authentication_endpoints()
        if not auth_success:
            print("\\n❌ Authentication failed - skipping protected endpoint tests")
            return
        
        # Test protected endpoints
        await self.test_system_endpoints()
        
        end_time = time.time()
        duration = end_time - start_time
        
        # Generate summary
        self.generate_summary(duration)
    
    def generate_summary(self, duration: float):
        """Generate test summary report"""
        print("\\n" + "=" * 60)
        print("📋 TEST SUMMARY REPORT")
        print("=" * 60)
        
        total_tests = len(self.test_results)
        passed = len([r for r in self.test_results if r['status'] == 'PASS'])
        failed = len([r for r in self.test_results if r['status'] == 'FAIL'])
        errors = len([r for r in self.test_results if r['status'] == 'ERROR'])
        skipped = len([r for r in self.test_results if r['status'] == 'SKIP'])
        
        print(f"📊 Results: {total_tests} total tests")
        print(f"✅ Passed: {passed}")
        print(f"❌ Failed: {failed}")
        print(f"💥 Errors: {errors}")
        print(f"⏭️  Skipped: {skipped}")
        print(f"⏱️  Duration: {duration:.2f}s")
        
        success_rate = (passed / total_tests * 100) if total_tests > 0 else 0
        print(f"📈 Success Rate: {success_rate:.1f}%")
        
        if failed > 0 or errors > 0:
            print("\\n❌ FAILED/ERROR TESTS:")
            for result in self.test_results:
                if result['status'] in ['FAIL', 'ERROR']:
                    print(f"   {result['test_name']}: {result['status']} - {result['details']}")
        
        # Save detailed results to file
        report_file = f"api_test_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(report_file, 'w') as f:
            json.dump({
                'summary': {
                    'total_tests': total_tests,
                    'passed': passed,
                    'failed': failed,
                    'errors': errors,
                    'skipped': skipped,
                    'success_rate': success_rate,
                    'duration': duration,
                    'timestamp': datetime.now().isoformat()
                },
                'test_results': self.test_results
            }, f, indent=2)
        
        print(f"\\n💾 Detailed results saved to: {report_file}")


async def main():
    parser = argparse.ArgumentParser(description='Test Nginx WAF AI API endpoints')
    parser.add_argument('--url', default='http://localhost:8000', 
                       help='Base URL of the API (default: http://localhost:8000)')
    parser.add_argument('--timeout', type=int, default=30,
                       help='Request timeout in seconds (default: 30)')
    parser.add_argument('--admin-user', default='admin',
                       help='Admin username (default: admin)')
    parser.add_argument('--admin-pass', default='admin123',
                       help='Admin password (default: admin123)')
    
    args = parser.parse_args()
    
    tester = APITester(base_url=args.url, timeout=args.timeout)
    tester.admin_credentials = {"username": args.admin_user, "password": args.admin_pass}
    
    try:
        await tester.run_all_tests()
    except KeyboardInterrupt:
        print("\\n⚠️  Tests interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\\n💥 Fatal error during testing: {e}")
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
