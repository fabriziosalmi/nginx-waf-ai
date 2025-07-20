#!/usr/bin/env python3
"""
Performance and load testing for the Nginx WAF AI system.

This test suite verifies system performance under various load conditions,
measures response times, and tests resource utilization.
"""

import pytest
import asyncio
import time
import statistics
import concurrent.futures
import threading
from datetime import datetime, timedelta
from typing import List, Dict, Any
import requests
import httpx
import psutil
import json


class TestAPIPerformance:
    """Test API endpoint performance"""
    
    @pytest.fixture(autouse=True)
    def setup_method(self):
        """Set up performance test environment"""
        self.base_url = "http://localhost:8000"
        self.max_response_time = 2.0  # 2 seconds
        self.concurrent_users = 10
        self.test_duration = 30  # seconds
        
        # Verify API is accessible
        try:
            response = requests.get(f"{self.base_url}/health", timeout=5)
            if response.status_code != 200:
                pytest.skip("API not accessible for performance testing")
        except:
            pytest.skip("API not accessible for performance testing")
    
    def test_health_endpoint_response_time(self):
        """Test health endpoint response time"""
        response_times = []
        
        for _ in range(50):
            start_time = time.time()
            response = requests.get(f"{self.base_url}/health", timeout=10)
            end_time = time.time()
            
            assert response.status_code == 200
            response_times.append(end_time - start_time)
        
        avg_response_time = statistics.mean(response_times)
        p95_response_time = statistics.quantiles(response_times, n=20)[18]  # 95th percentile
        
        print(f"Average response time: {avg_response_time:.3f}s")
        print(f"95th percentile response time: {p95_response_time:.3f}s")
        
        assert avg_response_time < self.max_response_time
        assert p95_response_time < self.max_response_time * 2
    
    def test_concurrent_health_requests(self):
        """Test concurrent requests to health endpoint"""
        def make_request():
            start_time = time.time()
            try:
                response = requests.get(f"{self.base_url}/health", timeout=10)
                end_time = time.time()
                return {
                    "success": response.status_code == 200,
                    "response_time": end_time - start_time,
                    "status_code": response.status_code
                }
            except Exception as e:
                return {
                    "success": False,
                    "response_time": float('inf'),
                    "error": str(e)
                }
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.concurrent_users) as executor:
            futures = [executor.submit(make_request) for _ in range(self.concurrent_users * 5)]
            results = [future.result() for future in concurrent.futures.as_completed(futures)]
        
        successful_requests = [r for r in results if r["success"]]
        success_rate = len(successful_requests) / len(results)
        
        if successful_requests:
            avg_response_time = statistics.mean([r["response_time"] for r in successful_requests])
            print(f"Success rate: {success_rate:.2%}")
            print(f"Average response time under load: {avg_response_time:.3f}s")
        
        assert success_rate >= 0.95  # 95% success rate
        if successful_requests:
            assert avg_response_time < self.max_response_time * 2
    
    def test_authenticated_endpoint_performance(self):
        """Test performance of authenticated endpoints"""
        # First authenticate
        try:
            auth_response = requests.post(
                f"{self.base_url}/auth/login",
                json={"username": "admin", "password": "admin123"},
                timeout=10
            )
            
            if auth_response.status_code != 200:
                pytest.skip("Authentication failed for performance test")
            
            token = auth_response.json()["access_token"]
            headers = {"Authorization": f"Bearer {token}"}
        except:
            pytest.skip("Authentication not available for performance test")
        
        # Test authenticated endpoints
        endpoints = [
            "/api/status",
            "/api/stats",
            "/api/nodes",
            "/api/rules",
            "/api/threats"
        ]
        
        for endpoint in endpoints:
            response_times = []
            
            for _ in range(20):
                start_time = time.time()
                response = requests.get(
                    f"{self.base_url}{endpoint}",
                    headers=headers,
                    timeout=10
                )
                end_time = time.time()
                
                if response.status_code == 200:
                    response_times.append(end_time - start_time)
            
            if response_times:
                avg_time = statistics.mean(response_times)
                print(f"{endpoint} average response time: {avg_time:.3f}s")
                assert avg_time < self.max_response_time


class TestLoadTesting:
    """Test system behavior under sustained load"""
    
    @pytest.fixture(autouse=True)
    def setup_method(self):
        """Set up load test environment"""
        self.base_url = "http://localhost:8000"
        self.load_duration = 60  # 1 minute load test
        self.requests_per_second = 5
        
        # Verify API is accessible
        try:
            response = requests.get(f"{self.base_url}/health", timeout=5)
            if response.status_code != 200:
                pytest.skip("API not accessible for load testing")
        except:
            pytest.skip("API not accessible for load testing")
    
    def test_sustained_load(self):
        """Test system under sustained load"""
        start_time = time.time()
        end_time = start_time + self.load_duration
        
        results = []
        errors = []
        
        def make_requests():
            while time.time() < end_time:
                request_start = time.time()
                try:
                    response = requests.get(f"{self.base_url}/health", timeout=5)
                    request_end = time.time()
                    
                    results.append({
                        "timestamp": request_start,
                        "response_time": request_end - request_start,
                        "status_code": response.status_code,
                        "success": response.status_code == 200
                    })
                except Exception as e:
                    errors.append({
                        "timestamp": request_start,
                        "error": str(e)
                    })
                
                # Rate limiting
                time.sleep(1.0 / self.requests_per_second)
        
        # Start multiple threads to generate load
        threads = []
        for _ in range(3):  # 3 threads
            thread = threading.Thread(target=make_requests)
            thread.start()
            threads.append(thread)
        
        # Wait for all threads to complete
        for thread in threads:
            thread.join()
        
        total_requests = len(results) + len(errors)
        successful_requests = len([r for r in results if r["success"]])
        success_rate = successful_requests / total_requests if total_requests > 0 else 0
        
        if results:
            avg_response_time = statistics.mean([r["response_time"] for r in results if r["success"]])
            p95_response_time = statistics.quantiles(
                [r["response_time"] for r in results if r["success"]], n=20
            )[18] if len([r for r in results if r["success"]]) > 20 else avg_response_time
            
            print(f"Total requests: {total_requests}")
            print(f"Successful requests: {successful_requests}")
            print(f"Success rate: {success_rate:.2%}")
            print(f"Average response time: {avg_response_time:.3f}s")
            print(f"95th percentile response time: {p95_response_time:.3f}s")
            print(f"Errors: {len(errors)}")
            
            assert success_rate >= 0.90  # 90% success rate under load
            assert avg_response_time < 3.0  # Average response time under 3s
        else:
            pytest.fail("No successful requests during load test")
    
    def test_memory_usage_under_load(self):
        """Test memory usage stability under load"""
        import psutil
        import os
        
        # Get current process (if running in same process) or try to find the API process
        initial_memory = psutil.virtual_memory().used
        
        def generate_load():
            for _ in range(100):
                try:
                    requests.get(f"{self.base_url}/health", timeout=5)
                except:
                    pass
                time.sleep(0.1)
        
        # Generate load
        threads = []
        for _ in range(3):
            thread = threading.Thread(target=generate_load)
            thread.start()
            threads.append(thread)
        
        # Monitor memory during load
        memory_samples = []
        start_time = time.time()
        
        while any(thread.is_alive() for thread in threads):
            memory_samples.append(psutil.virtual_memory().used)
            time.sleep(1)
        
        # Wait for threads to complete
        for thread in threads:
            thread.join()
        
        final_memory = psutil.virtual_memory().used
        memory_increase = final_memory - initial_memory
        
        print(f"Initial memory usage: {initial_memory / 1024 / 1024:.1f} MB")
        print(f"Final memory usage: {final_memory / 1024 / 1024:.1f} MB")
        print(f"Memory increase: {memory_increase / 1024 / 1024:.1f} MB")
        
        # Memory increase should be reasonable (less than 100MB for this test)
        assert memory_increase < 100 * 1024 * 1024  # 100MB


class TestScalabilityMetrics:
    """Test system scalability metrics"""
    
    @pytest.fixture(autouse=True)
    def setup_method(self):
        """Set up scalability test environment"""
        self.base_url = "http://localhost:8000"
        
        # Verify API is accessible
        try:
            response = requests.get(f"{self.base_url}/health", timeout=5)
            if response.status_code != 200:
                pytest.skip("API not accessible for scalability testing")
        except:
            pytest.skip("API not accessible for scalability testing")
    
    def test_response_time_vs_concurrent_users(self):
        """Test how response time scales with concurrent users"""
        user_counts = [1, 2, 5, 10, 15, 20]
        results = {}
        
        for user_count in user_counts:
            print(f"Testing with {user_count} concurrent users...")
            
            def make_request():
                start_time = time.time()
                try:
                    response = requests.get(f"{self.base_url}/health", timeout=10)
                    end_time = time.time()
                    return {
                        "success": response.status_code == 200,
                        "response_time": end_time - start_time
                    }
                except:
                    return {"success": False, "response_time": float('inf')}
            
            with concurrent.futures.ThreadPoolExecutor(max_workers=user_count) as executor:
                # Each user makes 5 requests
                futures = [executor.submit(make_request) for _ in range(user_count * 5)]
                user_results = [future.result() for future in concurrent.futures.as_completed(futures)]
            
            successful_results = [r for r in user_results if r["success"]]
            if successful_results:
                avg_response_time = statistics.mean([r["response_time"] for r in successful_results])
                success_rate = len(successful_results) / len(user_results)
                
                results[user_count] = {
                    "avg_response_time": avg_response_time,
                    "success_rate": success_rate
                }
                
                print(f"  Average response time: {avg_response_time:.3f}s")
                print(f"  Success rate: {success_rate:.2%}")
        
        # Analyze scalability
        if len(results) >= 2:
            response_times = [results[users]["avg_response_time"] for users in sorted(results.keys())]
            
            # Response time should not increase drastically
            max_response_time = max(response_times)
            min_response_time = min(response_times)
            
            print(f"Response time range: {min_response_time:.3f}s - {max_response_time:.3f}s")
            
            # Response time should not increase by more than 5x
            assert max_response_time <= min_response_time * 5
    
    def test_throughput_measurement(self):
        """Measure system throughput"""
        test_duration = 30  # seconds
        concurrent_users = 5
        
        start_time = time.time()
        end_time = start_time + test_duration
        
        completed_requests = []
        lock = threading.Lock()
        
        def worker():
            while time.time() < end_time:
                request_start = time.time()
                try:
                    response = requests.get(f"{self.base_url}/health", timeout=5)
                    request_end = time.time()
                    
                    with lock:
                        completed_requests.append({
                            "start_time": request_start,
                            "end_time": request_end,
                            "success": response.status_code == 200
                        })
                except:
                    pass
                
                time.sleep(0.1)  # Small delay between requests
        
        # Start worker threads
        threads = []
        for _ in range(concurrent_users):
            thread = threading.Thread(target=worker)
            thread.start()
            threads.append(thread)
        
        # Wait for completion
        for thread in threads:
            thread.join()
        
        successful_requests = [r for r in completed_requests if r["success"]]
        total_test_time = time.time() - start_time
        
        throughput = len(successful_requests) / total_test_time
        
        print(f"Total successful requests: {len(successful_requests)}")
        print(f"Test duration: {total_test_time:.1f}s")
        print(f"Throughput: {throughput:.2f} requests/second")
        
        # System should handle at least 5 requests per second
        assert throughput >= 5.0


class TestResourceUtilization:
    """Test resource utilization patterns"""
    
    @pytest.fixture(autouse=True)
    def setup_method(self):
        """Set up resource monitoring"""
        self.base_url = "http://localhost:8000"
        
        # Verify API is accessible
        try:
            response = requests.get(f"{self.base_url}/health", timeout=5)
            if response.status_code != 200:
                pytest.skip("API not accessible for resource testing")
        except:
            pytest.skip("API not accessible for resource testing")
    
    def test_cpu_usage_under_load(self):
        """Monitor CPU usage under load"""
        cpu_samples = []
        
        def monitor_cpu():
            for _ in range(30):  # Monitor for 30 seconds
                cpu_samples.append(psutil.cpu_percent(interval=1))
        
        def generate_load():
            for _ in range(200):
                try:
                    requests.get(f"{self.base_url}/health", timeout=5)
                except:
                    pass
                time.sleep(0.05)
        
        # Start monitoring and load generation
        monitor_thread = threading.Thread(target=monitor_cpu)
        load_thread = threading.Thread(target=generate_load)
        
        monitor_thread.start()
        time.sleep(2)  # Get baseline
        load_thread.start()
        
        load_thread.join()
        monitor_thread.join()
        
        if cpu_samples:
            baseline_cpu = statistics.mean(cpu_samples[:2])  # First 2 samples
            peak_cpu = max(cpu_samples)
            avg_cpu = statistics.mean(cpu_samples)
            
            print(f"Baseline CPU usage: {baseline_cpu:.1f}%")
            print(f"Peak CPU usage: {peak_cpu:.1f}%")
            print(f"Average CPU usage: {avg_cpu:.1f}%")
            
            # CPU usage should be reasonable
            assert peak_cpu < 90.0  # Should not max out CPU
    
    def test_response_time_distribution(self):
        """Analyze response time distribution"""
        response_times = []
        
        for _ in range(100):
            start_time = time.time()
            try:
                response = requests.get(f"{self.base_url}/health", timeout=10)
                end_time = time.time()
                
                if response.status_code == 200:
                    response_times.append(end_time - start_time)
            except:
                pass
        
        if len(response_times) >= 10:
            response_times.sort()
            
            p50 = statistics.median(response_times)
            p90 = statistics.quantiles(response_times, n=10)[8]
            p95 = statistics.quantiles(response_times, n=20)[18]
            p99 = statistics.quantiles(response_times, n=100)[98]
            
            print(f"Response time percentiles:")
            print(f"  50th percentile: {p50:.3f}s")
            print(f"  90th percentile: {p90:.3f}s")
            print(f"  95th percentile: {p95:.3f}s")
            print(f"  99th percentile: {p99:.3f}s")
            
            # Performance expectations
            assert p50 < 0.5   # Median under 500ms
            assert p90 < 1.0   # 90% under 1s
            assert p95 < 2.0   # 95% under 2s
            assert p99 < 5.0   # 99% under 5s


class TestStressConditions:
    """Test system behavior under stress conditions"""
    
    @pytest.fixture(autouse=True)
    def setup_method(self):
        """Set up stress test environment"""
        self.base_url = "http://localhost:8000"
        
        # Verify API is accessible
        try:
            response = requests.get(f"{self.base_url}/health", timeout=5)
            if response.status_code != 200:
                pytest.skip("API not accessible for stress testing")
        except:
            pytest.skip("API not accessible for stress testing")
    
    def test_rapid_request_burst(self):
        """Test handling of rapid request bursts"""
        burst_size = 50
        burst_duration = 5  # seconds
        
        def make_burst_requests():
            results = []
            start_time = time.time()
            
            for _ in range(burst_size):
                request_start = time.time()
                try:
                    response = requests.get(f"{self.base_url}/health", timeout=5)
                    request_end = time.time()
                    
                    results.append({
                        "response_time": request_end - request_start,
                        "success": response.status_code == 200,
                        "status_code": response.status_code
                    })
                except Exception as e:
                    results.append({
                        "response_time": float('inf'),
                        "success": False,
                        "error": str(e)
                    })
            
            return results
        
        # Execute burst
        burst_results = make_burst_requests()
        
        successful_requests = [r for r in burst_results if r["success"]]
        success_rate = len(successful_requests) / len(burst_results)
        
        if successful_requests:
            avg_response_time = statistics.mean([r["response_time"] for r in successful_requests])
            max_response_time = max([r["response_time"] for r in successful_requests])
            
            print(f"Burst test results:")
            print(f"  Total requests: {len(burst_results)}")
            print(f"  Successful requests: {len(successful_requests)}")
            print(f"  Success rate: {success_rate:.2%}")
            print(f"  Average response time: {avg_response_time:.3f}s")
            print(f"  Max response time: {max_response_time:.3f}s")
            
            # Should handle at least 70% of burst requests successfully
            assert success_rate >= 0.70
            
            # Response times should remain reasonable
            assert avg_response_time < 3.0
    
    def test_long_running_requests(self):
        """Test handling of long-running requests"""
        # Test with requests that might take longer
        endpoints = [
            "/api/stats",  # Might involve computation
            "/health",     # Should be fast baseline
        ]
        
        for endpoint in endpoints:
            start_time = time.time()
            try:
                response = requests.get(
                    f"{self.base_url}{endpoint}",
                    timeout=30  # Allow longer timeout
                )
                end_time = time.time()
                
                response_time = end_time - start_time
                print(f"{endpoint} response time: {response_time:.3f}s")
                
                # Even complex endpoints should respond within 30 seconds
                assert response_time < 30.0
                
                # If successful, should be much faster
                if response.status_code == 200:
                    assert response_time < 10.0
                    
            except Exception as e:
                print(f"Long-running request failed for {endpoint}: {e}")
                # Don't fail the test for protected endpoints that require auth
                if "401" not in str(e):
                    pytest.fail(f"Request to {endpoint} failed: {e}")
    
    def test_recovery_after_stress(self):
        """Test system recovery after stress period"""
        # Apply stress
        print("Applying stress...")
        
        def stress_worker():
            for _ in range(100):
                try:
                    requests.get(f"{self.base_url}/health", timeout=1)
                except:
                    pass
        
        # Start multiple stress workers
        stress_threads = []
        for _ in range(5):
            thread = threading.Thread(target=stress_worker)
            thread.start()
            stress_threads.append(thread)
        
        # Wait for stress to complete
        for thread in stress_threads:
            thread.join()
        
        # Wait for recovery
        print("Waiting for recovery...")
        time.sleep(10)
        
        # Test recovery
        print("Testing recovery...")
        recovery_times = []
        for _ in range(10):
            start_time = time.time()
            try:
                response = requests.get(f"{self.base_url}/health", timeout=10)
                end_time = time.time()
                
                if response.status_code == 200:
                    recovery_times.append(end_time - start_time)
            except:
                pass
        
        if recovery_times:
            avg_recovery_time = statistics.mean(recovery_times)
            print(f"Average response time after recovery: {avg_recovery_time:.3f}s")
            
            # Should recover to normal performance
            assert avg_recovery_time < 2.0
            assert len(recovery_times) >= 8  # At least 80% success rate


if __name__ == "__main__":
    # When run directly, perform basic performance checks
    print("Running basic performance checks...")
    
    base_url = "http://localhost:8000"
    
    try:
        # Test basic response time
        start_time = time.time()
        response = requests.get(f"{base_url}/health", timeout=10)
        end_time = time.time()
        
        if response.status_code == 200:
            response_time = end_time - start_time
            print(f"✓ Health endpoint response time: {response_time:.3f}s")
            
            if response_time < 1.0:
                print("✓ Response time is excellent")
            elif response_time < 2.0:
                print("✓ Response time is good")
            else:
                print("⚠ Response time is slow")
        else:
            print(f"✗ Health endpoint returned status code: {response.status_code}")
    
    except Exception as e:
        print(f"✗ Failed to test performance: {e}")
    
    print("Basic performance check completed.")
