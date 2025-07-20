#!/usr/bin/env python3
"""
Test runner and verification script for the Nginx WAF AI test suite.

This script provides utilities to run tests in different modes and
verify the testing environment setup.
"""

import os
import sys
import subprocess
import json
import time
import argparse
from pathlib import Path
from typing import List, Dict, Any


class TestRunner:
    """Test runner for the Nginx WAF AI test suite"""
    
    def __init__(self, project_root: str = None):
        self.project_root = Path(project_root) if project_root else Path(__file__).parent.parent
        self.tests_dir = self.project_root / "tests"
        self.src_dir = self.project_root / "src"
        
    def verify_environment(self) -> Dict[str, bool]:
        """Verify test environment setup"""
        checks = {}
        
        # Check Python packages
        try:
            import pytest
            checks["pytest"] = True
        except ImportError:
            checks["pytest"] = False
        
        try:
            import httpx
            checks["httpx"] = True
        except ImportError:
            checks["httpx"] = False
        
        try:
            import requests
            checks["requests"] = True
        except ImportError:
            checks["requests"] = False
        
        # Check if source modules can be imported
        try:
            sys.path.insert(0, str(self.project_root))
            from src.main import app
            checks["src_modules"] = True
        except ImportError as e:
            checks["src_modules"] = False
            print(f"Warning: Could not import source modules: {e}")
        
        # Check if API is running
        try:
            import requests
            response = requests.get("http://localhost:8000/health", timeout=5)
            checks["api_running"] = response.status_code == 200
        except:
            checks["api_running"] = False
        
        # Check if Docker is available
        try:
            result = subprocess.run(["docker", "--version"], capture_output=True, text=True)
            checks["docker"] = result.returncode == 0
        except:
            checks["docker"] = False
        
        # Check if Docker Compose is running
        try:
            result = subprocess.run(["docker-compose", "ps"], capture_output=True, text=True)
            checks["docker_compose"] = result.returncode == 0 and "Up" in result.stdout
        except:
            checks["docker_compose"] = False
        
        return checks
    
    def print_environment_status(self):
        """Print environment verification results"""
        print("🔍 Environment Verification")
        print("=" * 50)
        
        checks = self.verify_environment()
        
        for check_name, status in checks.items():
            status_icon = "✅" if status else "❌"
            status_text = "OK" if status else "MISSING/FAILED"
            print(f"{status_icon} {check_name}: {status_text}")
        
        print("\n📋 Recommendations:")
        
        if not checks.get("pytest"):
            print("  • Install pytest: pip install pytest")
        
        if not checks.get("httpx"):
            print("  • Install httpx: pip install httpx")
        
        if not checks.get("requests"):
            print("  • Install requests: pip install requests")
        
        if not checks.get("src_modules"):
            print("  • Ensure you're running from the project root directory")
            print("  • Check that all source modules are properly structured")
        
        if not checks.get("api_running"):
            print("  • Start the WAF API: python run_server.py")
            print("  • Or use Docker: docker-compose up -d")
        
        if not checks.get("docker"):
            print("  • Install Docker to run integration tests")
        
        if not checks.get("docker_compose"):
            print("  • Start Docker Compose services: docker-compose up -d")
        
        overall_ready = all([
            checks.get("pytest", False),
            checks.get("httpx", False),
            checks.get("requests", False),
            checks.get("src_modules", False)
        ])
        
        print(f"\n🎯 Overall Status: {'READY' if overall_ready else 'NOT READY'}")
        
        return checks
    
    def run_unit_tests(self, verbose: bool = False) -> int:
        """Run unit tests only"""
        print("🧪 Running Unit Tests")
        print("=" * 50)
        
        cmd = [
            "python", "-m", "pytest",
            str(self.tests_dir / "test_auth.py"),
            str(self.tests_dir / "test_ml_engine.py"),
            str(self.tests_dir / "test_traffic_collector.py"),
            str(self.tests_dir / "test_waf_rule_generator.py"),
            str(self.tests_dir / "test_nginx_manager.py"),
            "-v" if verbose else "-q",
            "--tb=short"
        ]
        
        try:
            result = subprocess.run(cmd, cwd=self.project_root)
            return result.returncode
        except Exception as e:
            print(f"Failed to run unit tests: {e}")
            return 1
    
    def run_api_tests(self, verbose: bool = False) -> int:
        """Run API integration tests"""
        print("🌐 Running API Integration Tests")
        print("=" * 50)
        
        # Check if API is running
        checks = self.verify_environment()
        if not checks.get("api_running"):
            print("❌ API is not running. Please start the API first:")
            print("   python run_server.py")
            print("   or")
            print("   docker-compose up -d")
            return 1
        
        cmd = [
            "python", "-m", "pytest",
            str(self.tests_dir / "test_api_integration.py"),
            "-v" if verbose else "-q",
            "--tb=short"
        ]
        
        try:
            result = subprocess.run(cmd, cwd=self.project_root)
            return result.returncode
        except Exception as e:
            print(f"Failed to run API tests: {e}")
            return 1
    
    def run_e2e_tests(self, verbose: bool = False) -> int:
        """Run end-to-end tests"""
        print("🎯 Running End-to-End Tests")
        print("=" * 50)
        
        # Check if Docker services are running
        checks = self.verify_environment()
        if not checks.get("docker_compose"):
            print("❌ Docker Compose services are not running. Please start them first:")
            print("   docker-compose up -d")
            return 1
        
        cmd = [
            "python", "-m", "pytest",
            str(self.tests_dir / "test_e2e_integration.py"),
            "-v" if verbose else "-q",
            "--tb=short",
            "-s"  # Don't capture output for e2e tests
        ]
        
        try:
            result = subprocess.run(cmd, cwd=self.project_root)
            return result.returncode
        except Exception as e:
            print(f"Failed to run e2e tests: {e}")
            return 1
    
    def run_performance_tests(self, verbose: bool = False) -> int:
        """Run performance tests"""
        print("⚡ Running Performance Tests")
        print("=" * 50)
        
        # Check if API is running
        checks = self.verify_environment()
        if not checks.get("api_running"):
            print("❌ API is not running. Performance tests require a running API.")
            return 1
        
        cmd = [
            "python", "-m", "pytest",
            str(self.tests_dir / "test_performance.py"),
            "-v" if verbose else "-q",
            "--tb=short"
        ]
        
        try:
            result = subprocess.run(cmd, cwd=self.project_root)
            return result.returncode
        except Exception as e:
            print(f"Failed to run performance tests: {e}")
            return 1
    
    def run_all_tests(self, verbose: bool = False) -> Dict[str, int]:
        """Run all test suites"""
        print("🚀 Running Complete Test Suite")
        print("=" * 50)
        
        results = {}
        
        # Run tests in order of dependency
        print("\n1️⃣ Unit Tests")
        results["unit"] = self.run_unit_tests(verbose)
        
        print("\n2️⃣ API Integration Tests")
        results["api"] = self.run_api_tests(verbose)
        
        print("\n3️⃣ End-to-End Tests")
        results["e2e"] = self.run_e2e_tests(verbose)
        
        print("\n4️⃣ Performance Tests")
        results["performance"] = self.run_performance_tests(verbose)
        
        # Summary
        print("\n" + "=" * 50)
        print("📊 Test Results Summary")
        print("=" * 50)
        
        total_passed = 0
        total_failed = 0
        
        for test_type, return_code in results.items():
            status = "PASSED" if return_code == 0 else "FAILED"
            status_icon = "✅" if return_code == 0 else "❌"
            print(f"{status_icon} {test_type.upper()}: {status}")
            
            if return_code == 0:
                total_passed += 1
            else:
                total_failed += 1
        
        print(f"\n📈 Overall: {total_passed} passed, {total_failed} failed")
        
        if total_failed == 0:
            print("🎉 All tests passed!")
        else:
            print("⚠️  Some tests failed. Check output above for details.")
        
        return results
    
    def run_quick_smoke_test(self) -> bool:
        """Run a quick smoke test to verify basic functionality"""
        print("💨 Running Quick Smoke Test")
        print("=" * 50)
        
        try:
            import requests
            
            # Test 1: Health endpoint
            print("Testing health endpoint...")
            response = requests.get("http://localhost:8000/health", timeout=10)
            if response.status_code == 200:
                print("✅ Health endpoint OK")
            else:
                print(f"❌ Health endpoint failed: {response.status_code}")
                return False
            
            # Test 2: Root endpoint
            print("Testing root endpoint...")
            response = requests.get("http://localhost:8000/", timeout=10)
            if response.status_code == 200:
                print("✅ Root endpoint OK")
            else:
                print(f"❌ Root endpoint failed: {response.status_code}")
                return False
            
            # Test 3: Authentication endpoint
            print("Testing authentication...")
            response = requests.post(
                "http://localhost:8000/auth/login",
                json={"username": "admin", "password": "admin123"},
                timeout=10
            )
            if response.status_code in [200, 401]:  # Both are acceptable
                print("✅ Authentication endpoint OK")
            else:
                print(f"❌ Authentication endpoint failed: {response.status_code}")
                return False
            
            print("🎉 Smoke test passed!")
            return True
            
        except Exception as e:
            print(f"❌ Smoke test failed: {e}")
            return False
    
    def generate_test_report(self, output_file: str = None):
        """Generate a comprehensive test report"""
        if output_file is None:
            output_file = f"test_report_{int(time.time())}.json"
        
        print(f"📄 Generating test report: {output_file}")
        
        # Run all tests and collect results
        env_checks = self.verify_environment()
        test_results = self.run_all_tests(verbose=True)
        
        report = {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "environment": env_checks,
            "test_results": test_results,
            "summary": {
                "total_suites": len(test_results),
                "passed_suites": sum(1 for r in test_results.values() if r == 0),
                "failed_suites": sum(1 for r in test_results.values() if r != 0),
                "environment_ready": all([
                    env_checks.get("pytest", False),
                    env_checks.get("src_modules", False)
                ])
            }
        }
        
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"✅ Test report saved to: {output_file}")
        
        return report


def main():
    """Main CLI interface"""
    parser = argparse.ArgumentParser(
        description="Test runner for Nginx WAF AI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python test_runner.py --check          # Verify environment
  python test_runner.py --smoke          # Quick smoke test
  python test_runner.py --unit           # Run unit tests only
  python test_runner.py --api            # Run API tests only
  python test_runner.py --e2e            # Run e2e tests only
  python test_runner.py --performance    # Run performance tests only
  python test_runner.py --all            # Run all tests
  python test_runner.py --report         # Generate test report
        """
    )
    
    parser.add_argument("--check", action="store_true", help="Verify test environment")
    parser.add_argument("--smoke", action="store_true", help="Run quick smoke test")
    parser.add_argument("--unit", action="store_true", help="Run unit tests")
    parser.add_argument("--api", action="store_true", help="Run API integration tests")
    parser.add_argument("--e2e", action="store_true", help="Run end-to-end tests")
    parser.add_argument("--performance", action="store_true", help="Run performance tests")
    parser.add_argument("--all", action="store_true", help="Run all tests")
    parser.add_argument("--report", action="store_true", help="Generate comprehensive test report")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    parser.add_argument("--project-root", help="Project root directory")
    
    args = parser.parse_args()
    
    runner = TestRunner(args.project_root)
    
    if args.check:
        runner.print_environment_status()
        return 0
    
    elif args.smoke:
        success = runner.run_quick_smoke_test()
        return 0 if success else 1
    
    elif args.unit:
        return runner.run_unit_tests(args.verbose)
    
    elif args.api:
        return runner.run_api_tests(args.verbose)
    
    elif args.e2e:
        return runner.run_e2e_tests(args.verbose)
    
    elif args.performance:
        return runner.run_performance_tests(args.verbose)
    
    elif args.all:
        results = runner.run_all_tests(args.verbose)
        return 0 if all(r == 0 for r in results.values()) else 1
    
    elif args.report:
        runner.generate_test_report()
        return 0
    
    else:
        # Default: show help and run environment check
        parser.print_help()
        print("\n")
        runner.print_environment_status()
        return 0


if __name__ == "__main__":
    sys.exit(main())
