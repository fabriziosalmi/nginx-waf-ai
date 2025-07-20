#!/usr/bin/env python3
"""
Simple and effective test runner for the WAF AI system.
"""

import sys
import os
import subprocess
import argparse
import time
from pathlib import Path

def run_command(cmd):
    """Run a command and return the result"""
    print(f"Running: {' '.join(cmd)}")
    start_time = time.time()
    result = subprocess.run(cmd, capture_output=True, text=True)
    duration = time.time() - start_time
    
    print(f"Exit code: {result.returncode} (took {duration:.2f}s)")
    
    if result.stdout:
        print("STDOUT:")
        print(result.stdout)
    
    if result.stderr:
        print("STDERR:")
        print(result.stderr)
    
    return result.returncode

def main():
    parser = argparse.ArgumentParser(description='WAF AI Test Runner')
    parser.add_argument('--suite', 
                       choices=['unit', 'integration', 'api', 'e2e', 'performance', 'all'],
                       default='unit',
                       help='Test suite to run')
    parser.add_argument('--coverage', action='store_true', help='Generate coverage report')
    parser.add_argument('--verbose', action='store_true', help='Verbose output')
    
    args = parser.parse_args()
    
    # Ensure we're in the project root
    if not Path('src').exists() or not Path('tests').exists():
        print("❌ Please run from the project root directory")
        print("Expected: src/ and tests/ directories")
        sys.exit(1)
    
    print("🚀 WAF AI Test Runner")
    print("=" * 50)
    
    # Build pytest command
    cmd = ['python', '-m', 'pytest']
    
    if args.verbose:
        cmd.append('-v')
    else:
        cmd.extend(['--tb=short'])
    
    if args.coverage:
        cmd.extend(['--cov=src', '--cov-report=term-missing', '--cov-report=html'])
    
    # Add test markers based on suite
    if args.suite != 'all':
        cmd.extend(['-m', args.suite])
    
    # Add tests directory
    cmd.append('tests/')
    
    print(f"Test suite: {args.suite}")
    print(f"Coverage: {'Yes' if args.coverage else 'No'}")
    print("")
    
    # Run the tests
    exit_code = run_command(cmd)
    
    if args.coverage and exit_code == 0:
        print("\n📈 Coverage report generated in htmlcov/index.html")
    
    if exit_code == 0:
        print("\n✅ All tests passed!")
    else:
        print(f"\n❌ Tests failed with exit code {exit_code}")
    
    sys.exit(exit_code)

if __name__ == '__main__':
    main()
