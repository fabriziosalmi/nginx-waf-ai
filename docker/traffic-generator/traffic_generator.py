#!/usr/bin/env python3
"""
Traffic Generator - Simulates realistic web traffic with occasional attack patterns
"""

import os
import time
import random
import requests
from typing import List, Dict
import threading
from datetime import datetime

# Configuration from environment
TARGET_NODES = os.getenv("TARGET_NODES", "http://nginx-node-1,http://nginx-node-2").split(",")
ATTACK_PROBABILITY = float(os.getenv("ATTACK_PROBABILITY", "0.1"))  # 10% attack traffic
REQUEST_RATE = int(os.getenv("REQUEST_RATE", "5"))  # requests per second

# Normal traffic patterns
NORMAL_PATTERNS = [
    {"method": "GET", "path": "/", "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"},
    {"method": "GET", "path": "/api/users", "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)"},
    {"method": "GET", "path": "/api/products", "user_agent": "Mozilla/5.0 (X11; Linux x86_64)"},
    {"method": "POST", "path": "/api/login", "user_agent": "MyApp/1.0", "data": {"username": "user", "password": "pass"}},
    {"method": "GET", "path": "/api/search?q=laptop", "user_agent": "curl/7.68.0"},
    {"method": "GET", "path": "/api/orders", "user_agent": "Mozilla/5.0"},
    {"method": "GET", "path": "/api/cart", "user_agent": "Mobile Safari"},
    {"method": "GET", "path": "/dashboard/", "user_agent": "Mozilla/5.0"},
]

# Attack patterns that should be detected by WAF AI
ATTACK_PATTERNS = [
    # SQL Injection attempts
    {"method": "GET", "path": "/api/users?id=1' OR '1'='1", "user_agent": "sqlmap/1.6.12"},
    {"method": "GET", "path": "/search?q=test' UNION SELECT * FROM users--", "user_agent": "python-requests/2.28.1"},
    {"method": "POST", "path": "/api/login", "user_agent": "Havij", "data": {"username": "admin' OR 1=1--", "password": "test"}},
    {"method": "GET", "path": "/api/products?category=' DROP TABLE products--", "user_agent": "sqlmap/1.6.12"},
    
    # XSS attempts
    {"method": "GET", "path": "/search?q=<script>alert('xss')</script>", "user_agent": "Mozilla/5.0"},
    {"method": "POST", "path": "/api/comment", "user_agent": "BadBot/1.0", "data": {"text": "<img src=x onerror=alert('xss')>"}},
    {"method": "GET", "path": "/api/search?q=<svg/onload=alert('xss')>", "user_agent": "XSSHunter"},
    
    # Directory traversal
    {"method": "GET", "path": "/../../../etc/passwd", "user_agent": "DirBuster"},
    {"method": "GET", "path": "/api/file?path=../../../etc/hosts", "user_agent": "curl/7.68.0"},
    
    # Admin scanning
    {"method": "GET", "path": "/admin/config.php", "user_agent": "Nmap NSE"},
    {"method": "GET", "path": "/admin/backup.sql", "user_agent": "Wget/1.20.3"},
    {"method": "GET", "path": "/.env", "user_agent": "GitRob"},
    {"method": "GET", "path": "/config/database.yml", "user_agent": "Scanner"},
    
    # Command injection
    {"method": "GET", "path": "/api/ping?host=127.0.0.1; cat /etc/passwd", "user_agent": "curl/7.68.0"},
    {"method": "POST", "path": "/api/exec", "user_agent": "python-requests", "data": {"cmd": "ls -la; rm -rf /"}},
]

class TrafficGenerator:
    def __init__(self):
        self.session = requests.Session()
        self.session.timeout = 5
        self.stats = {
            "total_requests": 0,
            "normal_requests": 0,
            "attack_requests": 0,
            "errors": 0
        }
        
    def generate_request(self) -> Dict:
        """Generate a single request (normal or attack)"""
        if random.random() < ATTACK_PROBABILITY:
            pattern = random.choice(ATTACK_PATTERNS)
            self.stats["attack_requests"] += 1
            print(f"🚨 Generating attack: {pattern['method']} {pattern['path']}")
        else:
            pattern = random.choice(NORMAL_PATTERNS)
            self.stats["normal_requests"] += 1
            
        self.stats["total_requests"] += 1
        return pattern
    
    def send_request(self, target_node: str, pattern: Dict):
        """Send a request to a target node"""
        try:
            url = f"{target_node}{pattern['path']}"
            headers = {
                "User-Agent": pattern["user_agent"],
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.5",
                "Accept-Encoding": "gzip, deflate",
                "Connection": "keep-alive",
                "X-Forwarded-For": f"192.168.1.{random.randint(1, 254)}"
            }
            
            if pattern["method"] == "GET":
                response = self.session.get(url, headers=headers)
            elif pattern["method"] == "POST":
                data = pattern.get("data", {})
                response = self.session.post(url, headers=headers, json=data)
            
            print(f"✅ {pattern['method']} {url} -> {response.status_code}")
            
        except Exception as e:
            self.stats["errors"] += 1
            print(f"❌ Error sending request to {target_node}: {e}")
    
    def generate_traffic(self):
        """Main traffic generation loop"""
        print(f"🚀 Starting traffic generator")
        print(f"📊 Config: {REQUEST_RATE} req/s, {ATTACK_PROBABILITY*100}% attacks")
        print(f"🎯 Targets: {TARGET_NODES}")
        
        while True:
            try:
                pattern = self.generate_request()
                target_node = random.choice(TARGET_NODES)
                
                # Send request in background thread to maintain rate
                thread = threading.Thread(target=self.send_request, args=(target_node, pattern))
                thread.daemon = True
                thread.start()
                
                # Print stats every 50 requests
                if self.stats["total_requests"] % 50 == 0:
                    self.print_stats()
                
                # Wait to maintain request rate
                time.sleep(1.0 / REQUEST_RATE)
                
            except KeyboardInterrupt:
                print("\n🛑 Traffic generator stopped")
                break
            except Exception as e:
                print(f"❌ Error in traffic generator: {e}")
                time.sleep(1)
    
    def print_stats(self):
        """Print current statistics"""
        print(f"\n📈 TRAFFIC STATS [{datetime.now().strftime('%H:%M:%S')}]")
        print(f"   Total: {self.stats['total_requests']}")
        print(f"   Normal: {self.stats['normal_requests']}")
        print(f"   Attacks: {self.stats['attack_requests']}")
        print(f"   Errors: {self.stats['errors']}")
        attack_ratio = (self.stats['attack_requests'] / max(self.stats['total_requests'], 1)) * 100
        print(f"   Attack Ratio: {attack_ratio:.1f}%\n")

if __name__ == "__main__":
    generator = TrafficGenerator()
    generator.generate_traffic()
