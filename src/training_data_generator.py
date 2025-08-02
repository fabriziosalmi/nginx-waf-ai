"""
Training Data Generator Module

Generates training data from real traffic patterns and known threat signatures.
"""

import json
import os
from typing import List, Dict, Tuple
from datetime import datetime, timedelta
from loguru import logger


class TrainingDataGenerator:
    """Generates training data from real traffic and threat signatures"""
    
    def __init__(self, data_dir: str = "data"):
        self.data_dir = data_dir
        self.threat_patterns = self._load_threat_patterns()
        
    def _load_threat_patterns(self) -> Dict[str, List[str]]:
        """Load known threat patterns for training data generation"""
        return {
            "sql_injection": [
                "' OR 1=1--",
                "' UNION SELECT",
                "' DROP TABLE",
                "'; DELETE FROM",
                "1' AND 1=1--",
                "admin' OR 'a'='a",
                "' OR 'x'='x",
                "1' OR '1'='1'--",
                "'; EXEC master..xp_cmdshell",
                "' HAVING 1=1--"
            ],
            "xss_attack": [
                "<script>alert('xss')</script>",
                "<img src=x onerror=alert('xss')>",
                "<svg/onload=alert('xss')>",
                "javascript:alert('xss')",
                "<iframe src=javascript:alert('xss')>",
                "<body onload=alert('xss')>",
                "<input onfocus=alert('xss') autofocus>",
                "<select onfocus=alert('xss') autofocus>",
                "<textarea onfocus=alert('xss') autofocus>",
                "<keygen onfocus=alert('xss') autofocus>"
            ],
            "directory_traversal": [
                "../../../etc/passwd",
                "..\\..\\..\\windows\\system32\\config\\sam",
                "../../../../etc/shadow",
                "../../../var/log/auth.log",
                "..\\..\\..\\boot.ini",
                "../../../../proc/version",
                "../../../etc/hosts",
                "..\\..\\..\\windows\\win.ini"
            ]
        }
    
    def generate_training_data(self, 
                              num_samples: int = 1000,
                              threat_ratio: float = 0.3) -> Tuple[List[Dict], List[str]]:
        """
        Generate training data with normal and malicious requests
        
        Args:
            num_samples: Total number of samples to generate
            threat_ratio: Ratio of malicious samples (0.3 = 30% malicious)
        
        Returns:
            Tuple of (training_data, labels)
        """
        training_data = []
        labels = []
        
        # Calculate split
        threat_samples = int(num_samples * threat_ratio)
        normal_samples = num_samples - threat_samples
        
        # Generate normal traffic
        logger.info(f"Generating {normal_samples} normal traffic samples")
        for i in range(normal_samples):
            sample = self._generate_normal_request()
            training_data.append(sample)
            labels.append("normal")
        
        # Generate threat traffic evenly distributed across threat types
        threat_types = list(self.threat_patterns.keys())
        samples_per_type = threat_samples // len(threat_types)
        
        for threat_type in threat_types:
            logger.info(f"Generating {samples_per_type} {threat_type} samples")
            for i in range(samples_per_type):
                sample = self._generate_threat_request(threat_type)
                training_data.append(sample)
                labels.append(threat_type)
        
        logger.info(f"Generated {len(training_data)} training samples with {len([l for l in labels if l != 'normal'])} threats")
        return training_data, labels
    
    def _generate_normal_request(self) -> Dict:
        """Generate a normal, benign HTTP request"""
        import random
        
        normal_urls = [
            "/",
            "/api/users",
            "/api/products",
            "/api/orders",
            "/api/search?q=laptop",
            "/api/search?q=shoes",
            "/dashboard/",
            "/api/status",
            "/api/health",
            "/login",
            "/register",
            "/api/cart",
            "/api/categories",
            "/api/profile",
            "/api/settings"
        ]
        
        user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X)",
            "curl/7.68.0",
            "PostmanRuntime/7.26.8"
        ]
        
        methods = ["GET", "POST", "PUT", "DELETE"]
        
        return {
            "timestamp": (datetime.now() - timedelta(minutes=random.randint(0, 1440))).isoformat(),
            "method": random.choice(methods),
            "url": random.choice(normal_urls),
            "headers_count": random.randint(4, 8),
            "body_length": random.randint(0, 200) if random.choice(methods) in ["POST", "PUT"] else 0,
            "source_ip": f"192.168.1.{random.randint(100, 200)}",
            "user_agent": random.choice(user_agents),
            "content_length": random.randint(0, 200),
            "has_suspicious_headers": False,
            "url_length": len(random.choice(normal_urls)),
            "contains_sql_patterns": False,
            "contains_xss_patterns": False
        }
    
    def _generate_threat_request(self, threat_type: str) -> Dict:
        """Generate a malicious HTTP request of the specified type"""
        import random
        
        patterns = self.threat_patterns.get(threat_type, [])
        if not patterns:
            return self._generate_normal_request()
        
        pattern = random.choice(patterns)
        
        # Create base URLs that commonly get attacked
        base_urls = [
            "/api/users",
            "/search",
            "/login",
            "/admin",
            "/api/products",
            "/api/orders",
            "/comment",
            "/api/search",
            "/file"
        ]
        
        base_url = random.choice(base_urls)
        
        # Inject the threat pattern into the URL
        if threat_type == "sql_injection":
            url = f"{base_url}?id={pattern}"
        elif threat_type == "xss_attack":
            url = f"{base_url}?data={pattern}"
        elif threat_type == "directory_traversal":
            url = f"{base_url}?file={pattern}"
        else:
            url = f"{base_url}?param={pattern}"
        
        # Threat-specific user agents
        threat_user_agents = {
            "sql_injection": ["sqlmap/1.6.12", "havij", "pangolin", "python-requests/2.28.1"],
            "xss_attack": ["XSSHunter", "Mozilla/5.0", "BadBot/1.0"],
            "directory_traversal": ["DirBuster", "Nikto", "Wget/1.20.3"]
        }
        
        user_agent = random.choice(threat_user_agents.get(threat_type, ["AttackBot/1.0"]))
        
        return {
            "timestamp": (datetime.now() - timedelta(minutes=random.randint(0, 1440))).isoformat(),
            "method": random.choice(["GET", "POST"]),
            "url": url,
            "headers_count": random.randint(3, 6),
            "body_length": len(pattern) if random.choice([True, False]) else 0,
            "source_ip": f"10.0.0.{random.randint(1, 50)}",  # Different IP range for threats
            "user_agent": user_agent,
            "content_length": len(pattern),
            "has_suspicious_headers": random.choice([True, False]),
            "url_length": len(url),
            "contains_sql_patterns": threat_type == "sql_injection",
            "contains_xss_patterns": threat_type == "xss_attack"
        }
    
    def save_training_data(self, training_data: List[Dict], labels: List[str], 
                          filename_prefix: str = "training") -> Tuple[str, str]:
        """Save training data and labels to files"""
        
        # Create data directory if it doesn't exist
        os.makedirs(self.data_dir, exist_ok=True)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        data_file = os.path.join(self.data_dir, f"{filename_prefix}_data_{timestamp}.json")
        labels_file = os.path.join(self.data_dir, f"{filename_prefix}_labels_{timestamp}.json")
        
        # Save training data
        with open(data_file, 'w') as f:
            json.dump(training_data, f, indent=2)
        
        # Save labels
        with open(labels_file, 'w') as f:
            json.dump(labels, f, indent=2)
        
        logger.info(f"Training data saved to {data_file}")
        logger.info(f"Labels saved to {labels_file}")
        
        return data_file, labels_file
    
    def generate_and_save_training_data(self, num_samples: int = 1000, 
                                       threat_ratio: float = 0.3) -> Tuple[str, str]:
        """Generate and save training data in one step"""
        training_data, labels = self.generate_training_data(num_samples, threat_ratio)
        return self.save_training_data(training_data, labels)


def create_initial_training_data():
    """Create initial training data for the WAF system"""
    generator = TrainingDataGenerator()
    
    # Generate comprehensive training data
    data_file, labels_file = generator.generate_and_save_training_data(
        num_samples=2000,  # Generate 2000 samples
        threat_ratio=0.4   # 40% threats, 60% normal
    )
    
    return data_file, labels_file


if __name__ == "__main__":
    # Create initial training data when run directly
    data_file, labels_file = create_initial_training_data()
    print(f"Training data created:")
    print(f"Data: {data_file}")
    print(f"Labels: {labels_file}")
