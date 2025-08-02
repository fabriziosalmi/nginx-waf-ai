"""
WAF Rule Generator Module

Generates nginx WAF rules based on ML threat predictions.
"""

from typing import List, Dict, Optional
from dataclasses import dataclass
from datetime import datetime
import json
import re


@dataclass
class WAFRule:
    """Represents a WAF rule for nginx"""
    rule_id: str
    rule_type: str
    condition: str
    action: str
    description: str
    severity: str
    created_at: datetime
    expires_at: Optional[datetime] = None
    
    def to_nginx_config(self) -> str:
        """Convert rule to nginx configuration format"""
        if self.rule_type == "block_ip":
            return f"deny {self.condition};"
        elif self.rule_type == "block_url_pattern":
            return f'if ($request_uri ~ "{self.condition}") {{ return 403; }}'
        elif self.rule_type == "block_user_agent":
            return f'if ($http_user_agent ~ "{self.condition}") {{ return 403; }}'
        elif self.rule_type == "rate_limit":
            # Use existing zone defined in main nginx config to avoid conflicts
            return f"limit_req zone=main burst=5 nodelay;"
        else:
            return f"# {self.description}"
    
    def to_dict(self) -> Dict:
        return {
            'rule_id': self.rule_id,
            'rule_type': self.rule_type,
            'condition': self.condition,
            'action': self.action,
            'description': self.description,
            'severity': self.severity,
            'created_at': self.created_at.isoformat(),
            'expires_at': self.expires_at.isoformat() if self.expires_at else None,
            'nginx_config': self.to_nginx_config()
        }


class WAFRuleGenerator:
    """Generates WAF rules based on threat predictions"""
    
    def __init__(self):
        self.active_rules = []
        self.rule_counter = 0
    
    def generate_rules_from_threats(self, threats: List[Dict], 
                                  threat_patterns: Dict[str, int]) -> List[WAFRule]:
        """Generate WAF rules based on detected threats"""
        new_rules = []
        
        # Group threats by type for pattern analysis
        threat_groups = self._group_threats_by_type(threats)
        
        for threat_type, threat_list in threat_groups.items():
            if len(threat_list) >= 3:  # Generate rule if we see 3+ similar threats
                rule = self._generate_rule_for_threat_type(threat_type, threat_list)
                if rule:
                    new_rules.append(rule)
        
        # Generate IP-based rules for repeat offenders
        ip_threats = self._analyze_ip_patterns(threats)
        for ip, count in ip_threats.items():
            if count >= 5:  # Block IPs with 5+ threats
                rule = self._generate_ip_block_rule(ip, count)
                new_rules.append(rule)
        
        # Generate rate limiting rules for high-volume attacks
        if sum(threat_patterns.values()) > 20:  # High threat volume
            rule = self._generate_rate_limit_rule(threat_patterns)
            new_rules.append(rule)
        
        self.active_rules.extend(new_rules)
        return new_rules
    
    def _group_threats_by_type(self, threats: List[Dict]) -> Dict[str, List[Dict]]:
        """Group threats by their type"""
        groups = {}
        for threat in threats:
            threat_type = threat.get('threat_type', 'unknown')
            if threat_type not in groups:
                groups[threat_type] = []
            groups[threat_type].append(threat)
        return groups
    
    def _generate_rule_for_threat_type(self, threat_type: str, 
                                     threats: List[Dict]) -> Optional[WAFRule]:
        """Generate a specific rule based on threat type"""
        self.rule_counter += 1
        
        if threat_type == "sql_injection":
            # Create rule to block SQL injection patterns
            pattern = r"(union\s+select|or\s+1=1|drop\s+table|select\s+\*\s+from)"
            return WAFRule(
                rule_id=f"waf_rule_{self.rule_counter}",
                rule_type="block_url_pattern",
                condition=pattern,
                action="block",
                description=f"Block SQL injection attempts (detected {len(threats)} instances)",
                severity="high",
                created_at=datetime.now()
            )
        
        elif threat_type == "xss_attack":
            # Create rule to block XSS patterns
            pattern = r"(<script|javascript:|onerror=|onload=)"
            return WAFRule(
                rule_id=f"waf_rule_{self.rule_counter}",
                rule_type="block_url_pattern",
                condition=pattern,
                action="block",
                description=f"Block XSS attempts (detected {len(threats)} instances)",
                severity="high",
                created_at=datetime.now()
            )
        
        elif threat_type == "bot_attack":
            # Analyze user agents from bot attacks
            user_agents = [t.get('user_agent', '') for t in threats if t.get('user_agent')]
            if user_agents:
                # Find common patterns in user agents
                common_pattern = self._find_common_user_agent_pattern(user_agents)
                if common_pattern:
                    return WAFRule(
                        rule_id=f"waf_rule_{self.rule_counter}",
                        rule_type="block_user_agent",
                        condition=common_pattern,
                        action="block",
                        description=f"Block malicious bots (detected {len(threats)} instances)",
                        severity="medium",
                        created_at=datetime.now()
                    )
        
        return None
    
    def _generate_ip_block_rule(self, ip: str, threat_count: int) -> WAFRule:
        """Generate IP blocking rule"""
        self.rule_counter += 1
        
        return WAFRule(
            rule_id=f"waf_rule_{self.rule_counter}",
            rule_type="block_ip",
            condition=ip,
            action="block",
            description=f"Block malicious IP {ip} ({threat_count} threats detected)",
            severity="high",
            created_at=datetime.now(),
            expires_at=datetime.fromtimestamp(datetime.now().timestamp() + 3600)  # 1 hour
        )
    
    def _generate_rate_limit_rule(self, threat_patterns: Dict[str, int]) -> WAFRule:
        """Generate rate limiting rule"""
        self.rule_counter += 1
        
        total_threats = sum(threat_patterns.values())
        
        return WAFRule(
            rule_id=f"waf_rule_{self.rule_counter}",
            rule_type="rate_limit",
            condition="high_threat_volume",  # Just a description, zone is hardcoded in to_nginx_config
            action="rate_limit",
            description=f"Rate limit due to high threat volume ({total_threats} threats)",
            severity="medium",
            created_at=datetime.now(),
            expires_at=datetime.fromtimestamp(datetime.now().timestamp() + 1800)  # 30 minutes
        )
    
    def _analyze_ip_patterns(self, threats: List[Dict]) -> Dict[str, int]:
        """Analyze IP addresses in threats"""
        ip_counts = {}
        for threat in threats:
            ip = threat.get('source_ip', '')
            if ip:
                ip_counts[ip] = ip_counts.get(ip, 0) + 1
        return ip_counts
    
    def _find_common_user_agent_pattern(self, user_agents: List[str]) -> Optional[str]:
        """Find common patterns in user agent strings"""
        if not user_agents:
            return None
        
        # Simple pattern matching - look for exact matches first
        if len(set(user_agents)) == 1:
            return re.escape(user_agents[0])
        
        # Look for common substrings
        common_parts = []
        for agent in user_agents:
            words = agent.split()
            for word in words:
                if len(word) > 3 and sum(1 for ua in user_agents if word in ua) >= len(user_agents) * 0.7:
                    common_parts.append(word)
        
        if common_parts:
            return "|".join(re.escape(part) for part in set(common_parts))
        
        return None
    
    def get_active_rules(self) -> List[WAFRule]:
        """Get currently active rules"""
        now = datetime.now()
        # Filter out expired rules
        self.active_rules = [
            rule for rule in self.active_rules 
            if rule.expires_at is None or rule.expires_at > now
        ]
        return self.active_rules
    
    def generate_nginx_config(self, rules: List[WAFRule]) -> str:
        """Generate complete nginx configuration for WAF rules"""
        config_lines = [
            "# Auto-generated WAF rules",
            f"# Generated at: {datetime.now().isoformat()}",
            "",
            "# WAF Rules",
        ]
        
        for rule in rules:
            config_lines.append(f"# Rule ID: {rule.rule_id} - {rule.description}")
            config_lines.append(rule.to_nginx_config())
            config_lines.append("")
        
        return "\n".join(config_lines)
    
    def export_rules_to_json(self, rules: List[WAFRule], filepath: str):
        """Export rules to JSON file"""
        rules_data = [rule.to_dict() for rule in rules]
        with open(filepath, 'w') as f:
            json.dump(rules_data, f, indent=2)
        print(f"Rules exported to {filepath}")


class RuleOptimizer:
    """Optimizes and merges similar WAF rules"""
    
    def optimize_rules(self, rules: List[WAFRule]) -> List[WAFRule]:
        """Optimize rules by merging similar ones and removing duplicates"""
        optimized = []
        
        # Group rules by type
        rule_groups = {}
        for rule in rules:
            if rule.rule_type not in rule_groups:
                rule_groups[rule.rule_type] = []
            rule_groups[rule.rule_type].append(rule)
        
        # Optimize each group
        for rule_type, group_rules in rule_groups.items():
            if rule_type == "block_ip":
                optimized.extend(self._optimize_ip_rules(group_rules))
            elif rule_type == "block_url_pattern":
                optimized.extend(self._optimize_pattern_rules(group_rules))
            else:
                optimized.extend(group_rules)
        
        return optimized
    
    def _optimize_ip_rules(self, ip_rules: List[WAFRule]) -> List[WAFRule]:
        """Optimize IP blocking rules by grouping into subnets"""
        # Simple implementation - in practice, you'd want to group by subnets
        unique_ips = {}
        for rule in ip_rules:
            ip = rule.condition
            if ip not in unique_ips or rule.created_at > unique_ips[ip].created_at:
                unique_ips[ip] = rule
        
        return list(unique_ips.values())
    
    def _optimize_pattern_rules(self, pattern_rules: List[WAFRule]) -> List[WAFRule]:
        """Optimize URL pattern rules by merging similar patterns"""
        # Simple deduplication - in practice, you'd want to merge similar regex patterns
        unique_patterns = {}
        for rule in pattern_rules:
            pattern = rule.condition
            if pattern not in unique_patterns or rule.created_at > unique_patterns[pattern].created_at:
                unique_patterns[pattern] = rule
        
        return list(unique_patterns.values())
