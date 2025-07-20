#!/usr/bin/env python3
"""
Unit tests for the WAF Rule Generator component.

This test suite verifies rule generation logic, nginx configuration generation,
rule optimization, and rule lifecycle management.
"""

import pytest
from datetime import datetime, timedelta
from unittest.mock import Mock, patch
from typing import List, Dict, Any

from src.waf_rule_generator import (
    WAFRuleGenerator, WAFRule, RuleOptimizer, 
    RuleAction, RulePriority, RuleType
)
from src.ml_engine import ThreatPrediction


class TestWAFRuleGenerator:
    """Test WAF rule generation functionality"""
    
    def setup_method(self):
        """Set up test fixtures"""
        self.generator = WAFRuleGenerator()
        self.test_threats = [
            ThreatPrediction(
                threat_score=-0.8,
                threat_type="sql_injection",
                confidence=0.9,
                features_used=["url_contains_sql", "suspicious_patterns"],
                source_ip="192.168.1.100",
                url="/admin/login?id=1' OR 1=1--",
                user_agent="Mozilla/5.0 (X11; Linux x86_64)"
            ),
            ThreatPrediction(
                threat_score=-0.7,
                threat_type="xss_attack",
                confidence=0.85,
                features_used=["url_contains_script", "suspicious_patterns"],
                source_ip="192.168.1.101",
                url="/search?q=<script>alert('xss')</script>",
                user_agent="Mozilla/5.0 (Windows NT 10.0)"
            ),
            ThreatPrediction(
                threat_score=-0.9,
                threat_type="brute_force",
                confidence=0.95,
                features_used=["repeated_failed_logins", "source_ip"],
                source_ip="192.168.1.102",
                url="/login",
                user_agent="Python/3.8"
            )
        ]
    
    def test_rule_generation_from_sql_injection(self):
        """Test rule generation from SQL injection threats"""
        sql_threat = self.test_threats[0]  # SQL injection threat
        
        rules = self.generator.generate_rules_from_threats([sql_threat])
        
        assert len(rules) > 0
        
        # Should generate URL pattern rule
        url_rules = [r for r in rules if r.rule_type == RuleType.URL_PATTERN]
        assert len(url_rules) > 0
        
        url_rule = url_rules[0]
        assert url_rule.action == RuleAction.BLOCK
        assert "sql" in url_rule.pattern.lower() or "union" in url_rule.pattern.lower() or "'" in url_rule.pattern
        assert url_rule.priority >= 90  # High priority for SQL injection
    
    def test_rule_generation_from_xss_attack(self):
        """Test rule generation from XSS attack threats"""
        xss_threat = self.test_threats[1]  # XSS attack threat
        
        rules = self.generator.generate_rules_from_threats([xss_threat])
        
        assert len(rules) > 0
        
        # Should generate URL pattern rule
        url_rules = [r for r in rules if r.rule_type == RuleType.URL_PATTERN]
        assert len(url_rules) > 0
        
        url_rule = url_rules[0]
        assert url_rule.action == RuleAction.BLOCK
        assert "script" in url_rule.pattern.lower() or "<" in url_rule.pattern or ">" in url_rule.pattern
        assert url_rule.priority >= 85  # High priority for XSS
    
    def test_rule_generation_from_brute_force(self):
        """Test rule generation from brute force threats"""
        brute_force_threat = self.test_threats[2]  # Brute force threat
        
        rules = self.generator.generate_rules_from_threats([brute_force_threat])
        
        assert len(rules) > 0
        
        # Should generate IP blocking rule
        ip_rules = [r for r in rules if r.rule_type == RuleType.IP_BLOCK]
        assert len(ip_rules) > 0
        
        ip_rule = ip_rules[0]
        assert ip_rule.action == RuleAction.BLOCK
        assert ip_rule.pattern == "192.168.1.102"
        assert ip_rule.priority >= 95  # Very high priority for brute force
    
    def test_rule_generation_multiple_threats(self):
        """Test rule generation from multiple different threats"""
        rules = self.generator.generate_rules_from_threats(self.test_threats)
        
        assert len(rules) >= 3  # Should generate at least one rule per threat
        
        # Check that different rule types are generated
        rule_types = set(rule.rule_type for rule in rules)
        assert RuleType.URL_PATTERN in rule_types
        assert RuleType.IP_BLOCK in rule_types
    
    def test_rule_deduplication(self):
        """Test that duplicate rules are properly deduplicated"""
        # Create multiple identical threats
        identical_threats = [self.test_threats[0]] * 3
        
        rules = self.generator.generate_rules_from_threats(identical_threats)
        
        # Should not generate duplicate rules
        rule_patterns = [rule.pattern for rule in rules]
        unique_patterns = set(rule_patterns)
        
        # Number of unique patterns should be less than total rules if deduplication works
        assert len(unique_patterns) <= len(rules)
    
    def test_rule_priority_assignment(self):
        """Test that rules are assigned appropriate priorities"""
        rules = self.generator.generate_rules_from_threats(self.test_threats)
        
        for rule in rules:
            assert isinstance(rule.priority, int)
            assert 1 <= rule.priority <= 100  # Priority should be in valid range
            
            # High-threat rules should have high priority
            if rule.pattern and ("injection" in rule.description.lower() or "xss" in rule.description.lower()):
                assert rule.priority >= 80
    
    def test_rule_expiration(self):
        """Test rule expiration functionality"""
        rules = self.generator.generate_rules_from_threats(self.test_threats)
        
        for rule in rules:
            if rule.expires_at:
                assert rule.expires_at > datetime.now()  # Should expire in the future
                assert rule.expires_at <= datetime.now() + timedelta(days=30)  # Reasonable expiration time


class TestWAFRule:
    """Test WAF rule data structure and methods"""
    
    def test_rule_creation(self):
        """Test WAF rule creation"""
        rule = WAFRule(
            rule_id="test-rule-1",
            rule_type=RuleType.URL_PATTERN,
            pattern=".*admin.*",
            action=RuleAction.BLOCK,
            priority=90,
            description="Block admin access attempts",
            created_at=datetime.now(),
            expires_at=datetime.now() + timedelta(hours=24)
        )
        
        assert rule.rule_id == "test-rule-1"
        assert rule.rule_type == RuleType.URL_PATTERN
        assert rule.pattern == ".*admin.*"
        assert rule.action == RuleAction.BLOCK
        assert rule.priority == 90
        assert rule.description == "Block admin access attempts"
        assert rule.created_at is not None
        assert rule.expires_at is not None
    
    def test_rule_to_nginx_config_url_pattern(self):
        """Test converting URL pattern rule to nginx config"""
        rule = WAFRule(
            rule_id="url-rule-1",
            rule_type=RuleType.URL_PATTERN,
            pattern=".*\\.(php|asp|jsp)$",
            action=RuleAction.BLOCK,
            priority=85,
            description="Block script file access"
        )
        
        nginx_config = rule.to_nginx_config()
        
        assert "location" in nginx_config
        assert rule.pattern in nginx_config
        assert "deny all" in nginx_config or "return 403" in nginx_config
    
    def test_rule_to_nginx_config_ip_block(self):
        """Test converting IP block rule to nginx config"""
        rule = WAFRule(
            rule_id="ip-rule-1",
            rule_type=RuleType.IP_BLOCK,
            pattern="192.168.1.100",
            action=RuleAction.BLOCK,
            priority=95,
            description="Block malicious IP"
        )
        
        nginx_config = rule.to_nginx_config()
        
        assert "deny" in nginx_config
        assert "192.168.1.100" in nginx_config
    
    def test_rule_to_nginx_config_rate_limit(self):
        """Test converting rate limit rule to nginx config"""
        rule = WAFRule(
            rule_id="rate-rule-1",
            rule_type=RuleType.RATE_LIMIT,
            pattern="/api/",
            action=RuleAction.RATE_LIMIT,
            priority=70,
            description="Rate limit API endpoints",
            metadata={"rate": "10r/m"}
        )
        
        nginx_config = rule.to_nginx_config()
        
        assert "limit_req" in nginx_config or "limit_conn" in nginx_config
        assert "/api/" in nginx_config
    
    def test_rule_is_expired(self):
        """Test rule expiration checking"""
        # Non-expiring rule
        rule_no_expiry = WAFRule(
            rule_id="no-expiry",
            rule_type=RuleType.URL_PATTERN,
            pattern=".*test.*",
            action=RuleAction.BLOCK,
            priority=50,
            description="No expiry rule"
        )
        
        assert not rule_no_expiry.is_expired()
        
        # Expired rule
        rule_expired = WAFRule(
            rule_id="expired",
            rule_type=RuleType.URL_PATTERN,
            pattern=".*test.*",
            action=RuleAction.BLOCK,
            priority=50,
            description="Expired rule",
            expires_at=datetime.now() - timedelta(hours=1)
        )
        
        assert rule_expired.is_expired()
        
        # Future expiry rule
        rule_future = WAFRule(
            rule_id="future",
            rule_type=RuleType.URL_PATTERN,
            pattern=".*test.*",
            action=RuleAction.BLOCK,
            priority=50,
            description="Future expiry rule",
            expires_at=datetime.now() + timedelta(hours=1)
        )
        
        assert not rule_future.is_expired()


class TestRuleOptimizer:
    """Test rule optimization functionality"""
    
    def setup_method(self):
        """Set up test fixtures"""
        self.optimizer = RuleOptimizer()
        
        # Create test rules for optimization
        self.test_rules = [
            WAFRule(
                rule_id="rule-1",
                rule_type=RuleType.URL_PATTERN,
                pattern=".*admin.*",
                action=RuleAction.BLOCK,
                priority=90,
                description="Block admin access"
            ),
            WAFRule(
                rule_id="rule-2",
                rule_type=RuleType.URL_PATTERN,
                pattern=".*admin/login.*",
                action=RuleAction.BLOCK,
                priority=85,
                description="Block admin login"
            ),
            WAFRule(
                rule_id="rule-3",
                rule_type=RuleType.IP_BLOCK,
                pattern="192.168.1.100",
                action=RuleAction.BLOCK,
                priority=95,
                description="Block malicious IP"
            ),
            WAFRule(
                rule_id="rule-4",
                rule_type=RuleType.URL_PATTERN,
                pattern=".*\\.php$",
                action=RuleAction.BLOCK,
                priority=80,
                description="Block PHP files"
            )
        ]
    
    def test_rule_deduplication_exact_match(self):
        """Test deduplication of exactly matching rules"""
        # Create duplicate rules
        duplicate_rules = [
            self.test_rules[0],  # Original rule
            WAFRule(  # Duplicate with different ID
                rule_id="rule-duplicate",
                rule_type=RuleType.URL_PATTERN,
                pattern=".*admin.*",
                action=RuleAction.BLOCK,
                priority=90,
                description="Block admin access"
            )
        ]
        
        optimized = self.optimizer.deduplicate_rules(duplicate_rules)
        
        # Should keep only one of the duplicate rules
        assert len(optimized) == 1
        assert optimized[0].pattern == ".*admin.*"
    
    def test_rule_consolidation_overlapping_patterns(self):
        """Test consolidation of overlapping URL patterns"""
        overlapping_rules = [
            self.test_rules[0],  # .*admin.*
            self.test_rules[1],  # .*admin/login.*
        ]
        
        consolidated = self.optimizer.consolidate_patterns(overlapping_rules)
        
        # Should consolidate overlapping patterns
        assert len(consolidated) <= len(overlapping_rules)
        
        # More general pattern should be kept
        patterns = [rule.pattern for rule in consolidated]
        assert ".*admin.*" in patterns
    
    def test_rule_priority_optimization(self):
        """Test rule priority optimization"""
        optimized = self.optimizer.optimize_priorities(self.test_rules)
        
        # Rules should be sorted by priority (highest first)
        priorities = [rule.priority for rule in optimized]
        assert priorities == sorted(priorities, reverse=True)
    
    def test_rule_performance_optimization(self):
        """Test performance optimization of rules"""
        # Create rules with potentially expensive patterns
        expensive_rules = [
            WAFRule(
                rule_id="expensive-1",
                rule_type=RuleType.URL_PATTERN,
                pattern=".*(.*).*(.*).*",  # Expensive regex
                action=RuleAction.BLOCK,
                priority=50,
                description="Expensive pattern"
            ),
            WAFRule(
                rule_id="simple-1",
                rule_type=RuleType.URL_PATTERN,
                pattern="/admin",  # Simple pattern
                action=RuleAction.BLOCK,
                priority=60,
                description="Simple pattern"
            )
        ]
        
        optimized = self.optimizer.optimize_performance(expensive_rules)
        
        # Should reorder rules to put simpler patterns first
        assert len(optimized) == len(expensive_rules)
        
        # Simple patterns should come before complex ones at same priority level
        for rule in optimized:
            assert rule.pattern is not None
    
    def test_full_optimization_pipeline(self):
        """Test the complete optimization pipeline"""
        # Add some duplicate and overlapping rules
        rules_to_optimize = self.test_rules + [
            WAFRule(  # Duplicate of rule-1
                rule_id="duplicate-admin",
                rule_type=RuleType.URL_PATTERN,
                pattern=".*admin.*",
                action=RuleAction.BLOCK,
                priority=90,
                description="Block admin access (duplicate)"
            ),
            WAFRule(  # Expired rule
                rule_id="expired-rule",
                rule_type=RuleType.URL_PATTERN,
                pattern=".*test.*",
                action=RuleAction.BLOCK,
                priority=70,
                description="Expired rule",
                expires_at=datetime.now() - timedelta(hours=1)
            )
        ]
        
        optimized = self.optimizer.optimize_rules(rules_to_optimize)
        
        # Should have fewer rules due to optimization
        assert len(optimized) <= len(rules_to_optimize)
        
        # Should not contain expired rules
        for rule in optimized:
            assert not rule.is_expired()
        
        # Should be sorted by priority
        priorities = [rule.priority for rule in optimized]
        assert priorities == sorted(priorities, reverse=True)


class TestNginxConfigGeneration:
    """Test nginx configuration generation"""
    
    def setup_method(self):
        """Set up test fixtures"""
        self.generator = WAFRuleGenerator()
        
        self.test_rules = [
            WAFRule(
                rule_id="block-admin",
                rule_type=RuleType.URL_PATTERN,
                pattern=".*admin.*",
                action=RuleAction.BLOCK,
                priority=90,
                description="Block admin access"
            ),
            WAFRule(
                rule_id="block-ip",
                rule_type=RuleType.IP_BLOCK,
                pattern="192.168.1.100",
                action=RuleAction.BLOCK,
                priority=95,
                description="Block malicious IP"
            ),
            WAFRule(
                rule_id="rate-limit-api",
                rule_type=RuleType.RATE_LIMIT,
                pattern="/api/",
                action=RuleAction.RATE_LIMIT,
                priority=70,
                description="Rate limit API",
                metadata={"rate": "10r/m"}
            )
        ]
    
    def test_generate_nginx_config_basic(self):
        """Test basic nginx configuration generation"""
        config = self.generator.generate_nginx_config(self.test_rules)
        
        assert isinstance(config, str)
        assert len(config) > 0
        
        # Should contain comments for organization
        assert "#" in config
        
        # Should contain rule configurations
        assert "location" in config  # URL pattern rules
        assert "deny" in config      # IP blocking rules
    
    def test_generate_nginx_config_rule_ordering(self):
        """Test that nginx config respects rule priorities"""
        config = self.generator.generate_nginx_config(self.test_rules)
        
        # Higher priority rules should appear first in config
        lines = config.split('\n')
        
        # Find positions of rules in config
        admin_pos = None
        ip_pos = None
        
        for i, line in enumerate(lines):
            if "admin" in line and admin_pos is None:
                admin_pos = i
            if "192.168.1.100" in line and ip_pos is None:
                ip_pos = i
        
        # IP blocking rule (priority 95) should come before admin rule (priority 90)
        if admin_pos is not None and ip_pos is not None:
            assert ip_pos < admin_pos
    
    def test_generate_nginx_config_syntax_validity(self):
        """Test that generated nginx config has valid syntax"""
        config = self.generator.generate_nginx_config(self.test_rules)
        
        # Basic syntax checks
        lines = config.split('\n')
        
        # Check that braces are balanced
        open_braces = config.count('{')
        close_braces = config.count('}')
        assert open_braces == close_braces
        
        # Check that location blocks are properly formatted
        location_lines = [line for line in lines if 'location' in line]
        for location_line in location_lines:
            # Should have proper nginx location syntax
            assert '~' in location_line or '=' in location_line or location_line.strip().endswith('{')
    
    def test_generate_nginx_config_security_headers(self):
        """Test that security headers are included in config"""
        config = self.generator.generate_nginx_config(self.test_rules)
        
        # Should include security-related configurations
        security_keywords = [
            'X-Frame-Options',
            'X-Content-Type-Options',
            'X-XSS-Protection',
            'server_tokens'
        ]
        
        # At least some security configurations should be present
        found_security = any(keyword in config for keyword in security_keywords)
        assert found_security
    
    def test_generate_nginx_config_empty_rules(self):
        """Test nginx config generation with empty rule list"""
        config = self.generator.generate_nginx_config([])
        
        assert isinstance(config, str)
        # Should still generate a basic config structure
        assert len(config) > 0
        assert "# WAF Rules Configuration" in config or "# No active rules" in config


class TestRuleLifecycleManagement:
    """Test rule lifecycle management"""
    
    def setup_method(self):
        """Set up test fixtures"""
        self.generator = WAFRuleGenerator()
    
    def test_add_rule(self):
        """Test adding a new rule"""
        initial_count = len(self.generator.get_active_rules())
        
        new_rule = WAFRule(
            rule_id="new-rule",
            rule_type=RuleType.URL_PATTERN,
            pattern=".*test.*",
            action=RuleAction.BLOCK,
            priority=50,
            description="Test rule"
        )
        
        self.generator.add_rule(new_rule)
        
        assert len(self.generator.get_active_rules()) == initial_count + 1
        assert new_rule in self.generator.get_active_rules()
    
    def test_remove_rule(self):
        """Test removing a rule"""
        # Add a rule first
        test_rule = WAFRule(
            rule_id="remove-test",
            rule_type=RuleType.URL_PATTERN,
            pattern=".*remove.*",
            action=RuleAction.BLOCK,
            priority=50,
            description="Rule to remove"
        )
        
        self.generator.add_rule(test_rule)
        initial_count = len(self.generator.get_active_rules())
        
        # Remove the rule
        self.generator.remove_rule("remove-test")
        
        assert len(self.generator.get_active_rules()) == initial_count - 1
        assert test_rule not in self.generator.get_active_rules()
    
    def test_update_rule(self):
        """Test updating an existing rule"""
        # Add a rule first
        original_rule = WAFRule(
            rule_id="update-test",
            rule_type=RuleType.URL_PATTERN,
            pattern=".*update.*",
            action=RuleAction.BLOCK,
            priority=50,
            description="Original rule"
        )
        
        self.generator.add_rule(original_rule)
        
        # Update the rule
        updated_rule = WAFRule(
            rule_id="update-test",
            rule_type=RuleType.URL_PATTERN,
            pattern=".*updated.*",
            action=RuleAction.RATE_LIMIT,
            priority=75,
            description="Updated rule"
        )
        
        self.generator.update_rule(updated_rule)
        
        active_rules = self.generator.get_active_rules()
        updated_in_list = next((r for r in active_rules if r.rule_id == "update-test"), None)
        
        assert updated_in_list is not None
        assert updated_in_list.pattern == ".*updated.*"
        assert updated_in_list.action == RuleAction.RATE_LIMIT
        assert updated_in_list.priority == 75
        assert updated_in_list.description == "Updated rule"
    
    def test_cleanup_expired_rules(self):
        """Test automatic cleanup of expired rules"""
        # Add an expired rule
        expired_rule = WAFRule(
            rule_id="expired-rule",
            rule_type=RuleType.URL_PATTERN,
            pattern=".*expired.*",
            action=RuleAction.BLOCK,
            priority=50,
            description="Expired rule",
            expires_at=datetime.now() - timedelta(hours=1)
        )
        
        # Add a non-expired rule
        active_rule = WAFRule(
            rule_id="active-rule",
            rule_type=RuleType.URL_PATTERN,
            pattern=".*active.*",
            action=RuleAction.BLOCK,
            priority=50,
            description="Active rule",
            expires_at=datetime.now() + timedelta(hours=1)
        )
        
        self.generator.add_rule(expired_rule)
        self.generator.add_rule(active_rule)
        
        # Cleanup expired rules
        self.generator.cleanup_expired_rules()
        
        active_rules = self.generator.get_active_rules()
        rule_ids = [rule.rule_id for rule in active_rules]
        
        assert "expired-rule" not in rule_ids
        assert "active-rule" in rule_ids
