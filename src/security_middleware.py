"""
Enhanced Security Middleware

Provides additional security layers including DoS protection, input sanitization,
and comprehensive security headers.
"""

import time
import hashlib
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
from collections import defaultdict, deque

from fastapi import Request, Response, HTTPException, status
from starlette.middleware.base import BaseHTTPMiddleware
from loguru import logger
import ipaddress


class SecurityMiddleware(BaseHTTPMiddleware):
    """Enhanced security middleware with multiple protection layers"""
    
    def __init__(
        self,
        app,
        rate_limit_requests: int = 100,
        rate_limit_window: int = 60,
        enable_dos_protection: bool = True,
        enable_input_validation: bool = True,
        enable_geo_blocking: bool = False,
        blocked_countries: List[str] = None,
        max_request_size: int = 10 * 1024 * 1024,  # 10MB
        enable_honeypot: bool = True
    ):
        super().__init__(app)
        self.rate_limit_requests = rate_limit_requests
        self.rate_limit_window = rate_limit_window
        self.enable_dos_protection = enable_dos_protection
        self.enable_input_validation = enable_input_validation
        self.enable_geo_blocking = enable_geo_blocking
        self.blocked_countries = blocked_countries or []
        self.max_request_size = max_request_size
        self.enable_honeypot = enable_honeypot
        
        # Rate limiting storage
        self.request_counts: Dict[str, deque] = defaultdict(deque)
        self.blocked_ips: Dict[str, datetime] = {}
        self.suspicious_activity: Dict[str, int] = defaultdict(int)
        
        # Security event logging
        self.security_events: deque = deque(maxlen=1000)
        
        # Honeypot endpoints
        self.honeypot_endpoints = {
            '/admin/login.php',
            '/wp-admin/',
            '/phpmyadmin/',
            '/.env',
            '/config.php',
            '/admin.php',
            '/login.asp',
            '/manager/html',
            '/xmlrpc.php'
        }
    
    async def dispatch(self, request: Request, call_next):
        """Main middleware processing"""
        start_time = time.time()
        client_ip = self._get_client_ip(request)
        
        try:
            # 1. Check if IP is blocked
            if self._is_ip_blocked(client_ip):
                self._log_security_event("blocked_ip_attempt", client_ip, request.url.path)
                raise HTTPException(status_code=429, detail="IP temporarily blocked")
            
            # 2. Rate limiting
            if self.enable_dos_protection and self._is_rate_limited(client_ip):
                self._log_security_event("rate_limit_exceeded", client_ip, request.url.path)
                raise HTTPException(status_code=429, detail="Rate limit exceeded")
            
            # 3. Request size validation
            if self._is_request_too_large(request):
                self._log_security_event("large_request", client_ip, request.url.path)
                raise HTTPException(status_code=413, detail="Request too large")
            
            # 4. Honeypot detection
            if self.enable_honeypot and self._is_honeypot_request(request):
                self._handle_honeypot_request(client_ip, request)
                raise HTTPException(status_code=404, detail="Not found")
            
            # 5. Suspicious pattern detection
            if self._has_suspicious_patterns(request):
                self._increment_suspicious_activity(client_ip)
                self._log_security_event("suspicious_pattern", client_ip, request.url.path)
            
            # 6. Input validation
            if self.enable_input_validation:
                await self._validate_input(request)
            
            # Process request
            response = await call_next(request)
            
            # Add security headers
            self._add_security_headers(response)
            
            # Log successful request
            processing_time = time.time() - start_time
            logger.debug(f"Request processed: {client_ip} -> {request.url.path} ({processing_time:.3f}s)")
            
            return response
            
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Security middleware error: {e}")
            self._log_security_event("middleware_error", client_ip, str(e))
            raise HTTPException(status_code=500, detail="Internal security error")
    
    def _get_client_ip(self, request: Request) -> str:
        """Extract client IP with proxy support"""
        # Check for forwarded headers (in order of preference)
        forwarded_headers = [
            'X-Forwarded-For',
            'X-Real-IP',
            'X-Client-IP',
            'CF-Connecting-IP'  # Cloudflare
        ]
        
        for header in forwarded_headers:
            if header in request.headers:
                # Take the first IP if multiple are present
                ip = request.headers[header].split(',')[0].strip()
                try:
                    ipaddress.ip_address(ip)
                    return ip
                except ValueError:
                    continue
        
        # Fallback to direct connection IP
        return request.client.host if request.client else "127.0.0.1"
    
    def _is_ip_blocked(self, ip: str) -> bool:
        """Check if IP is temporarily blocked"""
        if ip in self.blocked_ips:
            # Check if block has expired (24 hour blocks)
            if datetime.now() - self.blocked_ips[ip] > timedelta(hours=24):
                del self.blocked_ips[ip]
                return False
            return True
        return False
    
    def _is_rate_limited(self, ip: str) -> bool:
        """Check if IP exceeds rate limits"""
        now = time.time()
        window_start = now - self.rate_limit_window
        
        # Clean old entries
        while self.request_counts[ip] and self.request_counts[ip][0] < window_start:
            self.request_counts[ip].popleft()
        
        # Check current rate
        if len(self.request_counts[ip]) >= self.rate_limit_requests:
            # Block IP if consistently hitting rate limits
            self.suspicious_activity[ip] += 1
            if self.suspicious_activity[ip] >= 5:
                self.blocked_ips[ip] = datetime.now()
                logger.warning(f"IP {ip} blocked due to repeated rate limit violations")
            return True
        
        # Add current request
        self.request_counts[ip].append(now)
        return False
    
    def _is_request_too_large(self, request: Request) -> bool:
        """Check if request size exceeds limits"""
        content_length = request.headers.get('content-length')
        if content_length:
            try:
                size = int(content_length)
                return size > self.max_request_size
            except ValueError:
                return False
        return False
    
    def _is_honeypot_request(self, request: Request) -> bool:
        """Check if request matches honeypot endpoints"""
        path = request.url.path.lower()
        return any(honeypot in path for honeypot in self.honeypot_endpoints)
    
    def _handle_honeypot_request(self, ip: str, request: Request):
        """Handle honeypot detection"""
        self.suspicious_activity[ip] += 10  # High penalty for honeypot access
        self._log_security_event("honeypot_access", ip, request.url.path)
        
        # Immediate block for honeypot access
        if self.suspicious_activity[ip] >= 10:
            self.blocked_ips[ip] = datetime.now()
            logger.warning(f"IP {ip} blocked due to honeypot access")
    
    def _has_suspicious_patterns(self, request: Request) -> bool:
        """Check for suspicious patterns in request"""
        suspicious_patterns = [
            # SQL injection patterns
            r'union\s+select',
            r'drop\s+table',
            r'insert\s+into',
            r'delete\s+from',
            r'update\s+.*\s+set',
            r'exec\s*\(',
            r'sp_\w+',
            r'xp_\w+',
            
            # XSS patterns
            r'<script.*?>',
            r'javascript:',
            r'vbscript:',
            r'onload\s*=',
            r'onerror\s*=',
            r'onclick\s*=',
            
            # Command injection
            r';\s*cat\s+',
            r';\s*ls\s+',
            r';\s*id\s*;',
            r';\s*pwd\s*;',
            r'\|\s*nc\s+',
            r'\|\s*netcat\s+',
            
            # Directory traversal
            r'\.\.\/.*\.\./',
            r'\.\.\\.*\.\.\\'
        ]
        
        # Check URL, query params, and user agent
        check_strings = [
            request.url.path,
            str(request.url.query),
            request.headers.get('user-agent', ''),
            request.headers.get('referer', '')
        ]
        
        import re
        for check_string in check_strings:
            for pattern in suspicious_patterns:
                if re.search(pattern, check_string, re.IGNORECASE):
                    return True
        
        return False
    
    def _increment_suspicious_activity(self, ip: str):
        """Increment suspicious activity counter"""
        self.suspicious_activity[ip] += 1
        
        # Auto-block after threshold
        if self.suspicious_activity[ip] >= 20:
            self.blocked_ips[ip] = datetime.now()
            logger.warning(f"IP {ip} auto-blocked due to suspicious activity")
    
    async def _validate_input(self, request: Request):
        """Validate request input"""
        # Check for null bytes
        if '\x00' in str(request.url):
            raise HTTPException(status_code=400, detail="Invalid characters in request")
        
        # Check content type for POST/PUT requests
        if request.method in ['POST', 'PUT', 'PATCH']:
            content_type = request.headers.get('content-type', '')
            if not content_type:
                raise HTTPException(status_code=400, detail="Content-Type header required")
            
            # Only allow specific content types
            allowed_types = [
                'application/json',
                'application/x-www-form-urlencoded',
                'multipart/form-data',
                'text/plain'
            ]
            
            if not any(allowed_type in content_type for allowed_type in allowed_types):
                raise HTTPException(status_code=415, detail="Unsupported content type")
    
    def _add_security_headers(self, response: Response):
        """Add comprehensive security headers"""
        headers = {
            # Prevent MIME type sniffing
            'X-Content-Type-Options': 'nosniff',
            
            # Prevent framing (clickjacking protection)
            'X-Frame-Options': 'DENY',
            
            # XSS protection (legacy browsers)
            'X-XSS-Protection': '1; mode=block',
            
            # HTTPS enforcement
            'Strict-Transport-Security': 'max-age=31536000; includeSubDomains; preload',
            
            # Referrer policy
            'Referrer-Policy': 'strict-origin-when-cross-origin',
            
            # Content Security Policy
            'Content-Security-Policy': "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'",
            
            # Permissions policy (formerly Feature Policy)
            'Permissions-Policy': 'geolocation=(), microphone=(), camera=(), payment=(), usb=(), interest-cohort=()',
            
            # Remove server info
            'Server': 'nginx-waf-ai',
            
            # Cache control for sensitive endpoints
            'Cache-Control': 'no-cache, no-store, must-revalidate',
            'Pragma': 'no-cache',
            'Expires': '0'
        }
        
        for header, value in headers.items():
            response.headers[header] = value
    
    def _log_security_event(self, event_type: str, ip: str, details: str):
        """Log security events for monitoring"""
        event = {
            'timestamp': datetime.now().isoformat(),
            'event_type': event_type,
            'source_ip': ip,
            'details': details,
            'severity': self._get_event_severity(event_type)
        }
        
        self.security_events.append(event)
        
        # Log to system logger based on severity
        if event['severity'] == 'critical':
            logger.critical(f"SECURITY: {event_type} from {ip}: {details}")
        elif event['severity'] == 'warning':
            logger.warning(f"SECURITY: {event_type} from {ip}: {details}")
        else:
            logger.info(f"SECURITY: {event_type} from {ip}: {details}")
    
    def _get_event_severity(self, event_type: str) -> str:
        """Determine event severity"""
        critical_events = {'honeypot_access', 'blocked_ip_attempt'}
        warning_events = {'rate_limit_exceeded', 'suspicious_pattern', 'large_request'}
        
        if event_type in critical_events:
            return 'critical'
        elif event_type in warning_events:
            return 'warning'
        else:
            return 'info'
    
    def get_security_stats(self) -> Dict:
        """Get security statistics"""
        return {
            'blocked_ips_count': len(self.blocked_ips),
            'suspicious_ips_count': len(self.suspicious_activity),
            'total_security_events': len(self.security_events),
            'recent_events': list(self.security_events)[-10:],  # Last 10 events
            'top_suspicious_ips': sorted(
                self.suspicious_activity.items(),
                key=lambda x: x[1],
                reverse=True
            )[:10]
        }
    
    def unblock_ip(self, ip: str) -> bool:
        """Manually unblock an IP"""
        if ip in self.blocked_ips:
            del self.blocked_ips[ip]
            self.suspicious_activity[ip] = 0
            logger.info(f"IP {ip} manually unblocked")
            return True
        return False


# Thread-safe IP whitelist for critical infrastructure
WHITELIST_IPS = {
    '127.0.0.1',
    '::1',
    '10.0.0.0/8',
    '172.16.0.0/12',
    '192.168.0.0/16'
}

def is_ip_whitelisted(ip: str) -> bool:
    """Check if IP is in whitelist"""
    try:
        ip_obj = ipaddress.ip_address(ip)
        for whitelist_entry in WHITELIST_IPS:
            if '/' in whitelist_entry:
                if ip_obj in ipaddress.ip_network(whitelist_entry):
                    return True
            else:
                if str(ip_obj) == whitelist_entry:
                    return True
    except ValueError:
        pass
    return False
