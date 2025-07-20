"""
Error Handling and Recovery Utilities

Provides comprehensive error handling, circuit breaker pattern, 
retry mechanisms, and graceful degradation for the WAF AI system.
"""

import asyncio
import functools
import logging
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Tuple, Type, Union
from loguru import logger
import threading


class CircuitState(Enum):
    """Circuit breaker states"""
    CLOSED = "closed"      # Normal operation
    OPEN = "open"          # Failing, circuit is open
    HALF_OPEN = "half_open"  # Testing if service has recovered


@dataclass
class CircuitBreakerConfig:
    """Configuration for circuit breaker"""
    failure_threshold: int = 5  # Number of failures before opening
    recovery_timeout: int = 60  # Seconds to wait before trying again
    success_threshold: int = 3  # Successes needed to close circuit
    timeout: float = 30.0  # Timeout for operations


class CircuitBreaker:
    """Circuit breaker implementation for external service calls"""
    
    def __init__(self, config: CircuitBreakerConfig):
        self.config = config
        self.state = CircuitState.CLOSED
        self.failure_count = 0
        self.success_count = 0
        self.last_failure_time = None
        self._lock = threading.RLock()
        
    def _reset(self):
        """Reset circuit breaker state"""
        self.failure_count = 0
        self.success_count = 0
        self.last_failure_time = None
        
    def _can_attempt(self) -> bool:
        """Check if we can attempt the operation"""
        if self.state == CircuitState.CLOSED:
            return True
        elif self.state == CircuitState.OPEN:
            if (self.last_failure_time and 
                time.time() - self.last_failure_time > self.config.recovery_timeout):
                self.state = CircuitState.HALF_OPEN
                self.success_count = 0
                return True
            return False
        elif self.state == CircuitState.HALF_OPEN:
            return True
        return False
    
    def _record_success(self):
        """Record a successful operation"""
        with self._lock:
            if self.state == CircuitState.HALF_OPEN:
                self.success_count += 1
                if self.success_count >= self.config.success_threshold:
                    self.state = CircuitState.CLOSED
                    self._reset()
                    logger.info("Circuit breaker closed after recovery")
            elif self.state == CircuitState.CLOSED:
                self._reset()
    
    def _record_failure(self, exception: Exception):
        """Record a failed operation"""
        with self._lock:
            self.failure_count += 1
            self.last_failure_time = time.time()
            
            if self.state == CircuitState.HALF_OPEN:
                self.state = CircuitState.OPEN
                logger.warning("Circuit breaker opened during half-open test")
            elif (self.state == CircuitState.CLOSED and 
                  self.failure_count >= self.config.failure_threshold):
                self.state = CircuitState.OPEN
                logger.warning(f"Circuit breaker opened after {self.failure_count} failures")
    
    async def call(self, func: Callable, *args, **kwargs) -> Any:
        """Execute function with circuit breaker protection"""
        if not self._can_attempt():
            raise CircuitBreakerOpenError(f"Circuit breaker is {self.state.value}")
        
        try:
            # Apply timeout
            result = await asyncio.wait_for(
                func(*args, **kwargs) if asyncio.iscoroutinefunction(func) 
                else asyncio.get_event_loop().run_in_executor(None, func, *args, **kwargs),
                timeout=self.config.timeout
            )
            self._record_success()
            return result
        except Exception as e:
            self._record_failure(e)
            raise


class CircuitBreakerOpenError(Exception):
    """Raised when circuit breaker is open"""
    pass


def retry(max_attempts: int = 3, 
          backoff_strategy: str = "exponential",
          base_delay: float = 1.0,
          max_delay: float = 60.0,
          exceptions: Tuple[Type[Exception], ...] = (Exception,)):
    """Decorator for retry logic with different backoff strategies"""
    
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        async def async_wrapper(*args, **kwargs):
            last_exception = None
            
            for attempt in range(max_attempts):
                try:
                    if asyncio.iscoroutinefunction(func):
                        return await func(*args, **kwargs)
                    else:
                        return func(*args, **kwargs)
                        
                except exceptions as e:
                    last_exception = e
                    
                    if attempt == max_attempts - 1:
                        logger.error(f"All {max_attempts} attempts failed for {func.__name__}: {e}")
                        raise
                    
                    # Calculate delay based on strategy
                    if backoff_strategy == "exponential":
                        delay = min(base_delay * (2 ** attempt), max_delay)
                    elif backoff_strategy == "linear":
                        delay = min(base_delay * (attempt + 1), max_delay)
                    else:  # fixed
                        delay = base_delay
                    
                    logger.warning(f"Attempt {attempt + 1} failed for {func.__name__}: {e}. Retrying in {delay}s...")
                    await asyncio.sleep(delay)
            
            raise last_exception
        
        @functools.wraps(func)
        def sync_wrapper(*args, **kwargs):
            last_exception = None
            
            for attempt in range(max_attempts):
                try:
                    return func(*args, **kwargs)
                        
                except exceptions as e:
                    last_exception = e
                    
                    if attempt == max_attempts - 1:
                        logger.error(f"All {max_attempts} attempts failed for {func.__name__}: {e}")
                        raise
                    
                    # Calculate delay based on strategy
                    if backoff_strategy == "exponential":
                        delay = min(base_delay * (2 ** attempt), max_delay)
                    elif backoff_strategy == "linear":
                        delay = min(base_delay * (attempt + 1), max_delay)
                    else:  # fixed
                        delay = base_delay
                    
                    logger.warning(f"Attempt {attempt + 1} failed for {func.__name__}: {e}. Retrying in {delay}s...")
                    time.sleep(delay)
            
            raise last_exception
        
        # Return appropriate wrapper based on whether function is async
        return async_wrapper if asyncio.iscoroutinefunction(func) else sync_wrapper
    
    return decorator


class ErrorRecoveryManager:
    """Manages error recovery and fallback strategies"""
    
    def __init__(self):
        self.circuit_breakers: Dict[str, CircuitBreaker] = {}
        self.fallback_strategies: Dict[str, Callable] = {}
        self._lock = threading.RLock()
    
    def get_circuit_breaker(self, service_name: str, config: Optional[CircuitBreakerConfig] = None) -> CircuitBreaker:
        """Get or create circuit breaker for a service"""
        with self._lock:
            if service_name not in self.circuit_breakers:
                if config is None:
                    config = CircuitBreakerConfig()
                self.circuit_breakers[service_name] = CircuitBreaker(config)
            return self.circuit_breakers[service_name]
    
    def register_fallback(self, service_name: str, fallback_func: Callable):
        """Register a fallback strategy for a service"""
        with self._lock:
            self.fallback_strategies[service_name] = fallback_func
    
    async def call_with_fallback(self, service_name: str, primary_func: Callable, *args, **kwargs) -> Any:
        """Call function with circuit breaker and fallback"""
        circuit_breaker = self.get_circuit_breaker(service_name)
        
        try:
            return await circuit_breaker.call(primary_func, *args, **kwargs)
        except (CircuitBreakerOpenError, Exception) as e:
            logger.warning(f"Primary function failed for {service_name}: {e}")
            
            # Try fallback if available
            if service_name in self.fallback_strategies:
                try:
                    fallback_func = self.fallback_strategies[service_name]
                    logger.info(f"Using fallback strategy for {service_name}")
                    
                    if asyncio.iscoroutinefunction(fallback_func):
                        return await fallback_func(*args, **kwargs)
                    else:
                        return fallback_func(*args, **kwargs)
                        
                except Exception as fallback_error:
                    logger.error(f"Fallback strategy also failed for {service_name}: {fallback_error}")
                    raise
            else:
                logger.error(f"No fallback strategy available for {service_name}")
                raise
    
    def retry(self, max_attempts: int = 3, delay: float = 1.0, backoff: float = 2.0, exceptions: tuple = (Exception,)):
        """Retry decorator factory"""
        def decorator(func):
            @functools.wraps(func)
            async def async_wrapper(*args, **kwargs):
                last_exception = None
                current_delay = delay
                
                for attempt in range(max_attempts):
                    try:
                        if asyncio.iscoroutinefunction(func):
                            return await func(*args, **kwargs)
                        else:
                            return func(*args, **kwargs)
                    except exceptions as e:
                        last_exception = e
                        if attempt < max_attempts - 1:
                            logger.warning(f"Attempt {attempt + 1} failed: {e}, retrying in {current_delay}s")
                            await asyncio.sleep(current_delay)
                            current_delay *= backoff
                        else:
                            logger.error(f"All {max_attempts} attempts failed: {e}")
                
                raise last_exception
            
            @functools.wraps(func)
            def sync_wrapper(*args, **kwargs):
                last_exception = None
                current_delay = delay
                
                for attempt in range(max_attempts):
                    try:
                        return func(*args, **kwargs)
                    except exceptions as e:
                        last_exception = e
                        if attempt < max_attempts - 1:
                            logger.warning(f"Attempt {attempt + 1} failed: {e}, retrying in {current_delay}s")
                            time.sleep(current_delay)
                            current_delay *= backoff
                        else:
                            logger.error(f"All {max_attempts} attempts failed: {e}")
                
                raise last_exception
            
            if asyncio.iscoroutinefunction(func):
                return async_wrapper
            else:
                return sync_wrapper
        
        return decorator
    
    def get_health_status(self) -> Dict[str, Dict]:
        """Get health status of all monitored services"""
        status = {}
        with self._lock:
            for service_name, cb in self.circuit_breakers.items():
                status[service_name] = {
                    'state': cb.state.value,
                    'failure_count': cb.failure_count,
                    'last_failure_time': cb.last_failure_time,
                    'has_fallback': service_name in self.fallback_strategies
                }
        return status


class GracefulDegradationManager:
    """Manages graceful degradation when components fail"""
    
    def __init__(self):
        self.degraded_features: set = set()
        self.feature_dependencies: Dict[str, List[str]] = {}
        self._lock = threading.RLock()
    
    def register_feature_dependency(self, feature: str, dependencies: List[str]):
        """Register dependencies for a feature"""
        with self._lock:
            self.feature_dependencies[feature] = dependencies
    
    def mark_feature_degraded(self, feature: str):
        """Mark a feature as degraded"""
        with self._lock:
            self.degraded_features.add(feature)
            logger.warning(f"Feature {feature} marked as degraded")
    
    def restore_feature(self, feature: str):
        """Restore a degraded feature"""
        with self._lock:
            if feature in self.degraded_features:
                self.degraded_features.remove(feature)
                logger.info(f"Feature {feature} restored")
    
    def is_feature_available(self, feature: str) -> bool:
        """Check if a feature is available (not degraded)"""
        with self._lock:
            if feature in self.degraded_features:
                return False
            
            # Check dependencies
            if feature in self.feature_dependencies:
                for dependency in self.feature_dependencies[feature]:
                    if dependency in self.degraded_features:
                        return False
            
            return True
    
    def get_available_features(self) -> List[str]:
        """Get list of currently available features"""
        with self._lock:
            available = []
            for feature in self.feature_dependencies.keys():
                if self.is_feature_available(feature):
                    available.append(feature)
            return available
    
    def get_degradation_status(self) -> Dict[str, Any]:
        """Get current degradation status"""
        with self._lock:
            return {
                'degraded_features': list(self.degraded_features),
                'available_features': self.get_available_features(),
                'total_features': len(self.feature_dependencies),
                'degradation_percentage': len(self.degraded_features) / max(len(self.feature_dependencies), 1) * 100
            }


# Global instances
error_recovery = ErrorRecoveryManager()
degradation_manager = GracefulDegradationManager()

# Convenience functions for easy access
def circuit_breaker(service_name: str, config: Optional[CircuitBreakerConfig] = None) -> CircuitBreaker:
    """Get or create a circuit breaker for a service"""
    return error_recovery.get_circuit_breaker(service_name, config)

def retry_decorator(max_attempts: int = 3, delay: float = 1.0, backoff: float = 2.0, exceptions: tuple = (Exception,)):
    """Decorator for retry logic with exponential backoff"""
    return error_recovery.retry(max_attempts, delay, backoff, exceptions)

# Register feature dependencies during initialization
degradation_manager.register_feature_dependency('traffic_collection', ['nginx_nodes'])
degradation_manager.register_feature_dependency('threat_detection', ['ml_engine', 'traffic_collection'])
degradation_manager.register_feature_dependency('rule_generation', ['threat_detection', 'waf_generator'])
degradation_manager.register_feature_dependency('rule_deployment', ['nginx_manager', 'rule_generation'])
