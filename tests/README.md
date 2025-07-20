# WAF AI Test Suite

This directory contains comprehensive tests for the Nginx WAF AI system. The test suite is designed to verify all components work correctly both individually and together.

## Test Structure

```
tests/
├── test_api_integration.py      # API endpoint integration tests
├── test_auth.py                 # Authentication and authorization tests
├── test_waf_rule_generator.py   # WAF rule generation tests
├── test_nginx_manager.py        # Nginx node management tests
├── test_e2e_integration.py      # End-to-end Docker Compose tests
├── test_performance.py          # Performance and load tests
├── test_ml_engine.py           # ML engine unit tests (existing)
├── test_traffic_collector.py   # Traffic collector tests (existing)
├── conftest.py                 # Shared test fixtures and utilities
└── README.md                   # This file
```

## Test Categories

Tests are organized using pytest markers:

- **`unit`**: Fast, isolated unit tests for individual components
- **`integration`**: Tests that verify component interactions
- **`api`**: API endpoint tests (subset of integration tests)
- **`e2e`**: End-to-end tests using Docker Compose
- **`performance`**: Load and performance tests
- **`security`**: Security-focused tests (auth, RBAC, etc.)
- **`slow`**: Tests that take more than 5 seconds

## Quick Start

### 1. Install Test Dependencies

```bash
# Install all test dependencies
pip install -r test-requirements.txt

# Or install manually
pip install pytest pytest-asyncio pytest-cov httpx requests passlib psutil paramiko
```

### 2. Run Tests

```bash
# Run all unit tests (fastest)
python simple_test_runner.py --suite unit

# Run API tests
python simple_test_runner.py --suite api --verbose

# Run all tests with coverage
python simple_test_runner.py --suite all --coverage

# Run specific test file
pytest tests/test_api_integration.py -v

# Run tests by marker
pytest -m "unit and not slow" -v
```

### 3. Docker Compose Tests

For end-to-end tests that require the full stack:

```bash
# Start required services
docker-compose up -d redis

# Run e2e tests
python simple_test_runner.py --suite e2e

# Cleanup
docker-compose down
```

## Test Configuration

### pytest.ini

The project includes a `pytest.ini` file with:
- Coverage configuration (80% minimum)
- Test markers definitions
- Output formatting
- Logging configuration

### Environment Variables

Tests respect these environment variables:

```bash
# API testing
export WAF_API_BASE_URL="http://localhost:8000"
export WAF_API_KEY="your-test-api-key"

# Redis connection
export REDIS_URL="redis://localhost:6379"

# Test mode (skips external dependencies)
export PYTEST_CURRENT_TEST="true"
```

## Test Files Overview

### test_api_integration.py
- Tests all API endpoints defined in API.md
- Covers authentication, RBAC, and error handling
- Includes positive and negative test cases
- Tests request/response formats and validation

### test_auth.py
- Password hashing and verification
- JWT token generation and validation
- Role-based access control (RBAC)
- User creation and management
- Session handling

### test_waf_rule_generator.py
- ML predictions to WAF rules conversion
- Rule deduplication and optimization
- Configuration file generation
- Rule lifecycle management (add/remove)

### test_nginx_manager.py
- Nginx node management (add/remove/list)
- SSH and API-based deployment
- Health checks and status monitoring
- Configuration rollback functionality

### test_e2e_integration.py
- Full Docker Compose stack testing
- Service integration and communication
- End-to-end workflow validation
- Monitoring and logging verification
- Security and compliance checks

### test_performance.py
- API endpoint response times
- Concurrent request handling
- Memory and CPU usage
- Scalability testing
- Load testing scenarios

## CI/CD Integration

### GitHub Actions

The project includes `.github/workflows/test.yml` for automated testing:

- Runs on Python 3.9, 3.10, 3.11
- Tests against Redis service
- Generates coverage reports
- Uploads to Codecov
- Includes Docker integration tests

### Running in CI

```yaml
- name: Run tests
  run: |
    pytest tests/ -m "unit" --cov=src --cov-report=xml
    pytest tests/ -m "integration" --cov=src --cov-append --cov-report=xml
```

## Common Test Patterns

### Async Tests

```python
import pytest
import httpx

@pytest.mark.asyncio
async def test_async_endpoint():
    async with httpx.AsyncClient() as client:
        response = await client.get("http://localhost:8000/api/health")
        assert response.status_code == 200
```

### Mocking External Services

```python
from unittest.mock import patch, MagicMock

@patch('src.nginx_manager.SSHClient')
def test_nginx_deployment(mock_ssh):
    mock_ssh.return_value.exec_command.return_value = (None, MagicMock(), None)
    # Test implementation
```

### Parameterized Tests

```python
@pytest.mark.parametrize("user_role,expected_status", [
    ("admin", 200),
    ("user", 403),
    ("guest", 401)
])
def test_role_based_access(user_role, expected_status):
    # Test implementation
```

## Troubleshooting

### Common Issues

1. **Missing Dependencies**
   ```bash
   pip install -r test-requirements.txt
   ```

2. **Redis Connection Failed**
   ```bash
   docker-compose up -d redis
   # Or use local Redis
   redis-server
   ```

3. **Permission Errors (SSH tests)**
   ```bash
   # Ensure SSH key access or mock SSH in tests
   export SKIP_SSH_TESTS=true
   ```

4. **Import Errors**
   ```bash
   # Ensure PYTHONPATH includes src/
   export PYTHONPATH="${PYTHONPATH}:$(pwd)/src"
   ```

### Debug Mode

```bash
# Run with debug output
pytest tests/ -v --tb=long --capture=no

# Run specific test with pdb
pytest tests/test_api_integration.py::test_health_endpoint -v -s --pdb
```

### Coverage Reports

```bash
# Generate HTML coverage report
pytest --cov=src --cov-report=html

# View in browser
open htmlcov/index.html
```

## Contributing

### Adding New Tests

1. Follow the existing naming convention: `test_*.py`
2. Use appropriate markers (`@pytest.mark.unit`, etc.)
3. Add docstrings explaining test purpose
4. Include both positive and negative test cases
5. Mock external dependencies
6. Add test to appropriate CI workflow

### Test Fixtures

Common fixtures are defined in `conftest.py`:

```python
@pytest.fixture
def api_client():
    """HTTP client for API testing"""
    return httpx.Client(base_url="http://localhost:8000")

@pytest.fixture
def admin_token():
    """JWT token for admin user"""
    return create_test_token(role="admin")
```

### Best Practices

- Keep tests independent and isolated
- Use descriptive test names
- Test edge cases and error conditions
- Mock external services and databases
- Use fixtures for common setup
- Keep tests fast (< 1 second for unit tests)
- Add comments for complex test logic

## Performance Benchmarks

Expected test performance:

- Unit tests: < 1 second each
- Integration tests: < 5 seconds each
- E2E tests: < 30 seconds each
- Full test suite: < 5 minutes

## Support

For test-related questions:

1. Check this README
2. Review existing test files for patterns
3. Check CI logs for detailed error messages
4. Run tests locally with verbose output
5. Use pytest debugging features (`--pdb`)

---

**Note**: Always run the test suite before submitting changes to ensure nothing is broken!
