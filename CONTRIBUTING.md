# Contributing to Nginx WAF AI

Thank you for your interest in contributing to Nginx WAF AI! This document provides guidelines for contributing to the project.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Environment Setup](#development-environment-setup)
- [How to Contribute](#how-to-contribute)
- [Coding Standards](#coding-standards)
- [Testing Requirements](#testing-requirements)
- [Pull Request Process](#pull-request-process)
- [Reporting Bugs](#reporting-bugs)
- [Suggesting Enhancements](#suggesting-enhancements)

## Code of Conduct

This project adheres to the Contributor Covenant [Code of Conduct](CODE_OF_CONDUCT.md). By participating, you are expected to uphold this code. Please report unacceptable behavior to fabrizio.salmi@gmail.com.

## Getting Started

1. **Fork the Repository**
   ```bash
   git clone https://github.com/fabriziosalmi/nginx-waf-ai.git
   cd nginx-waf-ai
   ```

2. **Create a Feature Branch**
   ```bash
   git checkout -b feature/your-feature-name
   ```

   Branch naming conventions:
   - `feature/` - New features
   - `fix/` - Bug fixes
   - `docs/` - Documentation updates
   - `refactor/` - Code refactoring
   - `test/` - Test additions or updates

## Development Environment Setup

1. **Python Environment**
   ```bash
   # Create virtual environment
   python -m venv .venv
   source .venv/bin/activate  # On Windows: .venv\Scripts\activate
   
   # Install dependencies
   pip install -r requirements.txt
   pip install -r test-requirements.txt
   ```

2. **Pre-commit Hooks** (Optional but recommended)
   ```bash
   pip install pre-commit
   pre-commit install
   ```

3. **Configuration**
   ```bash
   # Copy example configuration
   cp .env.example .env
   # Edit .env with your settings
   ```

## How to Contribute

### Areas for Contribution

| Area | Description | Difficulty |
|------|-------------|------------|
| 🧠 **ML Models** | Improve threat detection algorithms | Advanced |
| 🌐 **API Features** | Add new endpoints and functionality | Medium |
| 📊 **Monitoring** | Enhanced dashboards and metrics | Medium |
| 🐳 **DevOps** | CI/CD, Docker, deployment | Medium |
| 📚 **Documentation** | Improve guides and examples | Beginner |
| 🧪 **Testing** | Add test coverage | Beginner-Medium |

### Types of Contributions

- **Bug Fixes**: Fix reported issues
- **New Features**: Implement new functionality
- **Documentation**: Improve or add documentation
- **Tests**: Add or improve test coverage
- **Performance**: Optimize existing code
- **Security**: Address security vulnerabilities

## Coding Standards

### Python Style Guide

- **Code Formatter**: Use [Black](https://github.com/psf/black) for code formatting
  ```bash
  black src/ tests/ cli.py
  ```

- **Linting**: Use flake8 for code quality
  ```bash
  flake8 src/ tests/ --max-line-length=88
  ```

- **Type Hints**: Add type hints to all new functions
  ```python
  def process_request(request: Dict[str, Any]) -> ThreatPrediction:
      ...
  ```

- **Import Sorting**: Use isort for import organization
  ```bash
  isort src/ tests/ cli.py
  ```

### Code Quality Checklist

- [ ] Code follows PEP 8 style guidelines
- [ ] All functions have docstrings
- [ ] Type hints are added for function parameters and returns
- [ ] Code is formatted with Black
- [ ] No linting errors from flake8
- [ ] No type errors from mypy (if applicable)

### Documentation Standards

- **Docstrings**: Use Google-style docstrings
  ```python
  def train_model(data: List[Dict], labels: List[str]) -> None:
      """Train the machine learning model.
      
      Args:
          data: List of feature dictionaries
          labels: List of corresponding labels
          
      Returns:
          None
          
      Raises:
          ValueError: If data is empty or invalid
      """
  ```

- **Comments**: Add comments for complex logic
- **README Updates**: Update README.md when adding features
- **API Documentation**: Update API.md for new endpoints

## Testing Requirements

### Running Tests

```bash
# Run all tests
pytest tests/ -v

# Run with coverage
pytest tests/ --cov=src --cov-report=html --cov-report=term-missing

# Run specific test file
pytest tests/test_ml_engine.py -v

# Run specific test
pytest tests/test_ml_engine.py::test_threat_detection -v
```

### Test Coverage Requirements

- **Minimum Coverage**: 80% for new code
- **Unit Tests**: Required for all new functions
- **Integration Tests**: Required for API endpoints
- **Documentation Tests**: Update tests/README.md if adding test utilities

### Writing Tests

```python
import pytest
from src.ml_engine import MLEngine

def test_ml_engine_initialization():
    """Test ML engine initializes correctly"""
    engine = MLEngine()
    assert engine is not None
    assert not engine.is_trained

@pytest.mark.asyncio
async def test_api_endpoint():
    """Test API endpoint behavior"""
    # Test implementation
    pass
```

## Pull Request Process

### Before Submitting

1. **Update Documentation**: Ensure README.md and other docs reflect your changes
2. **Add Tests**: Include tests for new functionality
3. **Run Tests**: Ensure all tests pass
4. **Code Quality**: Run linting and formatting tools
5. **Commit Messages**: Use clear, descriptive commit messages

### Commit Message Format

Use conventional commits format:

```
<type>(<scope>): <subject>

<body>

<footer>
```

Types:
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Code style changes (formatting)
- `refactor`: Code refactoring
- `test`: Test additions or changes
- `chore`: Build process or auxiliary tool changes

Examples:
```
feat(ml-engine): add support for new threat types

Implements detection for CSRF and file inclusion attacks.
Includes training data and test cases.

Closes #123
```

```
fix(api): correct authentication token validation

Previous implementation allowed expired tokens.
Now properly validates token expiration time.
```

### Pull Request Template

When submitting a PR, include:

```markdown
## Description
Brief description of the changes

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Documentation update
- [ ] Performance improvement
- [ ] Code refactoring

## Testing
- [ ] Unit tests pass
- [ ] Integration tests pass
- [ ] Manual testing completed

## Checklist
- [ ] Code follows project style guidelines
- [ ] Self-review completed
- [ ] Comments added for complex code
- [ ] Documentation updated
- [ ] No new warnings generated
- [ ] Tests added for new functionality
- [ ] All tests pass locally

## Related Issues
Closes #(issue number)
```

### Review Process

1. **Automated Checks**: CI/CD pipeline must pass
2. **Code Review**: At least one maintainer approval required
3. **Testing**: All tests must pass
4. **Documentation**: Documentation must be updated
5. **Merge**: Squash and merge after approval

## Reporting Bugs

### Before Reporting

1. **Search Existing Issues**: Check if the bug is already reported
2. **Verify**: Ensure it's actually a bug and not a feature
3. **Test**: Try to reproduce on the latest version

### Bug Report Template

```markdown
## Bug Description
A clear description of the bug

## Steps to Reproduce
1. Step one
2. Step two
3. Step three

## Expected Behavior
What should have happened

## Actual Behavior
What actually happened

## Environment
- OS: [e.g., Ubuntu 22.04]
- Python version: [e.g., 3.9.7]
- Docker version: [e.g., 20.10.8]
- WAF AI version: [e.g., 0.1.0]

## Logs
```
Include relevant log excerpts
```

## Additional Context
Any other information that might be helpful
```

## Suggesting Enhancements

### Enhancement Proposal Template

```markdown
## Feature Description
Clear description of the proposed feature

## Use Case
Why is this feature needed? What problem does it solve?

## Proposed Implementation
High-level implementation approach (if you have ideas)

## Alternatives Considered
Other approaches you've considered

## Additional Context
Screenshots, mockups, or other helpful information
```

## Getting Help

- **GitHub Discussions**: Ask questions and discuss ideas
- **GitHub Issues**: Report bugs and request features
- **Documentation**: Check the comprehensive guides in README.md and API.md
- **Email**: Contact maintainers at fabrizio.salmi@gmail.com

## Recognition

Contributors are recognized in:
- GitHub Contributors Graph
- Release notes for significant contributions
- CONTRIBUTORS.md file (if applicable)

## License

By contributing, you agree that your contributions will be licensed under the project's MIT License.

---

Thank you for contributing to Nginx WAF AI! Your efforts help make web applications more secure. 🛡️
