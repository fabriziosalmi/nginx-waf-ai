<!-- Use this file to provide workspace-specific custom instructions to Copilot. For more details, visit https://code.visualstudio.com/docs/copilot/copilot-customization#_use-a-githubcopilotinstructionsmd-file -->

# Nginx WAF AI Project Instructions

This project implements a real-time machine learning system for nginx Web Application Firewall (WAF) rule generation and deployment.

## Project Structure

- `src/traffic_collector.py` - HTTP traffic collection and preprocessing
- `src/ml_engine.py` - Machine learning models for threat detection
- `src/waf_rule_generator.py` - WAF rule generation from ML predictions
- `src/nginx_manager.py` - Nginx configuration management and deployment
- `src/main.py` - FastAPI-based API server
- `src/config.py` - Configuration management
- `cli.py` - Command-line interface

## Key Components

1. **Traffic Collection**: Collects HTTP requests from multiple nginx nodes
2. **ML Engine**: Real-time threat detection using anomaly detection and classification
3. **Rule Generation**: Converts ML predictions into nginx WAF rules
4. **Deployment**: Distributes rules to nginx nodes via SSH or API

## Development Guidelines

- Use async/await for I/O operations
- Implement proper error handling and logging
- Follow dataclass patterns for data structures
- Use type hints throughout the codebase
- Maintain separation of concerns between components

## ML Features

The system extracts these features from HTTP requests:
- URL length and patterns
- HTTP method
- Request body characteristics
- Header analysis
- Time-based features
- Suspicious pattern detection (SQL injection, XSS)

## Security Considerations

- Use SSH key-based authentication for nginx node access
- Implement rate limiting for API endpoints
- Validate all input data
- Use secure defaults for configuration
- Log security events appropriately

When working on this project:
- Consider the real-time nature of the system
- Think about scalability and performance
- Implement proper monitoring and alerting
- Use defensive programming practices
- Consider nginx reload impact on live traffic
