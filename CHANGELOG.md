# Changelog

All notable changes to the Nginx WAF AI project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Comprehensive documentation improvements
- CONTRIBUTING.md with development guidelines
- CHANGELOG.md for tracking project changes
- Improved .gitignore with Python-specific patterns

### Changed
- Corrected CLI command documentation to match actual implementation
- Fixed environment variable names in documentation
- Updated port numbers (Grafana: 3000 → 3080)
- Corrected credentials documentation

### Fixed
- Broken configuration file path references
- Inconsistent environment variable prefixes
- Missing example configuration files

## [0.1.0] - Initial Release

### Added
- Real-time traffic analysis from nginx nodes
- Machine learning-based threat detection using Isolation Forest and Random Forest
- Automated WAF rule generation for nginx
- Multi-node nginx cluster management
- FastAPI-based REST API with JWT authentication
- Role-based access control (Admin, Operator, Viewer)
- Docker Compose deployment configuration
- Web-based control panel for system management
- Prometheus metrics integration
- Grafana dashboard for visualization
- Loki for log aggregation
- CLI tools for system management
- Comprehensive test suite
- Security middleware with rate limiting
- Error handling and circuit breaker patterns
- Real-time WebSocket support for live monitoring

### Features
- **Traffic Collection**: Collects HTTP requests from nginx access logs or APIs
- **ML Engine**: Dual-model architecture for anomaly detection and classification
- **WAF Rules**: Generates nginx-compatible WAF rules from ML predictions
- **Nginx Management**: SSH and API-based deployment to multiple nginx nodes
- **Monitoring**: Complete observability stack with Prometheus, Grafana, and Loki
- **Security**: JWT authentication, RBAC, rate limiting, CORS protection

### Known Issues
- `/auth/login` endpoint currently commented out (use default credentials)
- `/auth/api-key` endpoint not fully implemented
- Some partial implementations in security endpoints

---

## Version History

### Versioning Scheme
- **Major version (X.0.0)**: Breaking changes or major feature additions
- **Minor version (0.X.0)**: New features, backwards compatible
- **Patch version (0.0.X)**: Bug fixes and minor improvements

### Release Timeline
- **v0.1.0**: Initial release with core functionality

---

## How to Contribute

See [CONTRIBUTING.md](CONTRIBUTING.md) for details on how to contribute to this project.

## Support

For issues or questions:
- GitHub Issues: Report bugs or request features
- GitHub Discussions: Ask questions and share ideas
- Email: fabrizio.salmi@gmail.com
