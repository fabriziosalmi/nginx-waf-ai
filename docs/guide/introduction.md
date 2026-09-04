# Introduction to Nginx WAF AI

**Nginx WAF AI** is an intelligent security layer for Nginx that analyzes HTTP traffic patterns in real-time, detects anomalies and threats using machine learning (Isolation Forest and Random Forest), and automatically generates and deploys protective WAF rules.

The system provides a RESTful FastAPI backend, a web-based control panel, Prometheus metrics integration, and automated SSH-based rule synchronization with rollback capabilities.

---

## 🚀 Key Features

- **Traffic Analysis**: Real-time collection and parsing of HTTP request data from multiple Nginx ingress nodes.
- **Machine Learning Detection**: Dual-model architecture featuring Scikit-Learn Isolation Forest (unsupervised anomaly detection) and Random Forest (supervised classification).
- **Automated Rule Generation**: Dynamic generation of Nginx `deny`/`allow` directives based on threat classification confidence.
- **Fleet Management**: Centralized deployment across Nginx nodes over SSH with automated configuration validation and rollback.
- **RESTful API**: Fast and modular FastAPI server with JWT authentication and granular role-based access controls.
- **Web Control Panel**: Responsive dashboard for monitoring live traffic, reviewing detected threats, and managing rules.
- **Observability**: Built-in Prometheus `/metrics` endpoint with ready-to-use Grafana and Loki monitoring configurations.

---

## 🏗️ Architecture Overview

```
[Nginx Nodes] ──(Traffic Logs)──> [Traffic Collector]
                                          │
                                          ▼
                                   [ML Engine (RF/IF)]
                                          │
                                          ▼
                                   [Rule Generator]
                                          │
                                 (FastAPI Server)
                                    /         \
                             [Control Panel]  [Prometheus]
                                    \         /
                                   [Nginx Fleet (SSH Deploy)]
```

---

## 🧭 Documentation Map

- [Quick Start Guide](/guide/quickstart): Get up and running in under 5 minutes with Docker Compose.
- [Production Deployment](/guide/production): Hardening, TLS, multi-node configuration, and environment setup.
- [REST API Reference](/guide/api): Complete endpoint documentation and status audit.
- [Documentation Audit](/guide/audit): Current implementation matrix and roadmap.
- [Changelog](/guide/changelog): Version release notes.
