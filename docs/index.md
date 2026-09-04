---
layout: home
title: Nginx WAF AI — Machine Learning Web Application Firewall
titleTemplate: false

hero:
  name: "Nginx WAF AI"
  text: "Machine learning WAF for Nginx traffic protection."
  tagline: "Automated HTTP threat detection, dynamic rule generation, and fleet deployment powered by FastAPI and Scikit-Learn models."
  actions:
    - theme: brand
      text: Get Started
      link: /guide/introduction
    - theme: alt
      text: Quick Start (Docker)
      link: /guide/quickstart
    - theme: alt
      text: REST API Reference
      link: /guide/api

features:
  - icon: 🧠
    title: Dual ML Detection
    details: Combines Isolation Forest for zero-day anomaly detection with Random Forest for supervised threat classification.
  - icon: ⚡
    title: Dynamic Rule Generation
    details: Automatically converts ML threat vectors into native Nginx deny/allow rules without manual intervention.
  - icon: 🔄
    title: Fleet Deployment & Rollback
    details: Deploys WAF configuration across multiple Nginx nodes via SSH with instant automatic rollback on syntax error.
  - icon: 🛡️
    title: FastAPI & JWT Auth
    details: High-throughput async REST API with role-based access control and security-hardened middleware.
  - icon: 📊
    title: Prometheus Metrics
    details: Native observability with Prometheus metrics exporter, ready for Grafana and Loki dashboards.
  - icon: 🎛️
    title: Control Panel UI
    details: Single-page web dashboard to visualize real-time traffic, threat alerts, and rule activation states.
---
