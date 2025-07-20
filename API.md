# Nginx WAF AI - API Documentation

## Overview

The Nginx WAF AI system provides a comprehensive RESTful API for real-time machine learning-based Web Application Firewall (WAF) rule generation and deployment. This document catalogs all available services and endpoints.

## Base URL
- **Development**: `http://localhost:8000`
- **Production**: `https://your-domain.com` (HTTPS required in production)

## Authentication

The API uses JWT (JSON Web Tokens) for authentication with role-based access control (RBAC).

### Roles
- **Admin**: Full system access, user management, emergency controls
- **Operator**: System operations, processing control, rule deployment
- **Viewer**: Read-only access to system status and data

### Authentication Methods
1. **JWT Token**: Bearer token in Authorization header
2. **API Key**: API key in X-API-Key header (for service-to-service)

---

## Services & Endpoints

### 1. Authentication Service (`/auth`)

#### 1.1 User Login
- **Endpoint**: `POST /auth/login`
- **Authentication**: None (public)
- **Rate Limit**: 5 requests/minute
- **Status**: ✅ **IMPLEMENTED**

**Request Body**:
```json
{
  "username": "string",
  "password": "string"
}
```

**Response**:
```json
{
  "access_token": "string",
  "token_type": "bearer",
  "expires_in": 86400
}
```

**Testing Required**:
- [ ] Valid credentials
- [ ] Invalid credentials
- [ ] Rate limiting enforcement
- [ ] Password strength validation

#### 1.2 Generate API Key
- **Endpoint**: `POST /auth/api-key`
- **Authentication**: Admin role required
- **Rate Limit**: 3 requests/minute
- **Status**: ✅ **IMPLEMENTED**

**Request Body**:
```json
{
  "username": "string"
}
```

**Response**:
```json
{
  "api_key": "string",
  "username": "string",
  "created_at": "2025-01-20T15:30:00"
}
```

**Testing Required**:
- [ ] Admin authentication
- [ ] Non-admin access denial
- [ ] API key generation and validation

#### 1.3 Create User
- **Endpoint**: `POST /auth/users`
- **Authentication**: Admin role required
- **Rate Limit**: 5 requests/minute
- **Status**: ✅ **IMPLEMENTED**

**Request Body**:
```json
{
  "username": "string",
  "password": "string",
  "roles": ["admin", "operator", "viewer"]
}
```

**Testing Required**:
- [ ] User creation with valid roles
- [ ] Password complexity validation
- [ ] Duplicate username handling

#### 1.4 List Users
- **Endpoint**: `GET /auth/users`
- **Authentication**: Admin role required
- **Rate Limit**: 10 requests/minute
- **Status**: ✅ **IMPLEMENTED**

**Testing Required**:
- [ ] User listing with statistics
- [ ] Admin-only access

---

### 2. Security Management Service (`/api/security`)

#### 2.1 Security Statistics
- **Endpoint**: `GET /api/security/stats`
- **Authentication**: Admin role required
- **Rate Limit**: 10 requests/minute
- **Status**: ✅ **IMPLEMENTED**

**Response**:
```json
{
  "timestamp": "2025-01-20T15:30:00",
  "auth_stats": {},
  "system_security": {
    "https_enabled": false,
    "rate_limiting": true,
    "security_headers": true,
    "debug_mode": false
  }
}
```

**Testing Required**:
- [ ] Security statistics accuracy
- [ ] Admin authentication

#### 2.2 Unblock IP Address
- **Endpoint**: `POST /api/security/unblock-ip`
- **Authentication**: Admin role required
- **Rate Limit**: 5 requests/minute
- **Status**: ⚠️ **PARTIAL** - Basic implementation, needs middleware integration

**Request Body**:
```json
{
  "ip_address": "192.168.1.100"
}
```

**Testing Required**:
- [ ] IP address validation
- [ ] Actual unblocking functionality
- [ ] Security middleware integration

#### 2.3 Emergency Shutdown
- **Endpoint**: `POST /api/security/emergency-shutdown`
- **Authentication**: Admin role required
- **Rate Limit**: 1 request/minute
- **Status**: ⚠️ **PARTIAL** - Basic implementation

**Testing Required**:
- [ ] Emergency shutdown execution
- [ ] System state preservation
- [ ] Recovery procedures

---

### 3. Public Endpoints

#### 3.1 Root
- **Endpoint**: `GET /`
- **Authentication**: None
- **Rate Limit**: 30 requests/minute
- **Status**: ✅ **IMPLEMENTED**

#### 3.2 Health Check (Public)
- **Endpoint**: `GET /health`
- **Authentication**: None
- **Rate Limit**: 60 requests/minute
- **Status**: ✅ **IMPLEMENTED**

**Testing Required**:
- [ ] Component status accuracy
- [ ] Response time

#### 3.3 Metrics (Prometheus)
- **Endpoint**: `GET /metrics`
- **Authentication**: Viewer role required
- **Rate Limit**: 30 requests/minute
- **Status**: ✅ **IMPLEMENTED**

**Testing Required**:
- [ ] Prometheus format compliance
- [ ] Metric accuracy
- [ ] Authentication requirement

---

### 4. System Status & Debug Service (`/api`)

#### 4.1 Debug Status
- **Endpoint**: `GET /api/debug/status`
- **Authentication**: Operator role required
- **Rate Limit**: 10 requests/minute
- **Status**: ✅ **IMPLEMENTED**

**Testing Required**:
- [ ] Component status accuracy
- [ ] Debug information completeness

#### 4.2 Test ML Predictions
- **Endpoint**: `POST /api/debug/test-prediction`
- **Authentication**: Operator role required
- **Rate Limit**: 5 requests/minute
- **Status**: ✅ **IMPLEMENTED**

**Testing Required**:
- [ ] ML model response accuracy
- [ ] Test data validation
- [ ] Threat detection thresholds

#### 4.3 System Status
- **Endpoint**: `GET /api/status`
- **Authentication**: Viewer role required
- **Rate Limit**: 10 requests/minute
- **Status**: ✅ **IMPLEMENTED**

**Testing Required**:
- [ ] Real-time status accuracy
- [ ] Component availability

#### 4.4 System Health (Comprehensive)
- **Endpoint**: `GET /api/health`
- **Authentication**: Viewer role required
- **Rate Limit**: 20 requests/minute
- **Status**: ✅ **IMPLEMENTED**

**Response**:
```json
{
  "system_status": "healthy|degraded|critical|failing",
  "health_score": 95.5,
  "processing_state": {},
  "components": {},
  "degradation": {},
  "circuit_breakers": {},
  "error_recovery": {}
}
```

**Testing Required**:
- [ ] Health score calculation
- [ ] Degradation status accuracy
- [ ] Circuit breaker status

#### 4.5 System Statistics
- **Endpoint**: `GET /api/stats`
- **Authentication**: Viewer role required
- **Rate Limit**: 20 requests/minute
- **Status**: ❌ **NOT IMPLEMENTED** - Function body missing

**Issues**:
- Empty function body
- No response structure defined

---

### 5. Node Management Service (`/api/nodes`)

#### 5.1 Add Nginx Node
- **Endpoint**: `POST /api/nodes/add`
- **Authentication**: Admin role required
- **Rate Limit**: 5 requests/minute
- **Status**: ✅ **IMPLEMENTED**

**Request Body**:
```json
{
  "node_id": "string",
  "hostname": "string",
  "ssh_host": "string",
  "ssh_port": 22,
  "ssh_username": "string",
  "ssh_key_path": "string",
  "nginx_config_path": "string",
  "nginx_reload_command": "string",
  "api_endpoint": "string"
}
```

**Testing Required**:
- [ ] Node validation
- [ ] SSH connectivity
- [ ] Nginx configuration access

#### 5.2 List Nginx Nodes
- **Endpoint**: `GET /api/nodes`
- **Authentication**: Viewer role required
- **Rate Limit**: 20 requests/minute
- **Status**: ✅ **IMPLEMENTED**

**Testing Required**:
- [ ] Node listing accuracy
- [ ] Node status information

#### 5.3 Node Cluster Status
- **Endpoint**: `GET /api/nodes/status`
- **Authentication**: Viewer role required
- **Rate Limit**: 20 requests/minute
- **Status**: ✅ **IMPLEMENTED**

**Testing Required**:
- [ ] Cluster health monitoring
- [ ] Individual node status
- [ ] Network connectivity checks

---

### 6. Machine Learning Service (`/api/training`)

#### 6.1 Start Training
- **Endpoint**: `POST /api/training/start`
- **Authentication**: Operator role required
- **Rate Limit**: 3 requests/minute
- **Status**: ✅ **IMPLEMENTED**

**Request Body**:
```json
{
  "training_data": [
    {
      "url_length": 30,
      "body_length": 0,
      "headers_count": 5,
      "content_length": 0,
      "has_suspicious_headers": false,
      "contains_sql_patterns": true,
      "contains_xss_patterns": false,
      "method": "GET",
      "timestamp": "2025-01-20T15:30:00",
      "source_ip": "192.168.1.100",
      "user_agent": "Mozilla/5.0..."
    }
  ],
  "labels": ["sql_injection", "normal", "xss_attack"]
}
```

**Testing Required**:
- [ ] Training data validation
- [ ] Model training completion
- [ ] Model persistence

---

### 7. Traffic Collection Service (`/api/traffic`)

#### 7.1 Start Traffic Collection
- **Endpoint**: `POST /api/traffic/start-collection`
- **Authentication**: Operator role required
- **Rate Limit**: 5 requests/minute
- **Status**: ✅ **IMPLEMENTED**

**Request Body**:
```json
{
  "node_urls": ["http://nginx-node-1", "http://nginx-node-2"]
}
```

**Testing Required**:
- [ ] Node URL validation
- [ ] Traffic collection start
- [ ] Background task management

#### 7.2 Traffic Statistics
- **Endpoint**: `GET /api/traffic/stats`
- **Authentication**: Viewer role required
- **Rate Limit**: 30 requests/minute
- **Status**: ✅ **IMPLEMENTED**

**Testing Required**:
- [ ] Traffic statistics accuracy
- [ ] Collection status monitoring

---

### 8. Real-time Processing Service (`/api/processing`)

#### 8.1 Start Real-time Processing
- **Endpoint**: `POST /api/processing/start`
- **Authentication**: Operator role required
- **Rate Limit**: 3 requests/minute
- **Status**: ✅ **IMPLEMENTED**

**Testing Required**:
- [ ] Processing prerequisite validation
- [ ] Background task creation
- [ ] Thread safety

#### 8.2 Stop Real-time Processing
- **Endpoint**: `POST /api/processing/stop`
- **Authentication**: Operator role required
- **Rate Limit**: 5 requests/minute
- **Status**: ❌ **NOT IMPLEMENTED** - Function body missing

**Issues**:
- Empty function body
- No graceful shutdown logic

---

### 9. Threat Detection Service (`/api/threats`)

#### 9.1 Get Recent Threats
- **Endpoint**: `GET /api/threats`
- **Authentication**: Viewer role required
- **Rate Limit**: 20 requests/minute
- **Status**: ✅ **IMPLEMENTED**

**Response**:
```json
{
  "threats": [],
  "total_threats": 0,
  "threat_patterns": {}
}
```

**Testing Required**:
- [ ] Threat data accuracy
- [ ] Real-time threat updates
- [ ] Pattern analysis

---

### 10. WAF Rules Service (`/api/rules`)

#### 10.1 Get Active Rules
- **Endpoint**: `GET /api/rules`
- **Authentication**: Viewer role required
- **Rate Limit**: 20 requests/minute
- **Status**: ✅ **IMPLEMENTED**

**Testing Required**:
- [ ] Active rules listing
- [ ] Rule metadata accuracy

#### 10.2 Deploy Rules
- **Endpoint**: `POST /api/rules/deploy`
- **Authentication**: Admin role required
- **Rate Limit**: 3 requests/minute
- **Status**: ⚠️ **PARTIAL** - Some deployment logic incomplete

**Request Body**:
```json
{
  "node_ids": ["node_1", "node_2"],
  "force_deployment": false
}
```

**Issues**:
- Incomplete deployment result handling
- Error recovery mechanisms

**Testing Required**:
- [ ] Rule deployment to nodes
- [ ] Nginx configuration validation
- [ ] Rollback mechanisms

---

### 11. Configuration Service (`/api/config`)

#### 11.1 Get Nginx Configuration
- **Endpoint**: `GET /api/config/nginx`
- **Authentication**: Operator role required
- **Rate Limit**: 10 requests/minute
- **Status**: ⚠️ **PARTIAL** - Missing error handling

**Issues**:
- Incomplete error handling in function

**Testing Required**:
- [ ] Configuration generation
- [ ] Rule integration
- [ ] Nginx syntax validation

---

## Testing Priority Matrix

### High Priority (Critical Functionality)
1. **Authentication endpoints** - Core security
2. **Real-time processing start/stop** - Core functionality
3. **Rule deployment** - Main business logic
4. **System health monitoring** - Operations

### Medium Priority (Important Features)
1. **Traffic collection** - Data pipeline
2. **ML training** - Model management
3. **Node management** - Infrastructure
4. **Threat detection** - Security monitoring

### Low Priority (Supporting Features)
1. **Debug endpoints** - Development tools
2. **Statistics endpoints** - Monitoring
3. **Security management** - Administrative

---

## Implementation Status Summary

| Service | Endpoints | Implemented | Partial | Missing | Total |
|---------|-----------|-------------|---------|---------|-------|
| Authentication | 4 | 4 | 0 | 0 | 4 |
| Security | 3 | 1 | 2 | 0 | 3 |
| Public | 3 | 3 | 0 | 0 | 3 |
| System/Debug | 5 | 4 | 0 | 1 | 5 |
| Nodes | 3 | 3 | 0 | 0 | 3 |
| ML Training | 1 | 1 | 0 | 0 | 1 |
| Traffic | 2 | 2 | 0 | 0 | 2 |
| Processing | 2 | 1 | 0 | 1 | 2 |
| Threats | 1 | 1 | 0 | 0 | 1 |
| Rules | 2 | 1 | 1 | 0 | 2 |
| Config | 1 | 0 | 1 | 0 | 1 |
| **TOTAL** | **27** | **21** | **4** | **2** | **27** |

**Implementation Rate**: 77.8% Complete, 14.8% Partial, 7.4% Missing

---

## Next Steps

1. **Complete missing implementations**:
   - `/api/stats` endpoint
   - `/api/processing/stop` endpoint

2. **Fix partial implementations**:
   - Security middleware integration
   - Rule deployment error handling
   - Nginx configuration error handling

3. **Comprehensive testing**:
   - Authentication and authorization
   - Error handling and edge cases
   - Performance and load testing
   - Security vulnerability assessment

4. **Documentation updates**:
   - OpenAPI/Swagger specification
   - Postman collection
   - Integration examples
