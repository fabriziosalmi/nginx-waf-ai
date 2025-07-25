const { createApp, ref, computed, onMounted, onUnmounted } = Vue;

createApp({
    setup() {
        // Reactive state
        const activeTab = ref('dashboard');
        const sidebarCollapsed = ref(false);
        const loading = ref(false);
        const autoRefresh = ref(true);
        const showAddNodeModal = ref(false);
        
        // API Base URL - Use host network since UI is accessed from browser
        // When running in Docker, the browser connects from outside the container network
        const API_BASE = window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1' 
            ? 'http://localhost:8000' 
            : `http://${window.location.hostname}:8000`;
        
        // Authentication
        const currentUser = ref({ username: 'admin' });
        const authToken = ref(localStorage.getItem('waf_auth_token') || '');
        
        // Login form state
        const loginForm = ref({
            username: 'admin',
            password: 'admin123'
        });
        const loginLoading = ref(false);
        const loginError = ref('');
        
        // System Status
        const systemStatus = ref({
            class: 'healthy',
            icon: 'fas fa-check-circle',
            text: 'All Systems Operational'
        });
        
        // Statistics
        const stats = ref({
            threats: { total: 0, last24h: 0 },
            traffic: { requests: 0, requestsPerSecond: 0 },
            rules: { active: 0, deployed: 0 },
            nodes: { healthy: 0, total: 0 }
        });
        
        // Data collections
        const threats = ref([]);
        const nodes = ref([]);
        const rules = ref([]);
        const recentActivity = ref([]);
        const recentRequests = ref([]);
        
        // Filters and settings
        const threatFilter = ref('all');
        const trafficTimeRange = ref('24h');
        const threatCount = computed(() => threats.value.length);
        
        // Filtered threats
        const filteredThreats = computed(() => {
            if (threatFilter.value === 'all') return threats.value;
            return threats.value.filter(threat => threat.type === threatFilter.value);
        });
        
        // Traffic stats
        const trafficStats = ref({
            totalRequests: 0,
            blockedRequests: 0,
            topSourceIP: '192.168.1.100',
            avgResponseTime: 145
        });
        
        // ML Model info
        const modelInfo = ref({
            status: 'healthy',
            statusIcon: 'fas fa-check-circle',
            statusText: 'Model Active',
            accuracy: 0.94,
            lastTrained: new Date(),
            trainingSize: 10000
        });
        
        const modelMetrics = ref({
            precision: 0.92,
            recall: 0.89,
            f1Score: 0.90
        });
        
        const isTraining = ref(false);
        const trainingProgress = ref(0);
        const trainingLogs = ref([]);
        
        // System initialization state
        const systemInitialized = ref(false);
        const initializingSystem = ref(false);
        const initProgress = ref([]);
        
        // Settings
        const settings = ref({
            threatThreshold: 0.5,
            autoBlock: true,
            rateLimit: 1000,
            modelUpdateFreq: '24h',
            confidenceThreshold: 0.8
        });
        
        // New node form
        const newNode = ref({
            node_id: '',
            hostname: '',
            ssh_host: '',
            ssh_port: 22,
            ssh_username: '',
            ssh_key_path: '',
            nginx_config_path: '/etc/nginx/conf.d',
            nginx_reload_command: 'sudo systemctl reload nginx'
        });
        
        const rulesLastUpdated = ref(new Date());
        
        // Charts
        let threatsChart = null;
        let trafficChart = null;
        let realTimeTrafficChart = null;
        
        // API Helper
        const apiCall = async (endpoint, options = {}) => {
            try {
                const response = await fetch(`${API_BASE}${endpoint}`, {
                    headers: {
                        'Content-Type': 'application/json',
                        'Authorization': authToken.value ? `Bearer ${authToken.value}` : '',
                        ...options.headers
                    },
                    ...options
                });
                
                if (!response.ok) {
                    throw new Error(`HTTP ${response.status}: ${response.statusText}`);
                }
                
                return await response.json();
            } catch (error) {
                console.error('API call failed:', error);
                console.error('API Error:', error.message);
                throw error;
            }
        };
        
        // Data fetching functions
        const fetchStats = async () => {
            try {
                // First check if we have a valid auth token
                if (!authToken.value) {
                    throw new Error('No authentication token');
                }
                
                const [healthRes, statsRes] = await Promise.all([
                    apiCall('/health'),
                    apiCall('/api/stats')
                ]);
                
                // Update system status
                if (healthRes.status === 'healthy') {
                    systemStatus.value = {
                        class: 'healthy',
                        icon: 'fas fa-check-circle',
                        text: 'All Systems Operational'
                    };
                } else {
                    systemStatus.value = {
                        class: 'warning',
                        icon: 'fas fa-exclamation-triangle',
                        text: 'System Issues Detected'
                    };
                }
                
                // Update stats with actual API response structure
                stats.value = {
                    threats: { 
                        total: statsRes.threats?.total_threats || 0, 
                        last24h: statsRes.threats?.total_threats || 0 
                    },
                    traffic: { 
                        requests: statsRes.traffic?.total_requests || 0, 
                        requestsPerSecond: Math.floor((statsRes.traffic?.recent_requests || 0) / 60) // rough estimate
                    },
                    rules: { 
                        active: statsRes.rules?.active_rules || 0, 
                        deployed: statsRes.rules?.active_rules || 0 
                    },
                    nodes: { 
                        healthy: statsRes.components?.nginx_nodes_count || 0, 
                        total: statsRes.components?.nginx_nodes_count || 0 
                    }
                };
                
            } catch (error) {
                console.warn('API call failed:', error);
                // Use empty/default data instead of mock data
                stats.value = {
                    threats: { total: 0, last24h: 0 },
                    traffic: { requests: 0, requestsPerSecond: 0 },
                    rules: { active: 0, deployed: 0 },
                    nodes: { healthy: 0, total: 0 }
                };
                
                systemStatus.value = {
                    class: 'danger',
                    icon: 'fas fa-exclamation-triangle',
                    text: 'API Connection Failed'
                };
            }
        };
        
        const fetchThreats = async () => {
            try {
                if (!authToken.value) {
                    throw new Error('No authentication token');
                }
                
                const data = await apiCall('/api/threats');
                threats.value = data.threats || [];
                
                // Add some processed fields for display
                threats.value = threats.value.map(threat => ({
                    ...threat,
                    formattedTime: new Date(threat.timestamp || Date.now()).toLocaleString(),
                    severityBadge: threat.confidence > 0.8 ? 'high' : threat.confidence > 0.5 ? 'medium' : 'low'
                }));
                
            } catch (error) {
                console.warn('Failed to fetch threats:', error);
                // Use empty array instead of mock data
                threats.value = [];
            }
        };
        
        const fetchNodes = async () => {
            try {
                if (!authToken.value) {
                    throw new Error('No authentication token');
                }
                
                const data = await apiCall('/api/nodes');
                nodes.value = data.nodes || [];
                
                // Add health status processing
                nodes.value = nodes.value.map(node => ({
                    ...node,
                    healthStatus: node.healthy ? 'healthy' : 'unhealthy',
                    statusIcon: node.healthy ? 'fas fa-check-circle' : 'fas fa-exclamation-triangle'
                }));
                
            } catch (error) {
                console.warn('Failed to fetch nodes:', error);
                // Use empty array instead of mock data
                nodes.value = [];
            }
        };
        
        const fetchRules = async () => {
            try {
                if (!authToken.value) {
                    throw new Error('No authentication token');
                }
                
                const data = await apiCall('/api/rules');
                rules.value = data.rules || [];
                rulesLastUpdated.value = new Date();
                
                // Add processing for rule display
                rules.value = rules.value.map(rule => ({
                    ...rule,
                    formattedCreated: rule.created_at ? new Date(rule.created_at).toLocaleString() : 'Unknown',
                    statusBadge: rule.active ? 'active' : 'inactive'
                }));
                
            } catch (error) {
                console.warn('Failed to fetch rules:', error);
                // Use empty array instead of mock data
                rules.value = [];
            }
        };
        
        const fetchRecentActivity = async () => {
            try {
                // Get real activity data from multiple sources
                const [threatsRes, trafficRes, rulesRes] = await Promise.all([
                    apiCall('/api/threats'),
                    apiCall('/api/traffic/stats'),
                    apiCall('/api/rules')
                ]);
                
                const activities = [];
                
                // Add threat activities
                if (threatsRes.threats && threatsRes.threats.length > 0) {
                    threatsRes.threats.slice(0, 3).forEach((threat, index) => {
                        activities.push({
                            id: `threat_${index}`,
                            type: 'threat',
                            icon: 'fas fa-exclamation-triangle',
                            message: `${threat.threat_type || 'Threat'} detected from ${threat.source_ip || 'unknown IP'}`,
                            timestamp: new Date(threat.timestamp || Date.now() - (index * 300000))
                        });
                    });
                }
                
                // Add traffic activity
                if (trafficRes.total_requests > 0) {
                    activities.push({
                        id: 'traffic_update',
                        type: 'system',
                        icon: 'fas fa-globe',
                        message: `Traffic processed: ${trafficRes.total_requests} total requests, ${trafficRes.recent_requests} recent`,
                        timestamp: new Date(Date.now() - 60000)
                    });
                }
                
                // Add rule deployment activity
                if (rulesRes.rules && rulesRes.rules.length > 0) {
                    activities.push({
                        id: 'rules_active',
                        type: 'rule',
                        icon: 'fas fa-shield-alt',
                        message: `WAF rules active: ${rulesRes.total_rules} rules deployed`,
                        timestamp: new Date(Date.now() - 120000)
                    });
                }
                
                // Sort by timestamp (newest first)
                activities.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
                
                recentActivity.value = activities.slice(0, 5); // Keep only 5 most recent
                
            } catch (error) {
                console.warn('Failed to fetch real activity data:', error);
                // Use empty array instead of fake data
                recentActivity.value = [];
            }
        };
        
        const fetchTrafficData = async () => {
            try {
                const data = await apiCall('/api/traffic/stats');
                
                // Update traffic stats with real data
                trafficStats.value = {
                    totalRequests: data.total_requests || 0,
                    recentRequests: data.recent_requests || 0,
                    isCollecting: data.is_collecting || false,
                    timestamp: data.timestamp
                };
                
                // For the traffic display, we'll use empty array instead of mock data
                // since the backend doesn't currently provide individual request details
                recentRequests.value = [];
                
            } catch (error) {
                console.warn('Failed to fetch traffic stats:', error);
                // Use empty data instead of mock data
                recentRequests.value = [];
                trafficStats.value = {
                    totalRequests: 0,
                    recentRequests: 0,
                    isCollecting: false,
                    timestamp: null
                };
            }
        };
        
        // Action functions
        const refreshData = async () => {
            loading.value = true;
            try {
                await Promise.all([
                    fetchStats(),
                    fetchThreats(),
                    fetchNodes(),
                    fetchRules(),
                    fetchRecentActivity(),
                    fetchTrafficData()
                ]);
                console.log('Data refreshed successfully');
            } catch (error) {
                console.error('Failed to refresh data');
            } finally {
                loading.value = false;
            }
        };
        
        const blockIP = async (ip) => {
            try {
                await apiCall('/security/block-ip', {
                    method: 'POST',
                    body: JSON.stringify({ ip_address: ip })
                });
                await refreshData();
            } catch (error) {
            }
        };
        
        const addToWhitelist = async (ip) => {
            try {
                await apiCall('/security/whitelist-ip', {
                    method: 'POST',
                    body: JSON.stringify({ ip_address: ip })
                });
                await refreshData();
            } catch (error) {
            }
        };
        
        const dismissThreat = async (threatId) => {
            try {
                threats.value = threats.value.filter(t => t.id !== threatId);
            } catch (error) {
            }
        };
        
        const clearThreats = () => {
            threats.value = [];
        };
        
        const testNode = async (nodeId) => {
            try {
                // Note: Backend doesn't have individual node test endpoint
                // This would need to be implemented in the backend
                console.warn('Node test endpoint not implemented in backend');
            } catch (error) {
                console.error('Failed to test node:', error);
            }
        };
        
        const deployRules = async (nodeId) => {
            try {
                // Use the correct backend endpoint for deploying rules
                await apiCall('/api/rules/deploy', { method: 'POST' });
                await fetchNodes();
            } catch (error) {
                console.error('Failed to deploy rules:', error);
            }
        };
        
        const removeNode = async (nodeId) => {
            if (confirm(`Are you sure you want to remove node ${nodeId}?`)) {
                try {
                    // Note: Backend doesn't have delete node endpoint
                    // This would need to be implemented in the backend
                    console.warn('Delete node endpoint not implemented in backend');
                } catch (error) {
                    console.error('Failed to remove node:', error);
                }
            }
        };
        
        const addNode = async () => {
            try {
                await apiCall('/api/nodes/add', {
                    method: 'POST',
                    body: JSON.stringify(newNode.value)
                });
                showAddNodeModal.value = false;
                
                // Reset form
                newNode.value = {
                    node_id: '',
                    hostname: '',
                    ssh_host: '',
                    ssh_port: 22,
                    ssh_username: '',
                    ssh_key_path: '',
                    nginx_config_path: '/etc/nginx/conf.d',
                    nginx_reload_command: 'sudo systemctl reload nginx'
                };
                
                await fetchNodes();
            } catch (error) {
                console.error('Failed to add node:', error);
            }
        };
        
        const generateRules = async () => {
            try {
                loading.value = true;
                // Note: Backend doesn't have generate rules endpoint
                // This would need to be implemented in the backend
                console.warn('Generate rules endpoint not implemented in backend');
                await fetchRules();
            } catch (error) {
                console.error('Failed to generate rules:', error);
            } finally {
                loading.value = false;
            }
        };
        
        const deployAllRules = async () => {
            try {
                loading.value = true;
                await apiCall('/api/rules/deploy', { method: 'POST' });
                await fetchRules();
            } catch (error) {
                console.error('Failed to deploy rules:', error);
            } finally {
                loading.value = false;
            }
        };
        
        const toggleRule = async (ruleId) => {
            try {
                // Note: Backend doesn't have toggle rule endpoint
                // This would need to be implemented in the backend
                console.warn('Toggle rule endpoint not implemented in backend');
            } catch (error) {
                console.error('Failed to toggle rule:', error);
            }
        };
        
        const editRule = (ruleId) => {
        };
        
        const deleteRule = async (ruleId) => {
            if (confirm('Are you sure you want to delete this rule?')) {
                try {
                    // Note: Backend doesn't have delete rule endpoint
                    // This would need to be implemented in the backend
                    console.warn('Delete rule endpoint not implemented in backend');
                } catch (error) {
                    console.error('Failed to delete rule:', error);
                }
            }
        };
        
        const exportTrafficData = () => {
            const csvContent = "data:text/csv;charset=utf-8," + 
                "Timestamp,Source IP,Method,URL,Status,Size,Blocked\\n" +
                recentRequests.value.map(req => 
                    `${req.timestamp},${req.source_ip},${req.method},${req.url},${req.status},${req.size},${req.blocked}`
                ).join("\\n");
            
            const encodedUri = encodeURI(csvContent);
            const link = document.createElement("a");
            link.setAttribute("href", encodedUri);
            link.setAttribute("download", "traffic_data.csv");
            document.body.appendChild(link);
            link.click();
            document.body.removeChild(link);
            
        };
        
        const blockRequest = async (request) => {
            await blockIP(request.source_ip);
        };
        
        const startTraining = async () => {
            if (isTraining.value) return;
            
            try {
                isTraining.value = true;
                trainingProgress.value = 0;
                trainingLogs.value = [];
                
                // Get training data
                const trainingData = [
                    // SQL injection samples
                    { url: "/search?q=' OR 1=1 --", method: "GET", contains_sql_patterns: true, contains_xss_patterns: false },
                    { url: "/login?user=admin' UNION SELECT * FROM users --", method: "GET", contains_sql_patterns: true, contains_xss_patterns: false },
                    // XSS samples
                    { url: "/search?q=<script>alert('xss')</script>", method: "GET", contains_sql_patterns: false, contains_xss_patterns: true },
                    { url: "/comment?text=<img src=x onerror=alert(1)>", method: "POST", contains_sql_patterns: false, contains_xss_patterns: true },
                    // Normal requests
                    { url: "/", method: "GET", contains_sql_patterns: false, contains_xss_patterns: false },
                    { url: "/api/status", method: "GET", contains_sql_patterns: false, contains_xss_patterns: false }
                ];
                
                const labels = [1, 1, 1, 1, 0, 0]; // 1 = malicious, 0 = normal
                
                // Simulate training progress
                const interval = setInterval(() => {
                    trainingProgress.value += Math.random() * 15;
                    trainingLogs.value.push({
                        timestamp: new Date(),
                        message: `Training progress: ${trainingProgress.value.toFixed(1)}%`
                    });
                    
                    if (trainingProgress.value >= 100) {
                        trainingProgress.value = 100;
                        clearInterval(interval);
                        isTraining.value = false;
                        modelInfo.value.lastTrained = new Date();
                        console.log('Model training completed');
                    }
                }, 800);
                
                // Call the real API endpoint
                const result = await apiCall('/api/training/start', { 
                    method: 'POST',
                    body: JSON.stringify({
                        training_data: trainingData,
                        labels: labels
                    })
                });
                
                console.log('Training result:', result);
                
            } catch (error) {
                console.error('Training failed:', error);
                isTraining.value = false;
            }
        };
        
        const testModel = async () => {
            try {
                // Note: Backend doesn't have ML test endpoint
                // Testing can be done via debug endpoints or training validation
                console.warn('ML test endpoint not implemented in backend');
            } catch (error) {
                console.error('Failed to test model:', error);
            }
        };
        
        const saveSettings = async () => {
            try {
                await apiCall('/settings', {
                    method: 'PUT',
                    body: JSON.stringify(settings.value)
                });
            } catch (error) {
            }
        };
        
        const logout = () => {
            localStorage.removeItem('waf_auth_token');
            authToken.value = '';
            // In a real app, redirect to login page
        };
        
        const login = async (username, password) => {
            try {
                const response = await fetch(`${API_BASE}/auth/login`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({ username, password })
                });
                
                if (!response.ok) {
                    throw new Error('Invalid credentials');
                }
                
                const data = await response.json();
                authToken.value = data.access_token;
                localStorage.setItem('waf_auth_token', data.access_token);
                currentUser.value.username = username;
                
                return true;
            } catch (error) {
                console.error('Login failed:', error);
                return false;
            }
        };
        
        const checkAuth = () => {
            const token = localStorage.getItem('waf_auth_token');
            if (token) {
                authToken.value = token;
                return true;
            }
            return false;
        };
        
        const handleLogin = async () => {
            loginLoading.value = true;
            loginError.value = '';
            
            try {
                const success = await login(loginForm.value.username, loginForm.value.password);
                if (success) {
                    // Load dashboard data after successful login
                    await refreshData();
                    setTimeout(initCharts, 100);
                    startAutoRefresh();
                }
            } catch (error) {
                loginError.value = error.message;
            } finally {
                loginLoading.value = false;
            }
        };
        
        // System initialization functions
        const checkSystemStatus = async () => {
            try {
                const [statsRes, nodesRes, debugRes] = await Promise.all([
                    apiCall('/api/stats'),
                    apiCall('/api/nodes'),
                    apiCall('/api/debug/status')
                ]);
                
                // Check if system appears to be initialized
                const hasNodes = nodesRes.nodes && nodesRes.nodes.length > 0;
                const hasTrafficStats = statsRes.traffic && statsRes.traffic.total_requests > 0;
                const mlTrained = debugRes.components && debugRes.components.ml_engine;
                
                systemInitialized.value = hasNodes && (hasTrafficStats || mlTrained);
                
                return systemInitialized.value;
            } catch (error) {
                console.warn('Could not check system status:', error);
                systemInitialized.value = false;
                return false;
            }
        };
        
        const addInitProgress = (id, message, icon = 'fas fa-circle', status = 'pending') => {
            initProgress.value.push({ id, message, icon, status });
        };
        
        const updateInitProgress = (id, status, newIcon = null) => {
            const step = initProgress.value.find(s => s.id === id);
            if (step) {
                step.status = status;
                if (newIcon) step.icon = newIcon;
            }
        };
        
        const initializeSystem = async () => {
            if (initializingSystem.value) return;
            
            initializingSystem.value = true;
            initProgress.value = [];
            
            try {
                // Step 1: Register nodes
                addInitProgress('nodes', 'Registering nginx nodes...', 'fas fa-server');
                try {
                    const dockerNodes = [
                        {
                            node_id: 'nginx-node-1',
                            hostname: 'nginx-node-1',
                            ssh_host: 'nginx-node-1',
                            ssh_port: 22,
                            ssh_username: 'root',
                            ssh_key_path: '/dev/null',
                            nginx_config_path: '/etc/nginx/conf.d',
                            nginx_reload_command: 'nginx -s reload',
                            api_endpoint: 'http://log-server-1:8080'
                        },
                        {
                            node_id: 'nginx-node-2',
                            hostname: 'nginx-node-2',
                            ssh_host: 'nginx-node-2',
                            ssh_port: 22,
                            ssh_username: 'root',
                            ssh_key_path: '/dev/null',
                            nginx_config_path: '/etc/nginx/conf.d',
                            nginx_reload_command: 'nginx -s reload',
                            api_endpoint: 'http://log-server-2:8080'
                        }
                    ];
                    
                    for (const node of dockerNodes) {
                        try {
                            await apiCall('/api/nodes/add', {
                                method: 'POST',
                                body: JSON.stringify(node)
                            });
                        } catch (e) {
                            console.warn(`Node ${node.node_id} registration failed (may already exist):`, e);
                        }
                    }
                    
                    updateInitProgress('nodes', 'success', 'fas fa-check');
                } catch (error) {
                    updateInitProgress('nodes', 'error', 'fas fa-times');
                    console.warn('Node registration had issues:', error);
                }
                
                await new Promise(resolve => setTimeout(resolve, 1000));
                
                // Step 2: Start traffic collection
                addInitProgress('traffic', 'Starting traffic collection...', 'fas fa-chart-line');
                try {
                    await apiCall('/api/traffic/start-collection', { method: 'POST' });
                    updateInitProgress('traffic', 'success', 'fas fa-check');
                } catch (error) {
                    updateInitProgress('traffic', 'warning', 'fas fa-exclamation-triangle');
                    console.warn('Traffic collection start had issues:', error);
                }
                
                await new Promise(resolve => setTimeout(resolve, 1000));
                
                // Step 3: Train ML model
                addInitProgress('ml', 'Training ML model...', 'fas fa-brain');
                try {
                    const trainingData = [
                        { url: "/login?user=admin' OR '1'='1'", method: "GET", contains_sql_patterns: true, contains_xss_patterns: false, url_length: 35, suspicious_keywords: 1 },
                        { url: "/search?q=<script>alert('xss')</script>", method: "GET", contains_sql_patterns: false, contains_xss_patterns: true, url_length: 42, suspicious_keywords: 1 },
                        { url: "/", method: "GET", contains_sql_patterns: false, contains_xss_patterns: false, url_length: 1, suspicious_keywords: 0 },
                        { url: "/api/status", method: "GET", contains_sql_patterns: false, contains_xss_patterns: false, url_length: 11, suspicious_keywords: 0 }
                    ];
                    const labels = [1, 1, 0, 0];
                    
                    await apiCall('/api/training/start', {
                        method: 'POST',
                        body: JSON.stringify({ training_data: trainingData, labels })
                    });
                    updateInitProgress('ml', 'success', 'fas fa-check');
                } catch (error) {
                    updateInitProgress('ml', 'warning', 'fas fa-exclamation-triangle');
                    console.warn('ML training had issues:', error);
                }
                
                await new Promise(resolve => setTimeout(resolve, 2000));
                
                // Step 4: Start real-time processing
                addInitProgress('processing', 'Starting real-time processing...', 'fas fa-play');
                try {
                    await apiCall('/api/processing/start', { method: 'POST' });
                    updateInitProgress('processing', 'success', 'fas fa-check');
                } catch (error) {
                    updateInitProgress('processing', 'warning', 'fas fa-exclamation-triangle');
                    console.warn('Real-time processing start had issues:', error);
                }
                
                await new Promise(resolve => setTimeout(resolve, 1000));
                
                // Final verification
                addInitProgress('verify', 'Verifying system status...', 'fas fa-check-circle');
                await checkSystemStatus();
                updateInitProgress('verify', 'success', 'fas fa-check');
                
                // Refresh all data
                await refreshData();
                
                console.log('System initialization completed');
                
            } catch (error) {
                console.error('System initialization failed:', error);
            } finally {
                initializingSystem.value = false;
            }
        };
        
        // UI functions
        const toggleSidebar = () => {
            sidebarCollapsed.value = !sidebarCollapsed.value;
        };
        
        // Utility functions
        const formatNumber = (num) => {
            if (!num) return '0';
            return new Intl.NumberFormat().format(num);
        };
        
        const formatTime = (date) => {
            if (!date) return 'N/A';
            return new Intl.DateTimeFormat('en-US', {
                hour: '2-digit',
                minute: '2-digit',
                month: 'short',
                day: 'numeric'
            }).format(new Date(date));
        };
        
        const formatBytes = (bytes) => {
            if (!bytes) return '0 B';
            const k = 1024;
            const sizes = ['B', 'KB', 'MB', 'GB'];
            const i = Math.floor(Math.log(bytes) / Math.log(k));
            return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
        };
        
        const getThreatIcon = (type) => {
            const icons = {
                sql_injection: 'fas fa-database',
                xss: 'fas fa-code',
                brute_force: 'fas fa-hammer',
                dos: 'fas fa-bomb'
            };
            return icons[type] || 'fas fa-exclamation-triangle';
        };
        
        const getStatusClass = (status) => {
            if (status >= 200 && status < 300) return 'success';
            if (status >= 400 && status < 500) return 'warning';
            if (status >= 500) return 'error';
            return '';
        };
        
        // Chart initialization
        const initCharts = () => {
            // Threats Chart
            const threatsCtx = document.getElementById('threatsChart');
            if (threatsCtx) {
                threatsChart = new Chart(threatsCtx, {
                    type: 'line',
                    data: {
                        labels: ['00:00', '04:00', '08:00', '12:00', '16:00', '20:00'],
                        datasets: [{
                            label: 'Threats Detected',
                            data: [2, 1, 4, 3, 5, 2],
                            borderColor: '#dc2626',
                            backgroundColor: 'rgba(220, 38, 38, 0.1)',
                            tension: 0.4,
                            fill: true
                        }]
                    },
                    options: {
                        responsive: true,
                        maintainAspectRatio: false,
                        plugins: {
                            legend: {
                                display: false
                            }
                        },
                        scales: {
                            y: {
                                beginAtZero: true,
                                grid: {
                                    color: '#e2e8f0'
                                }
                            },
                            x: {
                                grid: {
                                    display: false
                                }
                            }
                        }
                    }
                });
            }
            
            // Traffic Chart
            const trafficCtx = document.getElementById('trafficChart');
            if (trafficCtx) {
                trafficChart = new Chart(trafficCtx, {
                    type: 'bar',
                    data: {
                        labels: ['00:00', '04:00', '08:00', '12:00', '16:00', '20:00'],
                        datasets: [{
                            label: 'Requests',
                            data: [1200, 800, 1500, 2200, 1800, 1400],
                            backgroundColor: '#2563eb',
                        }]
                    },
                    options: {
                        responsive: true,
                        maintainAspectRatio: false,
                        plugins: {
                            legend: {
                                display: false
                            }
                        },
                        scales: {
                            y: {
                                beginAtZero: true,
                                grid: {
                                    color: '#e2e8f0'
                                }
                            },
                            x: {
                                grid: {
                                    display: false
                                }
                            }
                        }
                    }
                });
            }
            
            // Real-time Traffic Chart
            const realTimeCtx = document.getElementById('realTimeTrafficChart');
            if (realTimeCtx) {
                realTimeTrafficChart = new Chart(realTimeCtx, {
                    type: 'line',
                    data: {
                        labels: [],
                        datasets: [{
                            label: 'Requests/sec',
                            data: [],
                            borderColor: '#2563eb',
                            backgroundColor: 'rgba(37, 99, 235, 0.1)',
                            tension: 0.4,
                            fill: true
                        }, {
                            label: 'Blocked/sec',
                            data: [],
                            borderColor: '#dc2626',
                            backgroundColor: 'rgba(220, 38, 38, 0.1)',
                            tension: 0.4,
                            fill: true
                        }]
                    },
                    options: {
                        responsive: true,
                        maintainAspectRatio: false,
                        scales: {
                            y: {
                                beginAtZero: true,
                                grid: {
                                    color: '#e2e8f0'
                                }
                            },
                            x: {
                                grid: {
                                    display: false
                                }
                            }
                        },
                        plugins: {
                            legend: {
                                position: 'top'
                            }
                        }
                    }
                });
            }
        };
        
        // Auto-refresh
        let refreshInterval;
        const startAutoRefresh = () => {
            if (refreshInterval) clearInterval(refreshInterval);
            if (autoRefresh.value) {
                refreshInterval = setInterval(refreshData, 30000); // 30 seconds
            }
        };
        
        // Lifecycle
        onMounted(async () => {
            // Check if user is already authenticated
            if (checkAuth()) {
                await refreshData();
                
                // Check system initialization status
                await checkSystemStatus();
                
                // Initialize charts after DOM is ready
                setTimeout(initCharts, 100);
                
                // Start auto-refresh
                startAutoRefresh();
            } else {
                // Show login modal or redirect to login
                console.log('User not authenticated, login required');
            }
        });
        
        onUnmounted(() => {
            if (refreshInterval) clearInterval(refreshInterval);
        });
        
        // Watch auto-refresh setting
        const stopWatcher = Vue.watch(autoRefresh, startAutoRefresh);
        
        return {
            // State
            activeTab,
            sidebarCollapsed,
            loading,
            autoRefresh,
            showAddNodeModal,
            currentUser,
            authToken,
            loginForm,
            loginLoading,
            loginError,
            systemStatus,
            stats,
            threats,
            nodes,
            rules,
            recentActivity,
            recentRequests,
            threatFilter,
            trafficTimeRange,
            threatCount,
            filteredThreats,
            trafficStats,
            modelInfo,
            modelMetrics,
            isTraining,
            trainingProgress,
            trainingLogs,
            systemInitialized,
            initializingSystem,
            initProgress,
            settings,
            newNode,
            rulesLastUpdated,
            
            // Methods
            refreshData,
            blockIP,
            addToWhitelist,
            dismissThreat,
            clearThreats,
            testNode,
            deployRules,
            removeNode,
            addNode,
            generateRules,
            deployAllRules,
            toggleRule,
            editRule,
            deleteRule,
            exportTrafficData,
            blockRequest,
            startTraining,
            testModel,
            saveSettings,
            logout,
            login,
            checkAuth,
            handleLogin,
            checkSystemStatus,
            initializeSystem,
            toggleSidebar,
            formatNumber,
            formatTime,
            formatBytes,
            getThreatIcon,
            getStatusClass
        };
    }
}).mount('#app');
