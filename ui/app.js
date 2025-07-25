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
                console.warn('API call failed, using mock data:', error);
                // Use mock data if API fails
                stats.value = {
                    threats: { total: 23, last24h: 5 },
                    traffic: { requests: 154280, requestsPerSecond: 45 },
                    rules: { active: 12, deployed: 10 },
                    nodes: { healthy: 3, total: 3 }
                };
                
                systemStatus.value = {
                    class: 'warning',
                    icon: 'fas fa-exclamation-triangle',
                    text: 'API Connection Failed - Using Mock Data'
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
                console.warn('Failed to fetch threats, using mock data:', error);
                // Mock data
                threats.value = [
                    {
                        id: 1,
                        type: 'sql_injection',
                        severity: 'high',
                        confidence: 95.5,
                        source_ip: '192.168.1.100',
                        url: '/admin/login.php?id=1\' OR \'1\'=\'1',
                        timestamp: new Date(Date.now() - 300000),
                        details: 'SQL injection attempt detected in query parameter'
                    },
                    {
                        id: 2,
                        type: 'xss',
                        severity: 'medium',
                        confidence: 87.2,
                        source_ip: '10.0.0.50',
                        url: '/search?q=<script>alert(\'xss\')</script>',
                        timestamp: new Date(Date.now() - 600000),
                        details: 'Cross-site scripting attempt in search parameter'
                    }
                ];
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
                console.warn('Failed to fetch nodes, using mock data:', error);
                // Mock data
                nodes.value = [
                    {
                        node_id: 'nginx-node-1',
                        hostname: 'web-server-01',
                        ssh_host: 'nginx-node-1',
                        ssh_port: 22,
                        healthy: true,
                        metrics: {
                            cpu: 45.2,
                            memory: 67.8,
                            requestsPerSec: 124
                        }
                    },
                    {
                        node_id: 'nginx-node-2',
                        hostname: 'web-server-02',
                        ssh_host: 'nginx-node-2',
                        ssh_port: 22,
                        healthy: true,
                        metrics: {
                            cpu: 32.1,
                            memory: 54.3,
                            requestsPerSec: 98
                        }
                    }
                ];
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
                console.warn('Failed to fetch rules, using mock data:', error);
                // Mock data
                rules.value = [
                    {
                        id: 1,
                        name: 'Block SQL Injection',
                        description: 'Blocks common SQL injection patterns',
                        status: 'active',
                        enabled: true,
                        priority: 'high',
                        rule_content: 'if ($query_string ~* "(\\\\|%27|%22|\\\\x00)") {\n    return 403;\n}'
                    },
                    {
                        id: 2,
                        name: 'Rate Limiting',
                        description: 'Limits requests per IP to 100/minute',
                        status: 'active',
                        enabled: true,
                        priority: 'medium',
                        rule_content: 'limit_req_zone $binary_remote_addr zone=api:10m rate=100r/m;'
                    }
                ];
            }
        };
        
        const fetchRecentActivity = async () => {
            try {
                const data = await apiCall('/activity');
                recentActivity.value = data.activities || [];
            } catch (error) {
                // Mock data
                recentActivity.value = [
                    {
                        id: 1,
                        type: 'threat',
                        icon: 'fas fa-exclamation-triangle',
                        message: 'SQL injection attempt blocked from 192.168.1.100',
                        timestamp: new Date(Date.now() - 180000)
                    },
                    {
                        id: 2,
                        type: 'rule',
                        icon: 'fas fa-shield-alt',
                        message: 'New WAF rule deployed to nginx-node-1',
                        timestamp: new Date(Date.now() - 420000)
                    },
                    {
                        id: 3,
                        type: 'system',
                        icon: 'fas fa-server',
                        message: 'nginx-node-2 came back online',
                        timestamp: new Date(Date.now() - 720000)
                    }
                ];
            }
        };
        
        const fetchTrafficData = async () => {
            try {
                const data = await apiCall('/traffic');
                recentRequests.value = data.requests || [];
                trafficStats.value = {
                    ...trafficStats.value,
                    ...data.stats
                };
            } catch (error) {
                // Mock data
                recentRequests.value = [
                    {
                        id: 1,
                        timestamp: new Date(Date.now() - 30000),
                        source_ip: '192.168.1.100',
                        method: 'POST',
                        url: '/api/login',
                        status: 200,
                        size: 1024,
                        blocked: false
                    },
                    {
                        id: 2,
                        timestamp: new Date(Date.now() - 45000),
                        source_ip: '10.0.0.50',
                        method: 'GET',
                        url: '/admin',
                        status: 403,
                        size: 512,
                        blocked: true
                    }
                ];
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
                const result = await apiCall(`/nodes/${nodeId}/test`, { method: 'POST' });
                if (result.success) {
                } else {
                }
            } catch (error) {
            }
        };
        
        const deployRules = async (nodeId) => {
            try {
                await apiCall(`/nodes/${nodeId}/deploy`, { method: 'POST' });
                await fetchNodes();
            } catch (error) {
            }
        };
        
        const removeNode = async (nodeId) => {
            if (confirm(`Are you sure you want to remove node ${nodeId}?`)) {
                try {
                    await apiCall(`/nodes/${nodeId}`, { method: 'DELETE' });
                    await fetchNodes();
                } catch (error) {
                }
            }
        };
        
        const addNode = async () => {
            try {
                await apiCall('/nodes', {
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
            }
        };
        
        const generateRules = async () => {
            try {
                loading.value = true;
                const result = await apiCall('/rules/generate', { method: 'POST' });
                await fetchRules();
            } catch (error) {
            } finally {
                loading.value = false;
            }
        };
        
        const deployAllRules = async () => {
            try {
                loading.value = true;
                await apiCall('/rules/deploy-all', { method: 'POST' });
                await fetchRules();
            } catch (error) {
            } finally {
                loading.value = false;
            }
        };
        
        const toggleRule = async (ruleId) => {
            try {
                const rule = rules.value.find(r => r.id === ruleId);
                if (rule) {
                    rule.enabled = !rule.enabled;
                    await apiCall(`/rules/${ruleId}/toggle`, { method: 'POST' });
                }
            } catch (error) {
            }
        };
        
        const editRule = (ruleId) => {
        };
        
        const deleteRule = async (ruleId) => {
            if (confirm('Are you sure you want to delete this rule?')) {
                try {
                    await apiCall(`/rules/${ruleId}`, { method: 'DELETE' });
                    rules.value = rules.value.filter(r => r.id !== ruleId);
                } catch (error) {
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
                
                // Simulate training progress
                const interval = setInterval(() => {
                    trainingProgress.value += Math.random() * 10;
                    trainingLogs.value.push({
                        timestamp: new Date(),
                        message: `Training progress: ${trainingProgress.value.toFixed(1)}%`
                    });
                    
                    if (trainingProgress.value >= 100) {
                        trainingProgress.value = 100;
                        clearInterval(interval);
                        isTraining.value = false;
                        modelInfo.value.lastTrained = new Date();
                    }
                }, 1000);
                
                await apiCall('/ml/train', { method: 'POST' });
            } catch (error) {
                isTraining.value = false;
            }
        };
        
        const testModel = async () => {
            try {
                const result = await apiCall('/ml/test', { method: 'POST' });
            } catch (error) {
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
            toggleSidebar,
            formatNumber,
            formatTime,
            formatBytes,
            getThreatIcon,
            getStatusClass
        };
    }
}).mount('#app');
