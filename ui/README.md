# WAF AI Dashboard

A modern, responsive web interface for monitoring and managing the Nginx WAF AI system.

## Features

### 🎯 Real-time Monitoring
- **System Health Dashboard**: Live status of all components
- **Threat Detection**: Real-time threat alerts and analysis
- **Traffic Analytics**: Comprehensive request monitoring
- **Performance Metrics**: System resource utilization

### 🛡️ Security Management
- **WAF Rules**: Create, edit, and deploy security rules
- **Threat Response**: Block IPs, whitelist sources, dismiss alerts
- **Node Management**: Configure and monitor nginx nodes
- **ML Model**: Train and evaluate machine learning models

### 📊 Analytics & Reporting
- **Interactive Charts**: Traffic trends and threat patterns
- **Export Capabilities**: Download traffic data and reports
- **Historical Data**: Track system performance over time
- **Custom Filters**: Analyze specific threat types or time periods

## Technology Stack

- **Frontend**: Vue.js 3 (CDN), vanilla JavaScript
- **Charts**: Chart.js for data visualization
- **Icons**: Font Awesome 6
- **Styling**: Custom CSS with modern design system
- **API Integration**: RESTful API with the FastAPI backend

## Quick Start

### Option 1: Standalone (Development)
```bash
# Navigate to the UI directory
cd ui

# Start a simple HTTP server
python3 -m http.server 8080

# Open in browser
open http://localhost:8080
```

### Option 2: With Docker Compose
```bash
# From the project root
docker-compose up -d

# The UI will be available at http://localhost:8080
```

### Option 3: Serve with Nginx
```bash
# Copy files to nginx web root
sudo cp -r ui/* /var/www/html/

# Or create a new nginx config
sudo cp nginx-ui.conf /etc/nginx/sites-available/
sudo ln -s /etc/nginx/sites-available/nginx-ui.conf /etc/nginx/sites-enabled/
sudo systemctl reload nginx
```

## API Configuration

The dashboard connects to the WAF AI API backend. Update the `API_BASE` constant in `app.js`:

```javascript
const API_BASE = 'http://your-api-server:8000/api/v1';
```

## Features Overview

### Dashboard Tab
- System status overview
- Key performance metrics
- Real-time charts
- Recent activity feed

### Threats Tab
- Live threat detection alerts
- Threat type filtering
- IP blocking and whitelisting
- Detailed threat analysis

### Nginx Nodes Tab
- Node health monitoring
- Resource utilization metrics
- Rule deployment controls
- SSH connection management

### WAF Rules Tab
- Rule creation and editing
- Bulk rule deployment
- Rule status management
- Nginx configuration preview

### Traffic Tab
- Real-time request monitoring
- Traffic analytics
- Request filtering and search
- Data export capabilities

### ML Engine Tab
- Model training interface
- Performance metrics
- Training progress monitoring
- Model testing tools

### Settings Tab
- Security configuration
- ML model parameters
- Notification settings
- System preferences

## Customization

### Theming
Modify CSS variables in `styles.css`:

```css
:root {
    --primary-color: #2563eb;
    --success-color: #059669;
    --danger-color: #dc2626;
    /* ... */
}
```

### API Integration
Update API endpoints in `app.js`:

```javascript
const apiCall = async (endpoint, options = {}) => {
    // Customize authentication, headers, error handling
};
```

### Chart Configuration
Modify chart settings in the `initCharts()` function:

```javascript
const initCharts = () => {
    // Customize chart types, colors, and options
};
```

## Browser Support

- Chrome 88+
- Firefox 85+
- Safari 14+
- Edge 88+

## Performance

- **Lazy Loading**: Components load on demand
- **Auto Refresh**: Configurable refresh intervals
- **Efficient Updates**: Only update changed data
- **Responsive Design**: Optimized for all screen sizes

## Security

- **JWT Authentication**: Secure API communication
- **Input Validation**: Client-side form validation
- **CSRF Protection**: Request token validation
- **Content Security**: XSS protection headers

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Support

For support and questions:
- Create an issue in the GitHub repository
- Check the API documentation
- Review the troubleshooting guide

---

Made with ❤️ for modern web security monitoring
