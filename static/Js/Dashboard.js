// Dashboard functionality
class SafetyDashboard {
    constructor() {
        this.refreshInterval = 5000; // 5 seconds
        this.init();
    }
    
    init() {
        this.initWebSocket();
        this.initEventListeners();
        this.startAutoRefresh();
    }
    
    initWebSocket() {
        // For real-time updates
        if (typeof WebSocket !== 'undefined') {
            const wsProtocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
            const wsUrl = `${wsProtocol}//${window.location.host}/ws`;
            
            this.ws = new WebSocket(wsUrl);
            
            this.ws.onmessage = (event) => {
                const data = JSON.parse(event.data);
                this.handleRealtimeUpdate(data);
            };
            
            this.ws.onerror = (error) => {
                console.error('WebSocket error:', error);
            };
        }
    }
    
    initEventListeners() {
        // SOS Button
        const sosBtn = document.getElementById('sosButton');
        if (sosBtn) {
            sosBtn.addEventListener('click', this.sendSOS.bind(this));
        }
        
        // Refresh button
        const refreshBtn = document.getElementById('refreshBtn');
        if (refreshBtn) {
            refreshBtn.addEventListener('click', this.refreshData.bind(this));
        }
    }
    
    startAutoRefresh() {
        setInterval(() => {
            this.refreshData();
        }, this.refreshInterval);
    }
    
    refreshData() {
        const endpoint = this.getCurrentEndpoint();
        fetch(endpoint)
            .then(response => response.json())
            .then(data => this.updateUI(data))
            .catch(error => console.error('Refresh error:', error));
    }
    
    getCurrentEndpoint() {
        const path = window.location.pathname;
        if (path.includes('worker')) {
            return '/api/worker/status';
        } else if (path.includes('manager')) {
            return '/api/manager/workers';
        }
        return '';
    }
    
    updateUI(data) {
        // Update based on user role
        if (window.location.pathname.includes('worker')) {
            this.updateWorkerUI(data);
        } else {
            this.updateManagerUI(data);
        }
    }
    
    updateWorkerUI(data) {
        // Update risk indicator
        const riskEl = document.querySelector('.risk-indicator');
        if (riskEl) {
            riskEl.textContent = data.risk_level.toUpperCase();
            riskEl.className = `badge risk-${data.risk_level}`;
        }
        
        // Update sensor values
        this.updateValue('.gas-value', data.gas);
        this.updateValue('.temp-value', `${data.temperature.toFixed(1)}°C`);
        this.updateValue('.helmet-status', data.helmet_worn ? 'WORN' : 'NOT WORN');
        this.updateValue('.battery-value', `${data.battery.toFixed(2)}V`);
        
        // Update last update time
        const timeEl = document.querySelector('.last-update');
        if (timeEl) {
            timeEl.textContent = this.formatTime(data.last_update);
        }
    }
    
    updateManagerUI(data) {
        // Update worker list
        this.updateWorkerList(data);
        
        // Update stats
        const activeCount = data.filter(w => w.is_active).length;
        const dangerCount = data.filter(w => w.risk_level === 'danger').length;
        
        this.updateValue('.active-workers', activeCount);
        this.updateValue('.danger-workers', dangerCount);
    }
    
    updateWorkerList(workers) {
        const tbody = document.querySelector('.workers-table tbody');
        if (!tbody) return;
        
        tbody.innerHTML = workers.map(worker => `
            <tr class="${worker.risk_level === 'danger' ? 'table-danger' : worker.risk_level === 'warning' ? 'table-warning' : ''}">
                <td>${worker.name}<br><small>${worker.worker_id}</small></td>
                <td>${worker.department}</td>
                <td><span class="badge bg-info">${worker.helmet_id}</span></td>
                <td>
                    <span class="badge ${worker.is_active ? 'bg-success' : 'bg-secondary'}">
                        ${worker.is_active ? 'Active' : 'Offline'}
                    </span>
                </td>
                <td>
                    <span class="badge ${this.getRiskBadgeClass(worker.risk_level)}">
                        ${worker.risk_score}
                    </span>
                </td>
                <td>${worker.today_hours || 0} hrs</td>
                <td>${worker.last_update ? this.formatTime(worker.last_update) : 'No data'}</td>
                <td>
                    <button class="btn btn-sm btn-outline-primary" onclick="viewWorker('${worker.worker_id}')">
                        <i class="fas fa-eye"></i>
                    </button>
                </td>
            </tr>
        `).join('');
    }
    
    getRiskBadgeClass(riskLevel) {
        switch(riskLevel) {
            case 'safe': return 'bg-success';
            case 'warning': return 'bg-warning';
            case 'danger': return 'bg-danger';
            default: return 'bg-secondary';
        }
    }
    
    updateValue(selector, value) {
        const el = document.querySelector(selector);
        if (el) el.textContent = value;
    }
    
    formatTime(timestamp) {
        if (!timestamp) return 'N/A';
        
        const date = new Date(timestamp);
        const now = new Date();
        const diffMs = now - date;
        const diffMins = Math.floor(diffMs / 60000);
        
        if (diffMins < 1) return 'Just now';
        if (diffMins < 60) return `${diffMins} min ago`;
        
        const diffHours = Math.floor(diffMins / 60);
        if (diffHours < 24) return `${diffHours} hr ago`;
        
        return date.toLocaleTimeString();
    }
    
    sendSOS() {
        if (!confirm('Send SOS emergency alert? This will immediately notify the manager.')) {
            return;
        }
        
        fetch('/api/worker/sos', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            }
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                alert('SOS alert sent! Manager has been notified.');
                
                // Visual feedback
                const sosBtn = document.getElementById('sosButton');
                if (sosBtn) {
                    sosBtn.classList.add('btn-danger');
                    sosBtn.innerHTML = '<i class="fas fa-check"></i> SOS SENT';
                    
                    setTimeout(() => {
                        sosBtn.classList.remove('btn-danger');
                        sosBtn.innerHTML = '<i class="fas fa-sos"></i> EMERGENCY SOS';
                    }, 3000);
                }
            }
        })
        .catch(error => {
            alert('Error sending SOS. Please try again.');
        });
    }
    
    handleRealtimeUpdate(data) {
        // Handle real-time WebSocket updates
        console.log('Real-time update:', data);
        
        // Play notification sound for alerts
        if (data.type === 'alert') {
            this.playAlertSound();
            this.showNotification(data.message);
        }
    }
    
    playAlertSound() {
        const audio = new Audio('/static/sounds/alert.mp3');
        audio.play().catch(e => console.log('Audio play failed:', e));
    }
    
    showNotification(message) {
        // Check if browser supports notifications
        if (!("Notification" in window)) {
            return;
        }
        
        // Check if permission is already granted
        if (Notification.permission === "granted") {
            new Notification("Safety Alert", {
                body: message,
                icon: "/static/images/alert.png"
            });
        } else if (Notification.permission !== "denied") {
            Notification.requestPermission().then(permission => {
                if (permission === "granted") {
                    new Notification("Safety Alert", {
                        body: message,
                        icon: "/static/images/alert.png"
                    });
                }
            });
        }
    }
}

// Initialize dashboard when page loads
document.addEventListener('DOMContentLoaded', () => {
    window.safetyDashboard = new SafetyDashboard();
});

// Utility functions for global use
function viewWorker(workerId) {
    window.location.href = `/manager/worker/${workerId}`;
}

function acknowledgeAlert(alertId) {
    fetch(`/api/alerts/${alertId}/acknowledge`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        }
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            location.reload();
        }
    });
}

function generateReport() {
    fetch('/api/reports/daily')
        .then(response => response.json())
        .then(data => {
            // Create a printable report
            const reportWindow = window.open('', '_blank');
            reportWindow.document.write(`
                <html>
                <head>
                    <title>Daily Safety Report</title>
                    <style>
                        body { font-family: Arial, sans-serif; padding: 20px; }
                        h1 { color: #2c3e50; }
                        .stats { display: grid; grid-template-columns: repeat(3, 1fr); gap: 20px; margin: 20px 0; }
                        .stat-card { background: #f8f9fa; padding: 15px; border-radius: 5px; }
                        table { width: 100%; border-collapse: collapse; margin: 20px 0; }
                        th, td { border: 1px solid #ddd; padding: 10px; text-align: left; }
                        th { background: #2c3e50; color: white; }
                    </style>
                </head>
                <body>
                    <h1>Daily Safety Report</h1>
                    <p>Generated: ${new Date().toLocaleString()}</p>
                    
                    <div class="stats">
                        <div class="stat-card">
                            <h3>${data.total_workers}</h3>
                            <p>Total Workers</p>
                        </div>
                        <div class="stat-card">
                            <h3>${data.active_workers}</h3>
                            <p>Active Workers</p>
                        </div>
                        <div class="stat-card">
                            <h3>${data.total_alerts}</h3>
                            <p>Total Alerts</p>
                        </div>
                    </div>
                    
                    <button onclick="window.print()" style="padding: 10px 20px; background: #007bff; color: white; border: none; border-radius: 5px; cursor: pointer;">
                        Print Report
                    </button>
                </body>
                </html>
            `);
        });
}
