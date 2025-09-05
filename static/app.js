// Server Check Application JavaScript

class ServerCheckApp {
    constructor() {
        this.init();
    }

    init() {
        this.setupEventListeners();
        this.setupAutoRefresh();
        this.setupFormValidation();
        this.setupTableSorting();
    }

    setupEventListeners() {
        // Add loading states to forms
        document.addEventListener('submit', (e) => {
            if (e.target.tagName === 'FORM') {
                this.showFormLoading(e.target);
            }
        });

        // Add confirmation for destructive actions
        document.addEventListener('click', (e) => {
            if (e.target.matches('[data-confirm]')) {
                const message = e.target.getAttribute('data-confirm');
                if (!confirm(message)) {
                    e.preventDefault();
                }
            }
        });

        // Add tooltips for help text
        document.addEventListener('mouseenter', (e) => {
            if (e.target.matches('[data-tooltip]')) {
                this.showTooltip(e.target);
            }
        }, true);

        document.addEventListener('mouseleave', (e) => {
            if (e.target.matches('[data-tooltip]')) {
                this.hideTooltip();
            }
        }, true);
    }

    setupAutoRefresh() {
        // Auto-refresh dashboard every 30 seconds
        if (window.location.pathname === '/') {
            setInterval(() => {
                this.refreshDashboard();
            }, 30000);
        }
    }

    setupFormValidation() {
        // Real-time form validation
        document.addEventListener('input', (e) => {
            if (e.target.matches('input[required]')) {
                this.validateField(e.target);
            }
        });
    }

    setupTableSorting() {
        // Table sorting functionality
        const sortableHeaders = document.querySelectorAll('.sortable');
        
        sortableHeaders.forEach(header => {
            header.addEventListener('click', function() {
                const sortField = this.dataset.sort;
                const currentUrl = new URL(window.location);
                const currentSort = currentUrl.searchParams.get('sort');
                
                // Toggle sort direction
                let newSort = sortField;
                if (currentSort === sortField) {
                    newSort = `-${sortField}`; // Add minus for descending
                }
                
                currentUrl.searchParams.set('sort', newSort);
                window.location.href = currentUrl.toString();
            });
        });
    }

    showFormLoading(form) {
        const submitBtn = form.querySelector('button[type="submit"]');
        if (submitBtn) {
            submitBtn.disabled = true;
            submitBtn.innerHTML = '<span class="spinner"></span> Отправка...';
        }
    }

    showTooltip(element) {
        const tooltip = document.createElement('div');
        tooltip.className = 'tooltip';
        tooltip.textContent = element.getAttribute('data-tooltip');
        tooltip.style.cssText = `
            position: absolute;
            background: var(--bg-secondary);
            color: var(--text-primary);
            padding: 8px 12px;
            border-radius: 4px;
            box-shadow: 0 2px 8px var(--shadow);
            z-index: 1000;
            font-size: 14px;
            max-width: 200px;
            word-wrap: break-word;
        `;
        
        document.body.appendChild(tooltip);
        
        const rect = element.getBoundingClientRect();
        tooltip.style.left = rect.left + 'px';
        tooltip.style.top = (rect.bottom + 5) + 'px';
    }

    hideTooltip() {
        const tooltip = document.querySelector('.tooltip');
        if (tooltip) {
            tooltip.remove();
        }
    }

    validateField(field) {
        const value = field.value.trim();
        const isValid = value.length > 0;
        
        field.classList.toggle('invalid', !isValid);
        
        // Show/hide error message
        let errorMsg = field.parentNode.querySelector('.error-message');
        if (!isValid && !errorMsg) {
            errorMsg = document.createElement('div');
            errorMsg.className = 'error-message';
            errorMsg.textContent = 'Это поле обязательно для заполнения';
            errorMsg.style.cssText = 'color: #dc3545; font-size: 12px; margin-top: 4px;';
            field.parentNode.appendChild(errorMsg);
        } else if (isValid && errorMsg) {
            errorMsg.remove();
        }
    }

    async refreshDashboard() {
        try {
            const response = await fetch('/api/servers');
            const servers = await response.json();
            
            // Update server cards
            this.updateServerCards(servers);
        } catch (error) {
            console.error('Failed to refresh dashboard:', error);
        }
    }

    updateServerCards(servers) {
        // Update server status indicators
        servers.forEach(server => {
            const card = document.querySelector(`[data-server-id="${server.id}"]`);
            if (card && server.latest_metric) {
                const statusIndicator = card.querySelector('.status-indicator');
                if (statusIndicator) {
                    const isReachable = server.latest_metric.reachable;
                    statusIndicator.className = `status-indicator ${isReachable ? 'online' : 'offline'}`;
                }
                
                // Update metrics
                this.updateMetricDisplay(card, server.latest_metric);
            }
        });
    }

    updateMetricDisplay(card, metric) {
        const metrics = ['cpu_percent', 'ram_percent', 'disk_percent'];
        metrics.forEach(metricName => {
            const element = card.querySelector(`[data-metric="${metricName}"]`);
            if (element && metric[metricName] !== null) {
                element.textContent = `${metric[metricName].toFixed(1)}%`;
                
                // Color coding based on thresholds
                const value = metric[metricName];
                element.className = element.className.replace(/metric-\w+/, '');
                if (value > 90) {
                    element.classList.add('metric-critical');
                } else if (value > 75) {
                    element.classList.add('metric-warning');
                } else {
                    element.classList.add('metric-ok');
                }
            }
        });
    }

    showNotification(message, type = 'info', duration = 5000) {
        const notification = document.createElement('div');
        notification.className = `notification notification-${type}`;
        
        // Create notification content with icon
        const icons = {
            'info': 'ℹ️',
            'success': '✅',
            'warning': '⚠️',
            'error': '❌'
        };
        
        notification.innerHTML = `
            <div class="notification-content">
                <span class="notification-icon">${icons[type] || icons.info}</span>
                <span class="notification-message">${message}</span>
                <button class="notification-close" onclick="this.parentElement.parentElement.remove()">×</button>
            </div>
        `;
        
        notification.style.cssText = `
            position: fixed;
            top: 20px;
            right: 20px;
            min-width: 300px;
            max-width: 500px;
            padding: 0;
            border-radius: 8px;
            color: white;
            z-index: 10000;
            animation: slideIn 0.3s ease;
            box-shadow: 0 4px 12px rgba(0,0,0,0.15);
            overflow: hidden;
        `;
        
        // Set background color based on type
        const colors = {
            'info': '#3b82f6',
            'success': '#10b981',
            'warning': '#f59e0b',
            'error': '#ef4444'
        };
        notification.style.backgroundColor = colors[type] || colors.info;
        
        // Style notification content
        const content = notification.querySelector('.notification-content');
        content.style.cssText = `
            display: flex;
            align-items: center;
            padding: 12px 16px;
            gap: 12px;
        `;
        
        const icon = notification.querySelector('.notification-icon');
        icon.style.cssText = `
            font-size: 18px;
            flex-shrink: 0;
        `;
        
        const messageEl = notification.querySelector('.notification-message');
        messageEl.style.cssText = `
            flex: 1;
            font-size: 14px;
            line-height: 1.4;
        `;
        
        const closeBtn = notification.querySelector('.notification-close');
        closeBtn.style.cssText = `
            background: none;
            border: none;
            color: white;
            font-size: 20px;
            cursor: pointer;
            padding: 0;
            width: 24px;
            height: 24px;
            display: flex;
            align-items: center;
            justify-content: center;
            border-radius: 50%;
            transition: background-color 0.2s ease;
        `;
        
        closeBtn.addEventListener('mouseenter', () => {
            closeBtn.style.backgroundColor = 'rgba(255,255,255,0.2)';
        });
        
        closeBtn.addEventListener('mouseleave', () => {
            closeBtn.style.backgroundColor = 'transparent';
        });
        
        document.body.appendChild(notification);
        
        // Auto-remove after specified duration
        if (duration > 0) {
            setTimeout(() => {
                if (notification.parentElement) {
                    notification.style.animation = 'slideOut 0.3s ease';
                    setTimeout(() => notification.remove(), 300);
                }
            }, duration);
        }
    }
}

// Initialize app when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    window.app = new ServerCheckApp();
});

// Global notification functions
function showNotification(message, type = 'info', duration = 5000) {
    if (window.app) {
        window.app.showNotification(message, type, duration);
    }
}

function showSuccess(message, duration = 3000) {
    showNotification(message, 'success', duration);
}

function showError(message, duration = 0) {
    showNotification(message, 'error', duration);
}

function showWarning(message, duration = 5000) {
    showNotification(message, 'warning', duration);
}

function showInfo(message, duration = 5000) {
    showNotification(message, 'info', duration);
}

// Global loading functions
function showLoadingOverlay(message = "Загрузка...") {
    const overlay = document.createElement('div');
    overlay.className = 'loading-overlay';
    overlay.innerHTML = `
        <div class="loading-card">
            <div class="spinner"></div>
            <p>${message}</p>
        </div>
    `;
    document.body.appendChild(overlay);
    return overlay;
}

function hideLoadingOverlay() {
    const overlay = document.querySelector('.loading-overlay');
    if (overlay) {
        overlay.remove();
    }
}

// Add CSS animations
const style = document.createElement('style');
style.textContent = `
    @keyframes slideIn {
        from { transform: translateX(100%); opacity: 0; }
        to { transform: translateX(0); opacity: 1; }
    }
    
    @keyframes slideOut {
        from { transform: translateX(0); opacity: 1; }
        to { transform: translateX(100%); opacity: 0; }
    }
    
    .metric-critical { color: #dc3545; font-weight: bold; }
    .metric-warning { color: #ffc107; font-weight: bold; }
    .metric-ok { color: #28a745; }
    
    .status-indicator {
        display: inline-block;
        width: 8px;
        height: 8px;
        border-radius: 50%;
        margin-right: 8px;
    }
    
    .status-indicator.online { background: #28a745; }
    .status-indicator.offline { background: #dc3545; }
    
    input.invalid {
        border-color: #dc3545;
    }
`;
document.head.appendChild(style);
