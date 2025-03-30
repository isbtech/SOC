/**
 * Main JavaScript file for Security Operations Center
 * 
 * This file contains common functionality used across the SOC system
 */

// Notification system
const SocNotifications = {
    /**
     * Show a notification message
     * @param {string} message - The message to display
     * @param {string} type - The type of notification (success, error, warning, info)
     * @param {number} duration - Duration in milliseconds
     */
    show: function(message, type = 'info', duration = 5000) {
        // Create notification container if it doesn't exist
        let container = document.getElementById('notification-container');
        if (!container) {
            container = document.createElement('div');
            container.id = 'notification-container';
            container.style.position = 'fixed';
            container.style.top = '20px';
            container.style.right = '20px';
            container.style.zIndex = '9999';
            document.body.appendChild(container);
        }
        
        // Create notification element
        const notification = document.createElement('div');
        notification.className = `toast show bg-${type === 'error' ? 'danger' : type}`;
        notification.role = 'alert';
        notification.setAttribute('aria-live', 'assertive');
        notification.setAttribute('aria-atomic', 'true');
        
        // Create notification content
        notification.innerHTML = `
            <div class="toast-header bg-${type === 'error' ? 'danger' : type} text-white">
                <strong class="me-auto">${type.charAt(0).toUpperCase() + type.slice(1)}</strong>
                <button type="button" class="btn-close btn-close-white" data-bs-dismiss="toast" aria-label="Close"></button>
            </div>
            <div class="toast-body">
                ${message}
            </div>
        `;
        
        // Add notification to container
        container.appendChild(notification);
        
        // Auto-dismiss notification after duration
        setTimeout(() => {
            notification.classList.remove('show');
            setTimeout(() => {
                container.removeChild(notification);
            }, 500);
        }, duration);
        
        // Add close button event
        const closeButton = notification.querySelector('.btn-close');
        closeButton.addEventListener('click', () => {
            notification.classList.remove('show');
            setTimeout(() => {
                container.removeChild(notification);
            }, 500);
        });
    },
    
    /**
     * Show success notification
     * @param {string} message - The message to display
     */
    success: function(message) {
        this.show(message, 'success');
    },
    
    /**
     * Show error notification
     * @param {string} message - The message to display
     */
    error: function(message) {
        this.show(message, 'error');
    },
    
    /**
     * Show warning notification
     * @param {string} message - The message to display
     */
    warning: function(message) {
        this.show(message, 'warning');
    },
    
    /**
     * Show info notification
     * @param {string} message - The message to display
     */
    info: function(message) {
        this.show(message, 'info');
    }
};

// Utility functions
const SocUtils = {
    /**
     * Format date to a readable format
     * @param {string|Date} date - The date to format
     * @param {boolean} includeTime - Whether to include time
     * @returns {string} Formatted date
     */
    formatDate: function(date, includeTime = true) {
        if (!date) return 'N/A';
        
        const dateObj = typeof date === 'string' ? new Date(date) : date;
        const options = {
            year: 'numeric',
            month: 'short',
            day: 'numeric'
        };
        
        if (includeTime) {
            options.hour = '2-digit';
            options.minute = '2-digit';
            options.second = '2-digit';
        }
        
        return dateObj.toLocaleDateString('en-US', options);
    },
    
    /**
     * Calculate time elapsed since a date
     * @param {string|Date} date - The date to calculate from
     * @returns {string} Elapsed time string
     */
    timeElapsed: function(date) {
        if (!date) return 'N/A';
        
        const dateObj = typeof date === 'string' ? new Date(date) : date;
        const now = new Date();
        const diff = Math.floor((now - dateObj) / 1000); // Difference in seconds
        
        if (diff < 60) {
            return diff + ' second' + (diff !== 1 ? 's' : '') + ' ago';
        }
        
        const minutes = Math.floor(diff / 60);
        if (minutes < 60) {
            return minutes + ' minute' + (minutes !== 1 ? 's' : '') + ' ago';
        }
        
        const hours = Math.floor(minutes / 60);
        if (hours < 24) {
            return hours + ' hour' + (hours !== 1 ? 's' : '') + ' ago';
        }
        
        const days = Math.floor(hours / 24);
        if (days < 30) {
            return days + ' day' + (days !== 1 ? 's' : '') + ' ago';
        }
        
        const months = Math.floor(days / 30);
        if (months < 12) {
            return months + ' month' + (months !== 1 ? 's' : '') + ' ago';
        }
        
        const years = Math.floor(months / 12);
        return years + ' year' + (years !== 1 ? 's' : '') + ' ago';
    },
    
    /**
     * Safe JSON parsing with error handling
     * @param {string} jsonString - The JSON string to parse
     * @param {*} defaultValue - Default value to return on error
     * @returns {*} Parsed JSON or default value
     */
    safeJSONParse: function(jsonString, defaultValue = {}) {
        try {
            return JSON.parse(jsonString);
        } catch (e) {
            console.error('Error parsing JSON:', e);
            return defaultValue;
        }
    },
    
    /**
     * Escape HTML to prevent XSS
     * @param {string} unsafeText - Text to escape
     * @returns {string} Escaped text
     */
    escapeHTML: function(unsafeText) {
        if (!unsafeText) return '';
        
        return unsafeText
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#039;');
    },
    
    /**
     * Validate IP address
     * @param {string} ip - IP address to validate
     * @returns {boolean} Whether the IP is valid
     */
    isValidIP: function(ip) {
        // Regular expression for IPv4
        const ipv4Regex = /^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
        
        // Regular expression for IPv6
        const ipv6Regex = /^(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))$/;
        
        return ipv4Regex.test(ip) || ipv6Regex.test(ip);
    },
    
    /**
     * Get severity class for UI elements
     * @param {string} severity - The severity level
     * @returns {string} CSS class name
     */
    getSeverityClass: function(severity) {
        switch (severity?.toLowerCase()) {
            case 'critical': return 'danger';
            case 'high': return 'warning';
            case 'medium': return 'primary';
            case 'low': return 'success';
            case 'informational': return 'info';
            default: return 'secondary';
        }
    },
    
    /**
     * Get status class for UI elements
     * @param {string} status - The status
     * @returns {string} CSS class name
     */
    getStatusClass: function(status) {
        switch (status?.toLowerCase()) {
            case 'new':
            case 'open': return 'danger';
            case 'in_progress':
            case 'assigned':
            case 'investigating': return 'warning';
            case 'mitigated':
            case 'contained': return 'primary';
            case 'resolved':
            case 'remediated': return 'success';
            case 'closed':
            case 'accepted_risk':
            case 'false_positive': return 'secondary';
            default: return 'info';
        }
    },
    
    /**
     * Copy text to clipboard
     * @param {string} text - The text to copy
     * @returns {Promise<boolean>} Success status
     */
    copyToClipboard: async function(text) {
        try {
            await navigator.clipboard.writeText(text);
            SocNotifications.success('Copied to clipboard!');
            return true;
        } catch (err) {
            console.error('Failed to copy: ', err);
            SocNotifications.error('Failed to copy to clipboard');
            return false;
        }
    }
};

// AJAX request handler
const SocApi = {
    /**
     * Make an AJAX request
     * @param {string} url - The URL to request
     * @param {Object} options - Request options
     * @returns {Promise} Promise resolving to response data
     */
    request: async function(url, options = {}) {
        const defaultOptions = {
            method: 'GET',
            headers: {
                'Content-Type': 'application/json',
                'X-Requested-With': 'XMLHttpRequest'
            }
        };
        
        // Merge options with defaults
        const requestOptions = {...defaultOptions, ...options};
        
        // If data is provided and method is not GET, stringify it
        if (options.data && requestOptions.method !== 'GET') {
            requestOptions.body = JSON.stringify(options.data);
        }
        
        // If data is provided and method is GET, append as query parameters
        if (options.data && requestOptions.method === 'GET') {
            const params = new URLSearchParams();
            Object.entries(options.data).forEach(([key, value]) => {
                params.append(key, value);
            });
            url = `${url}?${params.toString()}`;
        }
        
        try {
            const response = await fetch(url, requestOptions);
            
            // Check if response is ok
            if (!response.ok) {
                const errorText = await response.text();
                throw new Error(`Request failed: ${response.status} ${response.statusText} - ${errorText}`);
            }
            
            // Parse response based on content type
            const contentType = response.headers.get('content-type');
            if (contentType && contentType.includes('application/json')) {
                return await response.json();
            } else {
                return await response.text();
            }
        } catch (error) {
            console.error('API request error:', error);
            throw error;
        }
    },
    
    /**
     * Make a GET request
     * @param {string} url - The URL to request
     * @param {Object} data - Query parameters
     * @returns {Promise} Promise resolving to response data
     */
    get: function(url, data = {}) {
        return this.request(url, {method: 'GET', data});
    },
    
    /**
     * Make a POST request
     * @param {string} url - The URL to request
     * @param {Object} data - Request body data
     * @returns {Promise} Promise resolving to response data
     */
    post: function(url, data = {}) {
        return this.request(url, {method: 'POST', data});
    },
    
    /**
     * Make a PUT request
     * @param {string} url - The URL to request
     * @param {Object} data - Request body data
     * @returns {Promise} Promise resolving to response data
     */
    put: function(url, data = {}) {
        return this.request(url, {method: 'PUT', data});
    },
    
    /**
     * Make a DELETE request
     * @param {string} url - The URL to request
     * @param {Object} data - Request body data
     * @returns {Promise} Promise resolving to response data
     */
    delete: function(url, data = {}) {
        return this.request(url, {method: 'DELETE', data});
    }
};

// Initialize on document load
document.addEventListener('DOMContentLoaded', function() {
    // Initialize Bootstrap tooltips and popovers
    const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    tooltipTriggerList.map(function(tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl);
    });
    
    const popoverTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="popover"]'));
    popoverTriggerList.map(function(popoverTriggerEl) {
        return new bootstrap.Popover(popoverTriggerEl);
    });
    
    // Real-time dashboard updates
    const dashboardUpdateInterval = 60000; // 60 seconds
    if (window.location.pathname.includes('dashboard.php')) {
        setInterval(updateDashboardData, dashboardUpdateInterval);
    }
    
    // Real-time alerts polling
    const alertsUpdateInterval = 30000; // 30 seconds
    let alertsPollingActive = true;
    
    if (document.getElementById('alertsCount')) {
        setInterval(function() {
            if (alertsPollingActive && document.visibilityState === 'visible') {
                updateAlertsCount();
            }
        }, alertsUpdateInterval);
    }
    
    // Update alerts count badge
    function updateAlertsCount() {
        SocApi.get('api/alerts/count.php')
            .then(data => {
                if (data.success) {
                    const alertsCountElement = document.getElementById('alertsCount');
                    if (alertsCountElement) {
                        const currentCount = parseInt(alertsCountElement.textContent);
                        const newCount = data.count;
                        
                        if (newCount > currentCount) {
                            // New alerts - show notification
                            SocNotifications.warning(`${newCount - currentCount} new alert(s) received`);
                            
                            // Update count badge
                            alertsCountElement.textContent = newCount;
                            alertsCountElement.classList.add('pulse-animation');
                            
                            // Remove animation class after animation completes
                            setTimeout(() => {
                                alertsCountElement.classList.remove('pulse-animation');
                            }, 2000);
                        } else if (newCount !== currentCount) {
                            // Just update the count
                            alertsCountElement.textContent = newCount;
                        }
                    }
                }
            })
            .catch(error => {
                console.error('Error updating alerts count:', error);
                // Don't show notification for this error as it's a background task
            });
    }
    
    // Update dashboard data
    function updateDashboardData() {
        SocApi.get('api/dashboard/stats.php')
            .then(data => {
                if (data.success) {
                    // Update alert stats
                    if (data.alertStats) {
                        updateChartData(alertSeverityChart, data.alertStats);
                    }
                    
                    // Update incident stats
                    if (data.incidentStats) {
                        updateChartData(incidentStatusChart, data.incidentStats);
                    }
                    
                    // Update recent alerts
                    if (data.recentAlerts && document.getElementById('recentAlertsTable')) {
                        updateRecentAlerts(data.recentAlerts);
                    }
                    
                    // Update recent incidents
                    if (data.recentIncidents && document.getElementById('recentIncidentsTable')) {
                        updateRecentIncidents(data.recentIncidents);
                    }
                }
            })
            .catch(error => {
                console.error('Error updating dashboard data:', error);
                // Don't show notification for this error as it's a background task
            });
    }
    
    // Update chart data
    function updateChartData(chart, newData) {
        if (!chart) return;
        
        chart.data.datasets[0].data = newData;
        chart.update();
    }
    
    // Update recent alerts table
    function updateRecentAlerts(alerts) {
        const tableBody = document.querySelector('#recentAlertsTable tbody');
        if (!tableBody) return;
        
        // Clear existing rows
        tableBody.innerHTML = '';
        
        // Add new rows
        alerts.forEach(alert => {
            const row = document.createElement('tr');
            
            // Determine severity class
            const severityClass = SocUtils.getSeverityClass(alert.severity);
            
            // Determine status class
            const statusClass = SocUtils.getStatusClass(alert.status);
            
            // Create row HTML
            row.innerHTML = `
                <td>
                    <span class="badge bg-${severityClass}">${SocUtils.escapeHTML(alert.severity)}</span>
                </td>
                <td>
                    <a href="alert-details.php?id=${alert.alert_id}" class="text-decoration-none">
                        ${SocUtils.escapeHTML(alert.alert_message)}
                    </a>
                    <div class="small text-muted">${SocUtils.escapeHTML(alert.rule_name || '')}</div>
                </td>
                <td>
                    <span class="small">${SocUtils.formatDate(alert.created_at)}</span>
                </td>
                <td>
                    <span class="badge bg-${statusClass}">${SocUtils.escapeHTML(alert.status)}</span>
                </td>
            `;
            
            tableBody.appendChild(row);
        });
    }
    
    // Update recent incidents table
    function updateRecentIncidents(incidents) {
        const tableBody = document.querySelector('#recentIncidentsTable tbody');
        if (!tableBody) return;
        
        // Clear existing rows
        tableBody.innerHTML = '';
        
        // Add new rows
        incidents.forEach(incident => {
            const row = document.createElement('tr');
            
            // Determine severity class
            const severityClass = SocUtils.getSeverityClass(incident.severity);
            
            // Determine status class
            const statusClass = SocUtils.getStatusClass(incident.status);
            
            // Create row HTML
            row.innerHTML = `
                <td>
                    <span class="badge bg-${severityClass}">${SocUtils.escapeHTML(incident.severity)}</span>
                </td>
                <td>
                    <a href="incident-details.php?id=${incident.incident_id}" class="text-decoration-none">
                        ${SocUtils.escapeHTML(incident.title)}
                    </a>
                    <div class="small text-muted">${SocUtils.formatDate(incident.created_at)}</div>
                </td>
                <td>
                    <span class="badge bg-${statusClass}">${SocUtils.escapeHTML(incident.status)}</span>
                </td>
                <td>
                    ${incident.assigned_to 
                        ? `<span class="badge bg-secondary">${SocUtils.escapeHTML(incident.assigned_to)}</span>` 
                        : '<span class="badge bg-light text-dark">Unassigned</span>'}
                </td>
            `;
            
            tableBody.appendChild(row);
        });
    }
    
    // Handle visibility change to pause polling when tab is not visible
    document.addEventListener('visibilitychange', function() {
        alertsPollingActive = document.visibilityState === 'visible';
        
        // If becoming visible again, update immediately
        if (alertsPollingActive) {
            updateAlertsCount();
            if (window.location.pathname.includes('dashboard.php')) {
                updateDashboardData();
            }
        }
    });
    
    // Handle form validation
    const forms = document.querySelectorAll('.needs-validation');
    Array.from(forms).forEach(form => {
        form.addEventListener('submit', event => {
            if (!form.checkValidity()) {
                event.preventDefault();
                event.stopPropagation();
            }
            
            form.classList.add('was-validated');
        }, false);
    });
    
    // Handle copy to clipboard buttons
    document.querySelectorAll('.btn-copy').forEach(button => {
        button.addEventListener('click', function() {
            const textToCopy = this.getAttribute('data-copy');
            if (textToCopy) {
                SocUtils.copyToClipboard(textToCopy);
            }
        });
    });
    
    // Handle dark mode toggle if present
    const darkModeToggle = document.getElementById('darkModeToggle');
    if (darkModeToggle) {
        // Check for saved theme preference
        const savedTheme = localStorage.getItem('theme');
        if (savedTheme === 'dark') {
            document.body.classList.add('dark-mode');
            darkModeToggle.checked = true;
        }
        
        // Handle theme toggle
        darkModeToggle.addEventListener('change', function() {
            if (this.checked) {
                document.body.classList.add('dark-mode');
                localStorage.setItem('theme', 'dark');
            } else {
                document.body.classList.remove('dark-mode');
                localStorage.setItem('theme', 'light');
            }
        });
    }
    
    // Handle expandable sections
    document.querySelectorAll('.expandable-trigger').forEach(trigger => {
        trigger.addEventListener('click', function() {
            const targetId = this.getAttribute('data-target');
            const target = document.getElementById(targetId);
            
            if (target) {
                target.classList.toggle('expanded');
                this.classList.toggle('expanded');
                
                // Update aria attributes
                const expanded = target.classList.contains('expanded');
                this.setAttribute('aria-expanded', expanded);
                
                // Update icon if present
                const icon = this.querySelector('.expandable-icon');
                if (icon) {
                    if (expanded) {
                        icon.classList.replace('fa-chevron-down', 'fa-chevron-up');
                    } else {
                        icon.classList.replace('fa-chevron-up', 'fa-chevron-down');
                    }
                }
            }
        });
    });
    
    // Add logout confirmation
    const logoutLink = document.querySelector('a[href="logout.php"]');
    if (logoutLink) {
        logoutLink.addEventListener('click', function(e) {
            const confirmed = confirm('Are you sure you want to log out?');
            if (!confirmed) {
                e.preventDefault();
            }
        });
    }
    
    // Active sidebar highlight
    const currentPage = window.location.pathname.split('/').pop();
    document.querySelectorAll('.sidebar .nav-link').forEach(link => {
        const href = link.getAttribute('href');
        if (href === currentPage || (currentPage === '' && href === 'dashboard.php')) {
            link.classList.add('active');
        }
    });
});

// Export globally accessible objects
window.SocNotifications = SocNotifications;
window.SocUtils = SocUtils;
window.SocApi = SocApi;
