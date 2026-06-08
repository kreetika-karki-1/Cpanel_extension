/**
 * FRO (File Integrity & Resource Optimizer) JavaScript
 * Minimal dependencies - vanilla JS for Jupiter theme compatibility
 */

(function() {
    'use strict';
    
    /**
     * Initialize page on load
     */
    document.addEventListener('DOMContentLoaded', function() {
        initializeFRO();
    });
    
    /**
     * Main initialization function
     */
    function initializeFRO() {
        setupEventListeners();
        setupAutoRefresh();
    }
    
    /**
     * Setup event listeners
     */
    function setupEventListeners() {
        // Filter listeners
        var filterSelect = document.getElementById('severityFilter');
        if (filterSelect) {
            filterSelect.addEventListener('change', function(e) {
                filterAlerts(e.target.value);
            });
        }
        
        // Action buttons
        var actionButtons = document.querySelectorAll('[data-action]');
        actionButtons.forEach(function(btn) {
            btn.addEventListener('click', function(e) {
                e.preventDefault();
                var action = this.dataset.action;
                var eventId = this.dataset.eventId;
                handleAction(action, eventId);
            });
        });
    }
    
    /**
     * Setup auto-refresh for metrics
     */
    function setupAutoRefresh() {
        // Refresh metrics every 2 minutes
        setInterval(function() {
            var optimizerSection = document.querySelector('.fro-optimizer-section');
            if (optimizerSection) {
                // In a real app, would fetch via AJAX
                // location.reload();
            }
        }, 120000);
    }
    
    /**
     * Filter alerts by severity
     */
    function filterAlerts(severity) {
        var rows = document.querySelectorAll('.fro-alert-row');
        rows.forEach(function(row) {
            if (severity === 'all' || row.dataset.severity === severity) {
                row.style.display = '';
            } else {
                row.style.display = 'none';
            }
        });
    }
    
    /**
     * Handle action buttons (approve, quarantine, etc.)
     */
    function handleAction(action, eventId) {
        var confirmMsg = '';
        switch(action) {
            case 'approve':
                confirmMsg = 'Update baseline with this file change?';
                break;
            case 'quarantine':
                confirmMsg = 'Quarantine this file?';
                break;
            case 'restore':
                confirmMsg = 'Restore this file from backup?';
                break;
            default:
                return;
        }
        
        if (confirm(confirmMsg)) {
            // In a real app, would use AJAX to POST the action
            var url = '?action=' + action + '&event_id=' + eventId;
            window.location.href = url;
        }
    }
    
    /**
     * Format timestamp for display
     */
    function formatTimestamp(timestamp) {
        var date = new Date(timestamp * 1000);
        return date.toLocaleDateString() + ' ' + date.toLocaleTimeString();
    }
    
    /**
     * Show notification
     */
    function showNotification(message, type) {
        type = type || 'info';
        
        var notification = document.createElement('div');
        notification.className = 'fro-notification fro-notification-' + type;
        notification.textContent = message;
        notification.style.cssText = `
            position: fixed;
            top: 20px;
            right: 20px;
            z-index: 9999;
            padding: 15px 20px;
            border-radius: 4px;
            background-color: var(--fro-${type});
            color: white;
            box-shadow: 0 2px 8px rgba(0,0,0,0.2);
            animation: slideIn 0.3s ease;
        `;
        
        document.body.appendChild(notification);
        
        setTimeout(function() {
            notification.style.animation = 'slideOut 0.3s ease';
            setTimeout(function() {
                document.body.removeChild(notification);
            }, 300);
        }, 3000);
    }
    
    // Export functions for global use
    window.FRO = {
        filterAlerts: filterAlerts,
        handleAction: handleAction,
        showNotification: showNotification
    };
    
})();

// Animation keyframes
var style = document.createElement('style');
style.textContent = `
    @keyframes slideIn {
        from {
            transform: translateX(400px);
            opacity: 0;
        }
        to {
            transform: translateX(0);
            opacity: 1;
        }
    }
    
    @keyframes slideOut {
        from {
            transform: translateX(0);
            opacity: 1;
        }
        to {
            transform: translateX(400px);
            opacity: 0;
        }
    }
`;
document.head.appendChild(style);
