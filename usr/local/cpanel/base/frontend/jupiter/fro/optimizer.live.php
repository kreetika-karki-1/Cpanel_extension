<?php
/**
 * FRO Resource Optimizer (SRO) - Read-only metrics view for end-user
 * Shows PHP-FPM metrics and recommendations from WHM collector
 */

require_once '/usr/local/cpanel/php/cpanel.php';
$cpanel = new CPANEL();

if (!$cpanel->check_token()) {
    header('HTTP/1.1 403 Forbidden');
    exit('Access Denied');
}

$username = $cpanel->get_user();

// Try to read from WHM database (read-only)
$whm_db_path = '/var/cpanel/fro/metrics.db';
$db = null;

if (file_exists($whm_db_path)) {
    try {
        $db = new PDO("sqlite:{$whm_db_path}", null, null, array(PDO::SQLITE_ATTR_OPEN_FLAGS => PDO::SQLITE_OPEN_READONLY));
        $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    } catch (Exception $e) {
        error_log("FRO Metrics DB Error: " . $e->getMessage());
    }
}

$metrics = array();
$recommendations = array();

if ($db) {
    try {
        // Get latest metrics for user's domains
        $stmt = $db->prepare("
            SELECT domain, 
                   active_processes, idle_processes, avg_response_time_ms, memory_usage_mb,
                   collected_at
            FROM sro_phpfpm_metrics
            WHERE account = ? 
            ORDER BY collected_at DESC
            LIMIT 1
        ");
        $stmt->execute([$username]);
        $metrics = $stmt->fetch(PDO::FETCH_ASSOC) ?: array();
        
        // Get latest recommendations
        $stmt = $db->prepare("
            SELECT recommended_pm_strategy, recommended_max_children, 
                   recommended_max_requests, confidence_score, reason
            FROM sro_recommendations
            WHERE account = ?
            ORDER BY generated_at DESC
            LIMIT 1
        ");
        $stmt->execute([$username]);
        $recommendations = $stmt->fetch(PDO::FETCH_ASSOC) ?: array();
    } catch (Exception $e) {
        error_log("Query error: " . $e->getMessage());
    }
}

?>
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Resource Optimizer - FRO</title>
    <link rel="stylesheet" href="/fro/assets/fro.css">
</head>
<body>
<div class="fro-container">
    <div class="fro-header">
        <a href="index.live.php" class="fro-back-link">← Back to Dashboard</a>
        <h1>Smart Resource Optimizer</h1>
    </div>
    
    <div class="fro-optimizer-section">
        <?php if (!empty($metrics)): ?>
            <!-- Current Metrics -->
            <div class="fro-card fro-card-metrics">
                <h2>Current Performance Metrics</h2>
                <div class="fro-metrics-grid">
                    <div class="fro-metric">
                        <div class="fro-metric-label">Active PHP Workers</div>
                        <div class="fro-metric-value"><?php echo htmlspecialchars($metrics['active_processes'] ?? '—'); ?></div>
                        <div class="fro-metric-bar">
                            <div style="width: <?php echo (($metrics['active_processes'] ?? 0) / 20) * 100; ?>%;"></div>
                        </div>
                    </div>
                    
                    <div class="fro-metric">
                        <div class="fro-metric-label">Idle Workers</div>
                        <div class="fro-metric-value"><?php echo htmlspecialchars($metrics['idle_processes'] ?? '—'); ?></div>
                    </div>
                    
                    <div class="fro-metric">
                        <div class="fro-metric-label">Avg Response Time</div>
                        <div class="fro-metric-value"><?php echo round($metrics['avg_response_time_ms'] ?? 0, 1); ?> ms</div>
                    </div>
                    
                    <div class="fro-metric">
                        <div class="fro-metric-label">Memory Usage</div>
                        <div class="fro-metric-value"><?php echo round($metrics['memory_usage_mb'] ?? 0, 1); ?> MB</div>
                    </div>
                </div>
                <p class="fro-metric-timestamp">
                    Last collected: <?php echo date('M d, Y g:i A', $metrics['collected_at'] ?? time()); ?>
                </p>
            </div>
            
            <?php if (!empty($recommendations)): ?>
                <!-- Recommendations -->
                <div class="fro-card fro-card-recommendations">
                    <h2>Optimization Recommendations</h2>
                    <div class="fro-recommendation-item">
                        <div class="fro-rec-header">
                            <span class="fro-confidence-badge" style="background: hsl(120, 100%, 40%);">
                                <?php echo round(($recommendations['confidence_score'] ?? 0) * 100); ?>% Confidence
                            </span>
                        </div>
                        <div class="fro-rec-body">
                            <p><strong>Reason:</strong> <?php echo htmlspecialchars($recommendations['reason'] ?? 'No reason available'); ?></p>
                            <ul class="fro-rec-list">
                                <li><strong>Process Manager Strategy:</strong> 
                                    <code><?php echo htmlspecialchars($recommendations['recommended_pm_strategy'] ?? '—'); ?></code>
                                </li>
                                <li><strong>Recommended Max Workers:</strong> 
                                    <code><?php echo htmlspecialchars($recommendations['recommended_max_children'] ?? '—'); ?></code>
                                </li>
                                <li><strong>Max Requests (memory leak protection):</strong> 
                                    <code><?php echo htmlspecialchars($recommendations['recommended_max_requests'] ?? '—'); ?></code>
                                </li>
                            </ul>
                            <p class="fro-rec-note">
                                ℹ️ <strong>Note:</strong> Recommendations are generated based on 7 days of performance data. 
                                WHM administrators can apply these settings in bulk via the WHM plugin.
                            </p>
                        </div>
                    </div>
                </div>
            <?php endif; ?>
        <?php else: ?>
            <div class="fro-empty-state">
                <p>Metrics are being collected. This page will update within the next collection cycle.</p>
                <p style="font-size: 0.9em; color: #666;">Metrics are typically available within 1-2 minutes of the metrics collector starting.</p>
            </div>
        <?php endif; ?>
    </div>
</div>

<script src="/fro/assets/fro.js"></script>
</body>
</html>