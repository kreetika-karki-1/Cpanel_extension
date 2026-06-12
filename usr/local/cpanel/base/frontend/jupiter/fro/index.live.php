<?php
/**
 * FRO Main Dashboard (cPanel Jupiter Theme)
 * Entry point for File Integrity Monitor and Smart Resource Optimizer
 * Uses cPanel's LiveAPI for authentication and session management
 */

// Bootstrap cPanel LiveAPI
require_once '/usr/local/cpanel/php/cpanel.php';
$cpanel = new CPANEL();

// Verify authentication
if (!$cpanel->check_token()) {
    header('HTTP/1.1 403 Forbidden');
    exit('Access Denied');
}

$username = $cpanel->get_user();
$user_home = "/home/{$username}";
$fro_db = "{$user_home}/.fro/fim.db";

// Initialize database connection
$db = null;
if (file_exists($fro_db)) {
    try {
        $db = new PDO("sqlite:{$fro_db}");
        $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    } catch (Exception $e) {
        error_log("FRO DB Error: " . $e->getMessage());
    }
}

// Fetch summary statistics
$stats = array(
    'files_changed_today' => 0,
    'unreviewed_alerts' => 0,
    'critical_events' => 0,
    'last_baseline' => 'Never',
    'baseline_files' => 0,
);

if ($db) {
    try {
        // Files changed today
        $today_start = strtotime('today');
        $stmt = $db->prepare("
            SELECT COUNT(*) as count FROM fim_events 
            WHERE timestamp >= ? AND resolved = 0
        ");
        $stmt->execute([$today_start]);
        $row = $stmt->fetch(PDO::FETCH_ASSOC);
        $stats['files_changed_today'] = $row ? $row['count'] : 0;
        
        // Unreviewed alerts
        $stmt = $db->prepare("
            SELECT COUNT(*) as count FROM fim_events 
            WHERE resolved = 0 AND severity IN ('critical', 'warning')
        ");
        $stmt->execute();
        $row = $stmt->fetch(PDO::FETCH_ASSOC);
        $stats['unreviewed_alerts'] = $row ? $row['count'] : 0;
        
        // Critical events
        $stmt = $db->prepare("
            SELECT COUNT(*) as count FROM fim_events 
            WHERE severity = 'critical' AND resolved = 0
        ");
        $stmt->execute();
        $row = $stmt->fetch(PDO::FETCH_ASSOC);
        $stats['critical_events'] = $row ? $row['count'] : 0;
        
        // Baseline size
        $stmt = $db->prepare("
            SELECT COUNT(*) as count, MAX(created_at) as latest FROM fim_baseline
        ");
        $stmt->execute();
        $row = $stmt->fetch(PDO::FETCH_ASSOC);
        $stats['baseline_files'] = $row ? $row['count'] : 0;
        if ($row && $row['latest']) {
            $stats['last_baseline'] = date('M d, Y', $row['latest']);
        }
    } catch (Exception $e) {
        error_log("FRO Stats Error: " . $e->getMessage());
    }
}

?>
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>FRO - File Integrity & Resource Optimizer</title>
    <link rel="stylesheet" href="/fro/assets/fro.css">
</head>
<body>
<div class="fro-container">
    <!-- Header -->
    <div class="fro-header">
        <h1>File Integrity & Resource Optimizer</h1>
        <p class="fro-subtitle">Monitor and optimize your account security and performance</p>
    </div>
    
    <!-- Main Dashboard Cards -->
    <div class="fro-dashboard">
        <!-- FIM Widget -->
        <div class="fro-card fro-card-fim">
            <div class="fro-card-header">
                <h2>File Integrity Monitor</h2>
                <span class="fro-badge-<?php echo ($stats['critical_events'] > 0) ? 'critical' : 'info'; ?>">
                    <?php echo $stats['critical_events']; ?> Critical
                </span>
            </div>
            <div class="fro-card-body">
                <div class="fro-stat-row">
                    <span class="fro-stat-label">Files Changed Today:</span>
                    <span class="fro-stat-value"><?php echo $stats['files_changed_today']; ?></span>
                </div>
                <div class="fro-stat-row">
                    <span class="fro-stat-label">Alerts Pending Review:</span>
                    <span class="fro-stat-value"><?php echo $stats['unreviewed_alerts']; ?></span>
                </div>
                <div class="fro-stat-row">
                    <span class="fro-stat-label">Baseline Files:</span>
                    <span class="fro-stat-value"><?php echo $stats['baseline_files']; ?></span>
                </div>
                <div class="fro-stat-row">
                    <span class="fro-stat-label">Last Baseline:</span>
                    <span class="fro-stat-value"><?php echo htmlspecialchars($stats['last_baseline']); ?></span>
                </div>
            </div>
            <div class="fro-card-footer">
                <a href="integrity.live.php" class="fro-btn fro-btn-primary">View Alerts</a>
                <a href="#" class="fro-btn fro-btn-secondary" onclick="triggerFIMSetup(); return false;">Configure</a>
            </div>
        </div>
        
        <!-- SRO Widget -->
        <div class="fro-card fro-card-sro">
            <div class="fro-card-header">
                <h2>Resource Optimizer</h2>
                <span class="fro-badge-info">Beta</span>
            </div>
            <div class="fro-card-body">
                <div class="fro-stat-row">
                    <span class="fro-stat-label">PHP-FPM Status:</span>
                    <span class="fro-stat-value fro-status-running">● Running</span>
                </div>
                <div class="fro-stat-row">
                    <span class="fro-stat-label">Avg Response Time:</span>
                    <span class="fro-stat-value">45.5 ms</span>
                </div>
                <div class="fro-stat-row">
                    <span class="fro-stat-label">Memory Usage:</span>
                    <span class="fro-stat-value">156 MB / 256 MB</span>
                </div>
                <div class="fro-progress">
                    <div class="fro-progress-bar" style="width: 61%;"></div>
                </div>
            </div>
            <div class="fro-card-footer">
                <a href="optimizer.live.php" class="fro-btn fro-btn-primary">View Metrics</a>
            </div>
        </div>
    </div>
    
    <!-- Recent Events -->
    <div class="fro-recent-events">
        <h3>Recent Activity</h3>
        <?php if ($db && $stats['files_changed_today'] > 0): ?>
            <table class="fro-table">
                <thead>
                    <tr>
                        <th>File</th>
                        <th>Event</th>
                        <th>Severity</th>
                        <th>Time</th>
                    </tr>
                </thead>
                <tbody>
                    <?php 
                    try {
                        $stmt = $db->prepare("
                            SELECT file_path, event_type, severity, timestamp 
                            FROM fim_events 
                            WHERE resolved = 0 
                            ORDER BY timestamp DESC 
                            LIMIT 5
                        ");
                        $stmt->execute();
                        $events = $stmt->fetchAll(PDO::FETCH_ASSOC);
                        
                        foreach ($events as $event) {
                            $badge_class = 'fro-badge-' . strtolower($event['severity']);
                            $file = basename($event['file_path']);
                            $time = date('g:i A', $event['timestamp']);
                            echo "<tr>";
                            echo "<td>" . htmlspecialchars($file) . "</td>";
                            echo "<td>" . htmlspecialchars(ucfirst($event['event_type'])) . "</td>";
                            echo "<td><span class='$badge_class'>" . htmlspecialchars($event['severity']) . "</span></td>";
                            echo "<td>$time</td>";
                            echo "</tr>";
                        }
                    } catch (Exception $e) {}
                    ?>
                </tbody>
            </table>
        <?php else: ?>
            <p class="fro-empty-state">No recent file changes detected.</p>
        <?php endif; ?>
    </div>
</div>

<script src="/fro/assets/fro.js"></script>
<script>
function triggerFIMSetup() {
    alert('FIM Setup wizard coming soon!');
}
</script>
</body>
</html>
