<?php
/**
 * FRO File Integrity Alerts Detail View
 * Shows all detected file changes with actions (Approve, Quarantine, Restore)
 */

require_once '/usr/local/cpanel/php/cpanel.php';
$cpanel = new CPANEL();

if (!$cpanel->check_token()) {
    header('HTTP/1.1 403 Forbidden');
    exit('Access Denied');
}

$username = $cpanel->get_user();
$user_home = "/home/{$username}";
$fro_db = "{$user_home}/.fro/fim.db";
$action = $_GET['action'] ?? null;
$event_id = isset($_GET['event_id']) ? (int)$_GET['event_id'] : null;

// Initialize database
$db = null;
if (file_exists($fro_db)) {
    try {
        $db = new PDO("sqlite:{$fro_db}");
        $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    } catch (Exception $e) {
        error_log("FRO DB Error: " . $e->getMessage());
    }
}

// Handle actions
if ($db && $action && $event_id) {
    if ($action === 'approve') {
        // Approve change - update baseline
        try {
            $stmt = $db->prepare("SELECT file_path, new_hash, new_perms FROM fim_events WHERE event_id = ?");
            $stmt->execute([$event_id]);
            $event = $stmt->fetch(PDO::FETCH_ASSOC);
            
            if ($event) {
                $db->prepare("
                    INSERT OR REPLACE INTO fim_baseline (file_path, hash, perms, size, mtime, created_at)
                    SELECT ?, ?, ?, 0, ?, ?
                ")->execute([
                    $event['file_path'],
                    $event['new_hash'],
                    $event['new_perms'],
                    time(),
                    time()
                ]);
                
                $db->prepare("UPDATE fim_events SET resolved = 1 WHERE event_id = ?")->execute([$event_id]);
            }
        } catch (Exception $e) {
            error_log("Approve error: " . $e->getMessage());
        }
    }
    elseif ($action === 'resolve') {
        // Mark as resolved without changing baseline
        try {
            $db->prepare("UPDATE fim_events SET resolved = 1 WHERE event_id = ?")->execute([$event_id]);
        } catch (Exception $e) {
            error_log("Resolve error: " . $e->getMessage());
        }
    }
}

?>
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>File Integrity Alerts - FRO</title>
    <link rel="stylesheet" href="/fro/assets/fro.css">
</head>
<body>
<div class="fro-container">
    <div class="fro-header">
        <a href="index.live.php" class="fro-back-link">← Back to Dashboard</a>
        <h1>File Integrity Alerts</h1>
    </div>
    
    <div class="fro-alerts-section">
        <?php if ($db): ?>
            <div class="fro-filter-bar">
                <label>Filter by Severity:</label>
                <select id="severityFilter" onchange="filterAlerts(this.value)">
                    <option value="all">All Alerts</option>
                    <option value="critical">Critical Only</option>
                    <option value="warning">Warnings Only</option>
                    <option value="info">Info Only</option>
                </select>
            </div>
            
            <table class="fro-table fro-alerts-table">
                <thead>
                    <tr>
                        <th>File Path</th>
                        <th>Event Type</th>
                        <th>Severity</th>
                        <th>Timestamp</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody>
                    <?php
                    try {
                        $stmt = $db->prepare("
                            SELECT event_id, file_path, event_type, severity, timestamp, resolved 
                            FROM fim_events 
                            ORDER BY timestamp DESC, severity DESC
                        ");
                        $stmt->execute();
                        $events = $stmt->fetchAll(PDO::FETCH_ASSOC);
                        
                        if (empty($events)) {
                            echo "<tr><td colspan='5' class='fro-empty-state'>No integrity events recorded.</td></tr>";
                        } else {
                            foreach ($events as $event) {
                                $file = htmlspecialchars(basename($event['file_path']));
                                $time = date('M d, Y g:i A', $event['timestamp']);
                                $badge = $event['resolved'] ? 'fro-badge-resolved' : 'fro-badge-' . strtolower($event['severity']);
                                $status = $event['resolved'] ? '✓ Resolved' : htmlspecialchars(ucfirst($event['severity']));
                                
                                echo "<tr class='fro-alert-row' data-severity='{$event['severity']}'>
                                    <td class='fro-file-cell'>" . htmlspecialchars($event['file_path']) . "</td>
                                    <td>" . htmlspecialchars(ucfirst($event['event_type'])) . "</td>
                                    <td><span class='$badge'>$status</span></td>
                                    <td>$time</td>
                                    <td class='fro-actions-cell'>";
                                
                                if (!$event['resolved']) {
                                    echo "<a href='?action=approve&event_id={$event['event_id']}' class='fro-btn-sm fro-btn-success'>Approve</a> ";
                                    echo "<a href='?action=resolve&event_id={$event['event_id']}' class='fro-btn-sm fro-btn-secondary'>Ignore</a>";
                                }
                                echo "</td></tr>";
                            }
                        }
                    } catch (Exception $e) {
                        error_log("Query error: " . $e->getMessage());
                        echo "<tr><td colspan='5' class='fro-error'>Error loading alerts.</td></tr>";
                    }
                    ?>
                </tbody>
            </table>
        <?php else: ?>
            <p class="fro-error">Database not accessible. Please initialize File Integrity Monitor first.</p>
        <?php endif; ?>
    </div>
</div>

<script>
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
</script>
</body>
</html>
