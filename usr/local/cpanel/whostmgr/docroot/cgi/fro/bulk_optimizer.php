<?php
/**
 * FRO Bulk Optimizer - WHM SRO Management Interface
 * Location: /usr/local/cpanel/whostmgr/docroot/cgi/fro/bulk_optimizer.php
 */

if (!isset($_SERVER['REMOTE_USER']) || empty($_SERVER['REMOTE_USER'])) {
    header('HTTP/1.1 403 Forbidden');
    exit('Access Denied');
}

$whm_db_path = '/var/cpanel/fro/metrics.db';
$db = null;
$message = '';

if (file_exists($whm_db_path)) {
    try {
        $db = new PDO("sqlite:{$whm_db_path}");
        $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    } catch (Exception $e) {
        error_log("DB Error: " . $e->getMessage());
    }
}

// Handle apply action
if ($_POST['action'] === 'apply' && $db) {
    $rec_ids = array_filter(explode(',', $_POST['recommendation_ids'] ?? ''));
    
    foreach ($rec_ids as $rec_id) {
        $rec_id = (int)$rec_id;
        
        try {
            // Get recommendation
            $stmt = $db->prepare("
                SELECT account, domain, recommended_pm_strategy, recommended_max_children, recommended_max_requests
                FROM sro_recommendations WHERE recommendation_id = ?
            ");
            $stmt->execute([$rec_id]);
            $rec = $stmt->fetch(PDO::FETCH_ASSOC);
            
            if (!$rec) continue;
            
            // Save snapshot before applying
            $yaml_path = "/var/cpanel/userdata/{$rec['account']}/{$rec['domain']}.php-fpm.yaml";
            $yaml_content = file_exists($yaml_path) ? file_get_contents($yaml_path) : '';
            
            $db->prepare("
                INSERT INTO sro_yaml_snapshots (account, domain, yaml_content, snapshot_at)
                VALUES (?, ?, ?, ?)
            ")->execute([
                $rec['account'],
                $rec['domain'],
                $yaml_content,
                time()
            ]);
            
            // Build new YAML configuration
            $new_yaml = "pm: {$rec['recommended_pm_strategy']}\n";
            $new_yaml .= "pm_max_children: {$rec['recommended_max_children']}\n";
            $new_yaml .= "pm_max_requests: {$rec['recommended_max_requests']}\n";
            
            if (!is_dir(dirname($yaml_path))) {
                mkdir(dirname($yaml_path), 0755, true);
            }
            file_put_contents($yaml_path, $new_yaml);
            
            // Mark as applied
            $db->prepare("
                UPDATE sro_recommendations SET applied_at = ?, applied_by = ?
                WHERE recommendation_id = ?
            ")->execute([time(), $_SERVER['REMOTE_USER'], $rec_id]);
            
            $message = "✓ Applied {$rec['recommended_pm_strategy']} strategy to {$rec['domain']}";
        } catch (Exception $e) {
            error_log("Apply error: " . $e->getMessage());
            $message = "✗ Error applying recommendations: " . $e->getMessage();
        }
    }
}

// Fetch recommendations
$recommendations = [];
if ($db) {
    try {
        $stmt = $db->prepare("
            SELECT recommendation_id, account, domain, recommended_pm_strategy, 
                   recommended_max_children, confidence_score, reason, applied_at
            FROM sro_recommendations
            ORDER BY applied_at ASC, confidence_score DESC
        ");
        $stmt->execute();
        $recommendations = $stmt->fetchAll(PDO::FETCH_ASSOC);
    } catch (Exception $e) {
        error_log("Query error: " . $e->getMessage());
    }
}

?>
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>SRO Bulk Optimizer - FRO</title>
    <link rel="stylesheet" href="/fro/assets/fro.css">
</head>
<body>
<div class="fro-container">
    <div class="fro-header">
        <a href="admin_dashboard.php" class="fro-back-link">← Back to Admin Dashboard</a>
        <h1>Smart Resource Optimizer - Bulk Apply</h1>
    </div>
    
    <?php if ($message): ?>
        <div style="background-color: #d4edda; color: #155724; padding: 15px; border-radius: 4px; margin-bottom: 20px;">
            <?php echo htmlspecialchars($message); ?>
        </div>
    <?php endif; ?>
    
    <form method="POST" id="bulkApplyForm">
        <div style="margin-bottom: 20px;">
            <button type="button" onclick="selectAllPending()" class="fro-btn fro-btn-secondary" style="margin-right: 10px;">Select All Pending</button>
            <button type="submit" name="action" value="apply" class="fro-btn fro-btn-primary">Apply Selected</button>
        </div>
        
        <table class="fro-table">
            <thead>
                <tr>
                    <th><input type="checkbox" id="selectAllCb" onchange="toggleAll(this)"></th>
                    <th>Account</th>
                    <th>Domain</th>
                    <th>Recommended Strategy</th>
                    <th>Max Children</th>
                    <th>Max Requests</th>
                    <th>Confidence</th>
                    <th>Reason</th>
                    <th>Status</th>
                </tr>
            </thead>
            <tbody>
                <?php foreach ($recommendations as $rec): ?>
                    <?php 
                    $is_applied = !empty($rec['applied_at']);
                    $status = $is_applied ? '✓ Applied' : 'Pending';
                    $status_class = $is_applied ? 'fro-badge-resolved' : 'fro-badge-info';
                    ?>
                    <tr>
                        <td>
                            <input type="checkbox" name="recommendation_ids" value="<?php echo $rec['recommendation_id']; ?>" 
                                   <?php echo $is_applied ? 'disabled' : ''; ?>>
                        </td>
                        <td><?php echo htmlspecialchars($rec['account']); ?></td>
                        <td><?php echo htmlspecialchars($rec['domain']); ?></td>
                        <td><code><?php echo htmlspecialchars($rec['recommended_pm_strategy']); ?></code></td>
                        <td><?php echo $rec['recommended_max_children']; ?></td>
                        <td><?php echo $rec['recommended_max_children'] ? '500-1000' : 'N/A'; ?></td>\n                        <td><?php echo round(($rec['confidence_score'] ?? 0) * 100); ?>%</td>\n                        <td style=\"max-width: 300px; word-break: break-word;\"><?php echo htmlspecialchars($rec['reason']); ?></td>\n                        <td><span class=\"<?php echo $status_class; ?>\"><?php echo $status; ?></span></td>\n                    </tr>\n                <?php endforeach; ?>\n            </tbody>\n        </table>\n        \n        <input type=\"hidden\" name=\"action\" value=\"apply\">\n    </form>\n</div>\n\n<script>\nfunction selectAllPending() {\n    document.querySelectorAll('input[name=\"recommendation_ids\"]:not(:disabled)').forEach(cb => {\n        cb.checked = true;\n    });\n}\n\nfunction toggleAll(cb) {\n    document.querySelectorAll('input[name=\"recommendation_ids\"]:not(:disabled)').forEach(c => {\n        c.checked = cb.checked;\n    });\n}\n</script>\n</body>\n</html>\n
