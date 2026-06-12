<?php
/**
 * FRO WHM Admin Dashboard
 * Location: /usr/local/cpanel/whostmgr/docroot/cgi/fro/admin_dashboard.php
 */

// Verify WHM authentication
if (!isset($_SERVER['REMOTE_USER']) || empty($_SERVER['REMOTE_USER'])) {
    header('HTTP/1.1 403 Forbidden');
    exit('Access Denied');
}

$whm_db_path = '/var/cpanel/fro/metrics.db';
$db = null;

if (file_exists($whm_db_path)) {
    try {
        $db = new PDO("sqlite:{$whm_db_path}");
        $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    } catch (Exception $e) {
        error_log("WHM FRO DB Error: " . $e->getMessage());
    }
}

// Fetch WHM-level statistics
$stats = array(
    'total_accounts' => 0,
    'total_events' => 0,
    'critical_events' => 0,
    'recommendations_pending' => 0,
);

if ($db) {
    try {
        // Count accounts with metrics
        $stmt = $db->prepare("
            SELECT COUNT(DISTINCT account) as count FROM sro_phpfpm_metrics
        ");
        $stmt->execute();
        $row = $stmt->fetch(PDO::FETCH_ASSOC);
        $stats['total_accounts'] = $row ? $row['count'] : 0;
        
        // Pending recommendations
        $stmt = $db->prepare("
            SELECT COUNT(*) as count FROM sro_recommendations WHERE applied_at IS NULL
        ");
        $stmt->execute();
        $row = $stmt->fetch(PDO::FETCH_ASSOC);
        $stats['recommendations_pending'] = $row ? $row['count'] : 0;
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
    <title>FRO Admin Dashboard - WHM</title>
    <link rel="stylesheet" href="/fro/assets/fro.css">
    <style>
        .whm-header {
            background-color: #293a4a;
            color: white;
            padding: 20px;
            margin: -20px -20px 20px -20px;
        }
    </style>
</head>
<body>
<div class="whm-header">
    <h1>FRO - File Integrity & Resource Optimizer</h1>
    <p>WHM Administrator Dashboard</p>
</div>

<div class="fro-container">
    <!-- Statistics Cards -->
    <div class="fro-dashboard">
        <div class="fro-card">
            <div class="fro-card-header">
                <h2>Monitored Accounts</h2>
            </div>
            <div class="fro-card-body">
                <div class="fro-stat-value" style="font-size: 3em; text-align: center;">
                    <?php echo $stats['total_accounts']; ?>
                </div>
                <p style="text-align: center; color: #666;">Accounts with FIM/SRO active</p>
            </div>
        </div>
        
        <div class="fro-card">
            <div class="fro-card-header">
                <h2>Pending Recommendations</h2>
            </div>
            <div class="fro-card-body">
                <div class="fro-stat-value" style="font-size: 3em; text-align: center;">
                    <?php echo $stats['recommendations_pending']; ?>
                </div>
                <p style="text-align: center; color: #666;">SRO changes ready to apply</p>
            </div>
        </div>
    </div>
    
    <!-- Admin Navigation -->
    <div style="margin-top: 30px;">
        <h2 style="color: #293a4a; margin-bottom: 15px;">Administration</h2>
        <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 15px;">
            <a href="policy_manager.php" style="
                display: block;
                padding: 20px;
                background: white;
                border: 1px solid #ddd;
                border-radius: 8px;
                text-decoration: none;
                color: #333;
                box-shadow: 0 2px 8px rgba(0,0,0,0.1);
            ">
                <h3 style="color: #0055cc; margin-top: 0;">FIM Policy Manager</h3>
                <p>Configure global FIM policies, exclusions, and alert thresholds</p>
            </a>
            
            <a href="bulk_optimizer.php" style="
                display: block;
                padding: 20px;
                background: white;
                border: 1px solid #ddd;
                border-radius: 8px;
                text-decoration: none;
                color: #333;
                box-shadow: 0 2px 8px rgba(0,0,0,0.1);
            ">
                <h3 style="color: #0055cc; margin-top: 0;">SRO Bulk Optimizer</h3>
                <p>Review and apply resource optimization recommendations</p>
            </a>
            
            <a href="incident_feed.php" style="
                display: block;
                padding: 20px;
                background: white;
                border: 1px solid #ddd;
                border-radius: 8px;
                text-decoration: none;
                color: #333;
                box-shadow: 0 2px 8px rgba(0,0,0,0.1);
            ">
                <h3 style="color: #0055cc; margin-top: 0;">Incident Feed</h3>
                <p>Real-time cross-account FIM alerts and threat tracking</p>
            </a>
        </div>
    </div>
</div>

<script src="/fro/assets/fro.js"></script>
</body>
</html>
