#!/usr/bin/php
<?php
/* admin_dashboard.php - WHM admin entry for FRO
 * This script must be executed by WHM and runs under root. It provides an admin view.
 */
require_once '/usr/local/cpanel/php/cpanel.php';
$cpanel = new CPANEL();

// For brevity, show a placeholder. Real implementation should call UAPI::FRO::get_metrics and Optimizer
echo "<h2>FRO WHM Admin Dashboard</h2>\n";

// Example link to policy manager
echo "<p><a href=\"policy_manager.php\">Policy Manager</a> | <a href=\"bulk_optimizer.php\">Bulk Optimizer</a></p>";

$cpanel->end();
?>
