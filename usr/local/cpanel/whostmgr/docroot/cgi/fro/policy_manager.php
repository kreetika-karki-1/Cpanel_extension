#!/usr/bin/php
<?php
/* policy_manager.php - WHM global configuration UI for FRO
 * This is a minimal scaffold.
 */
require_once '/usr/local/cpanel/php/cpanel.php';
$cpanel = new CPANEL();

echo "<h2>FRO Policy Manager</h2>\n";

// In production: list and edit global defaults stored in /var/cpanel/fro/policy.json or WHM DB

$cpanel->end();
?>
