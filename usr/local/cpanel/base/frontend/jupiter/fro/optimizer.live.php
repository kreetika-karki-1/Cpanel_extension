<?php
/* optimizer.live.php
 * Read-only metrics for cPanel users (simple gauges and recommendation card)
 */
require_once "/usr/local/cpanel/php/cpanel.php";
$cpanel = new CPANEL();

$user = getenv('USER') ?: $_GET['user'] ?? '';
if (!$user) { echo "<div class=\"callout callout-danger\">User not identified</div>"; exit; }
$user = preg_replace('/[^a-z0-9_\-]/i', '', $user);

$res = $cpanel->uapi('FRO', 'get_metrics', ['user' => $user]);
$metrics = $res['data'] ?? [];
$rec = $cpanel->uapi('FRO', 'get_recommendations', ['user' => $user]);
$recommendation = $rec['data'] ?? [];

?>
<div class="container">
  <h2>Smart Resource Optimizer</h2>
  <div class="card" style="padding:12px;margin:8px;">
    <h4>Primary Recommendation</h4>
    <p><?php echo htmlspecialchars($recommendation['summary'] ?? 'No recommendations available'); ?></p>
  </div>
  <!-- Simple lightweight inline SVG gauges could be added here -->
</div>

<?php $cpanel->end(); ?>
