<?php
/* index.live.php
 * Main cPanel dashboard entry for FRO. Shows summary cards and links to detailed views.
 * Uses cPanel LiveAPI via CPANEL class.
 */
require_once "/usr/local/cpanel/php/cpanel.php";
$cpanel = new CPANEL();

// cPanel-specific rendering should happen inside the Jupiter frame; this file is a live UI extension
$user = getenv('USER') ?: $_GET['user'] ?? '';
if (!$user) {
    echo "<div class=\"callout callout-danger\">User not identified</div>";
    exit;
}
// Basic input validation
$user = preg_replace('/[^a-z0-9_\-]/i', '', $user);

// TODO: Fetch counts from UAPI::FRO::list_alerts
$alerts = $cpanel->uapi('FRO', 'list_alerts', ['user' => $user]);

$files_changed_today = $alerts['data']['files_changed_today'] ?? 0;
$unreviewed = $alerts['data']['unreviewed'] ?? 0;
$last_scan = $alerts['data']['last_scan'] ?? 'never';

?>
<div class="container">
  <h2>FRO — File Integrity & Resource Optimizer</h2>
  <div class="cards-row">
    <div class="card" style="background:#f8f9fa;padding:12px;border-radius:6px;margin:8px;display:inline-block;">
      <h3><?php echo intval($files_changed_today); ?></h3>
      <p>Files changed today</p>
    </div>
    <div class="card" style="background:#fff3cd;padding:12px;border-radius:6px;margin:8px;display:inline-block;">
      <h3><?php echo intval($unreviewed); ?></h3>
      <p>Unreviewed alerts</p>
    </div>
    <div class="card" style="background:#e9ecef;padding:12px;border-radius:6px;margin:8px;display:inline-block;">
      <h3><?php echo htmlspecialchars($last_scan); ?></h3>
      <p>Last scan time</p>
    </div>
  </div>
  <p><a class="btn btn-primary" href="/cgi/fro/integrity.live.php?user=<?php echo urlencode($user); ?>">View details</a></p>
</div>

<?php $cpanel->end(); ?>
