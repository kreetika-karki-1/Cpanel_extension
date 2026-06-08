<?php
/* integrity.live.php
 * Shows alerts table and provides actions: approve, restore, quarantine
 */
require_once "/usr/local/cpanel/php/cpanel.php";
$cpanel = new CPANEL();

$user = getenv('USER') ?: $_GET['user'] ?? '';
if (!$user) { echo "<div class=\"callout callout-danger\">User not identified</div>"; exit; }
$user = preg_replace('/[^a-z0-9_\-]/i', '', $user);

// Get alerts via UAPI FRO::list_alerts
$res = $cpanel->uapi('FRO', 'list_alerts', ['user' => $user]);
$alerts = $res['data']['alerts'] ?? [];

?>
<div class="container">
  <h2>FIM Alerts</h2>
  <table class="table">
    <thead><tr><th>Path</th><th>Type</th><th>Severity</th><th>Old SHA</th><th>New SHA</th><th>Time</th><th>Actions</th></tr></thead>
    <tbody>
    <?php foreach ($alerts as $a): ?>
      <tr>
        <td><?php echo htmlspecialchars($a['path']); ?></td>
        <td><?php echo htmlspecialchars($a['event_type']); ?></td>
        <td><span class="badge badge-" style="background:<?php echo $a['severity']=='critical'?'#dc3545':($a['severity']=='warning'?'#ffc107':'#17a2b8'); ?>;color:#fff;padding:4px;border-radius:4px"><?php echo htmlspecialchars($a['severity']); ?></span></td>
        <td><?php echo htmlspecialchars($a['old_sha256'] ?? ''); ?></td>
        <td><?php echo htmlspecialchars($a['new_sha256'] ?? ''); ?></td>
        <td><?php echo htmlspecialchars(date('Y-m-d H:i:s', $a['timestamp'] ?? time())); ?></td>
        <td>
          <form method="post" action="/cgi/fro/admin_action.php">
            <input type="hidden" name="user" value="<?php echo htmlspecialchars($user); ?>">
            <input type="hidden" name="path" value="<?php echo htmlspecialchars($a['path']); ?>">
            <button name="action" value="approve" class="btn btn-success btn-sm">Approve</button>
            <button name="action" value="quarantine" class="btn btn-warning btn-sm">Quarantine</button>
            <button name="action" value="restore" class="btn btn-danger btn-sm">Restore</button>
          </form>
        </td>
      </tr>
    <?php endforeach; ?>
    </tbody>
  </table>
</div>

<?php $cpanel->end(); ?>
