<?php
/* admin_action.php - Handles approve/quarantine/restore actions from integrity.live.php
 * This file is intended to be placed in the cPanel Jupiter frontend path so that
 * POSTing to /cgi/fro/admin_action.php is handled by cPanel's LiveAPI context.
 *
 * Security measures:
 * - Validates the authenticated cPanel user (via getenv('USER'))
 * - Sanitizes and validates paths with realpath() and checks they are under /home/$user
 * - Uses UAPI FRO Perl wrappers for approve/quarantine operations
 * - For restore, attempts to retrieve file content via UAPI Fileman::get_file_content
 *   and writes it back after validation. This is a best-effort restore; integration
 *   with cPanel backups should be added for full backup restores.
 */
require_once "/usr/local/cpanel/php/cpanel.php";
$cpanel = new CPANEL();

// Only accept POST
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    echo json_encode(['status' => 0, 'error' => 'Method not allowed']);
    exit;
}

// Get authenticated cPanel user
$auth_user = getenv('USER') ?: '';
if (!$auth_user) {
    http_response_code(403);
    echo json_encode(['status' => 0, 'error' => 'Unauthenticated']);
    exit;
}

// Extract and sanitize inputs
$action = $_POST['action'] ?? '';
$path = $_POST['path'] ?? '';
$user = $_POST['user'] ?? $auth_user;

// Basic validation
$action = preg_replace('/[^a-z_]/', '', $action);
$user = preg_replace('/[^a-z0-9_\-]/i', '', $user);

// Ensure the acting user matches the authenticated user (prevent acting on other accounts)
if ($user !== $auth_user) {
    http_response_code(403);
    echo json_encode(['status' => 0, 'error' => 'User mismatch']);
    exit;
}

if (empty($path)) {
    http_response_code(400);
    echo json_encode(['status' => 0, 'error' => 'Missing path']);
    exit;
}

// Resolve and validate path
$real = realpath($path);
if ($real === false) {
    // Path may not exist (e.g., deleted), attempt to resolve directory component
    $dir = dirname($path);
    $rdir = realpath($dir);
    if ($rdir === false) {
        http_response_code(400);
        echo json_encode(['status' => 0, 'error' => 'Invalid path']);
        exit;
    }
    $real = $rdir . '/' . basename($path);
}

$home = realpath('/home/' . $user);
if ($home === false || strpos($real, $home) !== 0) {
    http_response_code(403);
    echo json_encode(['status' => 0, 'error' => 'Path outside of user home']);
    exit;
}

// Dispatch actions
try {
    if ($action === 'approve') {
        $res = $cpanel->uapi('FRO', 'approve_alert', ['user' => $user, 'path' => $real]);
        echo json_encode(['status' => 1, 'result' => $res]);
        exit;

    } elseif ($action === 'quarantine') {
        $res = $cpanel->uapi('FRO', 'quarantine_file', ['user' => $user, 'path' => $real]);
        echo json_encode(['status' => 1, 'result' => $res]);
        exit;

    } elseif ($action === 'restore') {
        // Best-effort restore: attempt to fetch file content via Fileman::get_file_content
        $fm = $cpanel->uapi('Fileman', 'get_file_content', ['file' => $real]);
        if (empty($fm) || empty($fm['data']) || !isset($fm['data']['content'])) {
            // If Fileman can't provide content, return an error. In production, integrate with cPanel backups.
            http_response_code(404);
            echo json_encode(['status' => 0, 'error' => 'No content available from Fileman; backup restore not implemented']);
            exit;
        }
        $content = $fm['data']['content'];
        // Double-check path still under user home
        $rp = realpath(dirname($real));
        if ($rp === false || strpos($rp, $home) !== 0) {
            http_response_code(403);
            echo json_encode(['status' => 0, 'error' => 'Invalid restoration path']);
            exit;
        }
        // Write content safely
        $tmp = tempnam(sys_get_temp_dir(), 'fro_restore_');
        if ($tmp === false) {
            http_response_code(500);
            echo json_encode(['status' => 0, 'error' => 'Unable to create temp file']);
            exit;
        }
        file_put_contents($tmp, $content);
        // Set safe permissions
        chmod($tmp, 0640);
        // Move into place
        if (!rename($tmp, $real)) {
            unlink($tmp);
            http_response_code(500);
            echo json_encode(['status' => 0, 'error' => 'Failed to move restored file into place']);
            exit;
        }
        // Set ownership to the user (attempt)
        @chown($real, $user);
        echo json_encode(['status' => 1, 'result' => 'restored']);
        exit;

    } else {
        http_response_code(400);
        echo json_encode(['status' => 0, 'error' => 'Unknown action']);
        exit;
    }
} catch (Exception $e) {
    http_response_code(500);
    echo json_encode(['status' => 0, 'error' => 'Exception: ' . $e->getMessage()]);
    exit;
}

?>
