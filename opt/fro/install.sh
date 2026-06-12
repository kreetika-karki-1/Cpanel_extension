#!/bin/bash
# FRO Installer Script
# Installs FRO plugin, creates directories, systemd units, and database
# Usage: bash /opt/fro/install.sh

set -e

echo "═══════════════════════════════════════════════════════════════"
echo "  FRO (File Integrity & Resource Optimizer) Installer"
echo "═══════════════════════════════════════════════════════════════"

# Check if running as root
if [[ $EUID -ne 0 ]]; then
    echo "ERROR: This script must be run as root"
    exit 1
fi

echo "[*] Creating FRO system user..."
if ! id "fro" &>/dev/null; then
    useradd -r -s /bin/false -d /opt/fro -m fro || true
fi
echo "✓ FRO user created"

echo "[*] Creating directory structure..."
mkdir -p /opt/fro/daemon
mkdir -p /opt/fro/lib
mkdir -p /opt/fro/config
mkdir -p /var/cpanel/fro
mkdir -p /usr/local/cpanel/base/frontend/jupiter/fro/assets
mkdir -p /usr/local/cpanel/whostmgr/docroot/cgi/fro
mkdir -p /usr/local/cpanel/uapi/FRO/lib

echo "✓ Directories created"

echo "[*] Setting permissions..."
chown -R fro:wheel /opt/fro 2>/dev/null || chown -R fro /opt/fro
chown -R root:root /var/cpanel/fro
chmod 755 /opt/fro/daemon/*.py
chmod 755 /opt/fro/lib/*.py

echo "✓ Permissions set"

echo "[*] Installing Python dependencies..."
if command -v pip3 &> /dev/null; then
    pip3 install inotify-simple 2>/dev/null || echo "⚠ Warning: Could not install inotify-simple"
fi
echo "✓ Python dependencies installed"

echo "[*] Creating systemd service units..."

# FIM Watcher Service (runs as fro user per account)
cat > /etc/systemd/system/fro-watcher@.service << 'EOF'
[Unit]
Description=FRO File Integrity Monitor Watcher for %i
After=network.target

[Service]
Type=simple
User=fro
ExecStart=/opt/fro/daemon/fim_watcher.py --user %i
Restart=on-failure
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

# Metrics Collector Service (runs as root, system-wide)
cat > /etc/systemd/system/fro-collector.service << 'EOF'
[Unit]
Description=FRO Metrics Collector (SRO)
After=network.target

[Service]
Type=simple
User=root
ExecStart=/opt/fro/daemon/metrics_collector.py --interval 60
Restart=on-failure
RestartSec=30
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

echo "✓ Systemd units created"

echo "[*] Initializing WHM-level database..."
if ! sqlite3 /var/cpabel/fro/metrics.db ".tables" &>/dev/null; then
    sqlite3 /var/cpanel/fro/metrics.db << 'DBEOF'
CREATE TABLE IF NOT EXISTS sro_phpfpm_metrics (
    metric_id INTEGER PRIMARY KEY AUTOINCREMENT,
    account TEXT NOT NULL,
    domain TEXT NOT NULL,
    active_processes INTEGER,
    idle_processes INTEGER,
    max_children_reached INTEGER,
    slow_requests INTEGER,
    avg_response_time_ms REAL,
    memory_usage_mb REAL,
    peak_memory_usage_mb REAL,
    collected_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS sro_phpfpm_config (
    config_id INTEGER PRIMARY KEY AUTOINCREMENT,
    account TEXT NOT NULL,
    domain TEXT NOT NULL,
    pm_strategy TEXT,
    pm_max_children INTEGER,
    pm_max_requests INTEGER,
    php_version TEXT,
    updated_at INTEGER NOT NULL,
    UNIQUE(account, domain)
);

CREATE TABLE IF NOT EXISTS sro_recommendations (
    recommendation_id INTEGER PRIMARY KEY AUTOINCREMENT,
    account TEXT NOT NULL,
    domain TEXT NOT NULL,
    recommended_pm_strategy TEXT,
    recommended_max_children INTEGER,
    recommended_max_requests INTEGER,
    recommended_php_version TEXT,
    confidence_score REAL,
    reason TEXT,
    generated_at INTEGER NOT NULL,
    applied_at INTEGER,
    applied_by TEXT
);

CREATE TABLE IF NOT EXISTS sro_yaml_snapshots (
    snapshot_id INTEGER PRIMARY KEY AUTOINCREMENT,
    account TEXT NOT NULL,
    domain TEXT NOT NULL,
    yaml_content TEXT NOT NULL,
    snapshot_at INTEGER NOT NULL,
    applied_at INTEGER,
    reverted_at INTEGER
);
DBEOF
fi

chmod 644 /var/cpanel/fro/metrics.db

echo "✓ Database initialized"

echo "[*] Reloading systemd daemon..."
systemctl daemon-reload

echo ""
echo "═══════════════════════════════════════════════════════════════"
echo "  Installation Complete!"
echo "═══════════════════════════════════════════════════════════════"
echo ""
echo "Next steps:"
echo ""
echo "  1. Start metrics collector:"
echo "     systemctl start fro-collector"
echo "     systemctl enable fro-collector"
echo ""
echo "  2. For each cPanel account, start the FIM watcher:"
echo "     systemctl start fro-watcher@username"
echo "     systemctl enable fro-watcher@username"
echo ""
echo "  3. Create baseline for a user:"
echo "     /opt/fro/daemon/baseline_manager.py --user username --create-baseline"
echo ""
echo "  4. Access cPanel FRO dashboard:"
echo "     https://cpanel.example.com:2083/"
echo ""
echo "  5. Access WHM FRO dashboard:"
echo "     https://whm.example.com:2087/cgi/fro/admin_dashboard.php"
echo ""
echo "For logs, use:"
echo "  journalctl -u fro-collector -f"
echo "  journalctl -u 'fro-watcher@*' -f"
echo ""
echo "For more information, see:"
echo "  /opt/fro/README.md"
echo ""
