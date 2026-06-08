#!/bin/bash
# install.sh - simplistic installer: create fro user, directories and systemd units
set -e

# Create fro user if not exists
if ! id fro >/dev/null 2>&1; then
  useradd --system --home /opt/fro --shell /sbin/nologin fro || true
fi

mkdir -p /opt/fro/daemon
mkdir -p /var/cpanel/fro
chown -R fro:fro /opt/fro || true
chown -R root:root /var/cpanel/fro || true
chmod 750 /var/cpanel/fro || true

# Install systemd unit files (assumes they are placed alongside this script)
cp fro-watcher.service /etc/systemd/system/fro-watcher.service || true
cp fro-collector.service /etc/systemd/system/fro-collector.service || true

systemctl daemon-reload || true
# Enable services but do not start automatically in this install script
systemctl enable fro-watcher.service || true
systemctl enable fro-collector.service || true

echo "FRO installed (files copied). Please review /etc/systemd/system/fro-*.service and start services as appropriate."
