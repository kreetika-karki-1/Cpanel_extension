# FRO — File Integrity & Resource Optimizer

This repository contains a scaffolded cPanel/WHM plugin named FRO (File Integrity & Resource Optimizer). It includes Python daemons, shared utilities, cPanel LiveAPI frontend pages (Jupiter theme), WHM admin CGI stubs, UAPI Perl modules, systemd unit files, and a simple installer script.

This README documents what was implemented, how to deploy the scaffold to a cPanel/WHM host, how to run and test components, and recommended next steps for production hardening.

---

## Implemented components

Paths below correspond to how the scaffold is laid out in this repository and where files should be placed on the target host.

- Daemons and libraries
  - /opt/fro/daemon/baseline_manager.py — CLI baseline creation/reset tool
  - /opt/fro/daemon/fim_watcher.py — inotify watcher (polling fallback)
  - /opt/fro/daemon/metrics_collector.py — PHP-FPM status scraper
  - /opt/fro/lib/fro_utils.py — shared DB and path helpers

- cPanel (Jupiter theme) frontend
  - /usr/local/cpanel/base/frontend/jupiter/fro/index.live.php
  - /usr/local/cpanel/base/frontend/jupiter/fro/integrity.live.php
  - /usr/local/cpanel/base/frontend/jupiter/fro/optimizer.live.php
  - /usr/local/cpanel/base/frontend/jupiter/fro/assets/fro.css
  - /usr/local/cpanel/base/frontend/jupiter/fro/assets/fro.js

- WHM admin stubs
  - /usr/local/cpanel/whostmgr/docroot/cgi/fro/admin_dashboard.php
  - /usr/local/cpanel/whostmgr/docroot/cgi/fro/policy_manager.php
  - /usr/local/cpanel/whostmgr/docroot/cgi/fro/bulk_optimizer.php
  - /usr/local/cpanel/whostmgr/docroot/cgi/fro/fro.conf

- UAPI custom module (Perl)
  - /usr/local/cpanel/uapi/FRO/FRO.pm
  - /usr/local/cpanel/uapi/FRO/lib/Alerts.pm
  - /usr/local/cpanel/uapi/FRO/lib/Metrics.pm
  - /usr/local/cpanel/uapi/FRO/lib/Optimizer.pm

- Installer & systemd units
  - /var/cpanel/fro/install.sh
  - /var/cpanel/fro/fro-watcher.service
  - /var/cpanel/fro/fro-collector.service

---

## Design highlights and constraints

- PHP files use the cPanel LiveAPI bootstrap:
  ```php
  require_once "/usr/local/cpanel/php/cpanel.php";
  $cpanel = new CPANEL();
  ```
- Per-account SQLite DBs: `/home/<user>/.fro/fim.db` (WAL mode)
- WHM-level SQLite DB: `/var/cpanel/fro/whm.db` (WAL mode)
- Daemons are written in Python 3.x, use logging to syslog, and handle SIGTERM for graceful shutdown
- inotify_simple is preferred; fim_watcher.py falls back to polling if inotify is unavailable
- All SQL uses parameterized statements
- Path validation uses Python's realpath() to ensure operations stay under `/home/<user>`
- No external PHP frameworks or Node.js tooling; frontend uses vanilla JS and minimal CSS matching Jupiter's neutral palette

---

## Deployment instructions (on a cPanel/WHM host)

1. Place files in the correct root paths

   From the repo root (where this scaffold is checked out), copy files into system locations. Example using rsync:

   ```bash
   sudo rsync -av ./opt/ /opt/
   sudo rsync -av ./usr/ /usr/
   sudo rsync -av ./var/ /var/
   ```

   Review each destination before overwriting any existing files on a production server.

2. Set permissions and install the service user

   ```bash
   sudo chmod +x /opt/fro/daemon/*.py
   # The installer creates a fro system user and installs systemd units
   sudo bash /var/cpanel/fro/install.sh
   ```

   After running the installer, verify ownership and adjust as needed:

   ```bash
   sudo chown -R fro:fro /opt/fro
   sudo chown -R root:root /var/cpanel/fro
   sudo chmod 750 /var/cpanel/fro
   ```

3. Ensure per-user DB directories exist and are owned by each cPanel user (or otherwise accessible as intended)

   ```bash
   sudo -u alice mkdir -p /home/alice/.fro
   sudo chown alice:alice /home/alice/.fro
   ```

   The daemons expect per-account DBs to be writable/readable according to the chosen privilege model (see Security notes below).

4. Start and enable systemd services

   ```bash
   sudo systemctl daemon-reload
   sudo systemctl enable --now fro-watcher.service fro-collector.service
   sudo systemctl status fro-watcher.service
   sudo journalctl -u fro-watcher.service -f
   ```

5. Create an initial baseline for a user

   Run the baseline manager as the `fro` user (or as root sudoing to fro) to create the first baseline:

   ```bash
   sudo -u fro /usr/bin/env python3 /opt/fro/daemon/baseline_manager.py --user alice
   ```

   Verify the DB contents:

   ```bash
   sqlite3 /home/alice/.fro/fim.db "SELECT path,sha256,mtime FROM files LIMIT 5;"
   sqlite3 /home/alice/.fro/fim.db "SELECT id,path,event_type,severity,timestamp FROM events ORDER BY timestamp DESC LIMIT 5;"
   ```

6. Verify metrics collection (WHM DB)

   After the metrics collector runs, inspect /var/cpanel/fro/whm.db:

   ```bash
   sqlite3 /var/cpanel/fro/whm.db "SELECT domain,timestamp,data FROM metrics ORDER BY timestamp DESC LIMIT 10;"
   ```

7. Verify UI pages

   - cPanel (Jupiter) pages: /usr/local/cpanel/base/frontend/jupiter/fro/*.live.php
   - WHM admin pages: /usr/local/cpanel/whostmgr/docroot/cgi/fro/

   If pages do not show, verify file permissions and that cPanel is serving LiveAPI extensions in the Jupiter theme. A cPanel service reload may be required after placing UI files.

---

## Quick tests

- Create or modify a file under a monitored directory (e.g. `/home/alice/public_html/test.txt`) and check the events table:

  ```bash
  touch /home/alice/public_html/test-from-fro.txt
  # Wait for watcher to detect (or create a new baseline)
  sqlite3 /home/alice/.fro/fim.db "SELECT id,path,event_type,severity,datetime(timestamp,'unixepoch') FROM events ORDER BY timestamp DESC LIMIT 5;"
  ```

- Fetch metrics from WHM DB:

  ```bash
  sqlite3 /var/cpanel/fro/whm.db "SELECT domain,datetime(timestamp,'unixepoch'),data FROM metrics ORDER BY timestamp DESC LIMIT 5;"
  ```

---

## Missing integrations and recommended next steps

The scaffold implements the core structures and many of the algorithms, but the following production integrations and hardening steps remain:

1. admin_action.php endpoint for cPanel actions
   - The integrity UI posts to `/cgi/fro/admin_action.php`. Implement this secure POST handler that validates inputs (realpath checks), authenticates the cPanel user, and calls the UAPI FRO wrappers (approve_alert, quarantine_file, restore).

2. Restore from backup implementation
   - Integrate with cPanel Fileman or the cPanel backup system. Restores must be privileged operations and validated.

3. UAPI installation & reload
   - Copy the `/usr/local/cpanel/uapi/FRO/` Perl modules to the target host and confirm UAPI exposes `FRO::list_alerts`, `FRO::approve_alert`, `FRO::quarantine_file`, `FRO::get_metrics`, and `FRO::get_recommendations`.

4. SRO write helper and rollback
   - Implement a minimal root helper (carefully audited) for writing `/var/cpanel/userdata/username/domain.tld.php-fpm.yaml` and snapshotting files to the WHM DB. Prefer a WHM-run PHP path that executes as root instead of setuid binaries where possible.

5. Notification integration
   - The watcher should push a notification to cPanel's notification bell (via UAPI Notifications) when critical events arrive.

6. Security hardening
   - Validate all user inputs strictly in PHP and Perl modules.
   - Review file ownerships; consider making per-account DBs owned by the account and allow the `fro` service read access via group or ACLs.
   - Implement SELinux/AppArmor policies if required on the host.

7. Testing & CI
   - Add unit/integration tests for Python, basic Perl unit checks, PHP linting, and a CI pipeline that runs static checks.

---

## Development notes

- Python: use Python 3.9+; the daemons rely on stdlib and optionally the `inotify_simple` module for efficient watchers. If `inotify_simple` is not available, fim_watcher falls back to polling.
- Perl UAPI modules: simplistic implementations are included under `/usr/local/cpanel/uapi/FRO/lib/`. They use DBI and JSON and expect SQLite DBs in the locations named above.
- All SQL statements in the Python code use parameterized queries. Perl DBI calls use placeholders where practical.

---

## Licensing

This repository is released under the MIT License.

---

If you want, I can implement any of the missing integrations next (for example: admin_action.php, the restore workflow, the SRO write helper, or add CI). Tell me which item you want prioritized and I will add it to the repository.
