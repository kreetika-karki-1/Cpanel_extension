# FRO Architecture & Deployment Guide

## System Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                        cPanel/WHM Server                            │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  ┌──────────────────────┐         ┌──────────────────────┐          │
│  │   cPanel Frontends   │         │    WHM Admin Panel   │          │
│  │  (Jupiter Theme)     │         │  (Root Access Only)  │          │
│  │                      │         │                      │          │
│  │ • FRO Dashboard      │         │ • Admin Dashboard    │          │
│  │ • Integrity Alerts   │         │ • Bulk Optimizer     │          │
│  │ • Optimizer View     │         │ • Policy Manager     │          │
│  │ • Settings           │         │ • Incident Feed      │          │
│  └──────────────────────┘         └──────────────────────┘          │
│           ▲                                  ▲                      │
│           │ LiveAPI                         │ WHM API              │
│           ├─ UAPI Calls                     └─ Root Auth           │
│           │                                                         │
│  ┌────────┴────────────────────────────────────────────────────┐   │
│  │              cPanel UAPI Module (Perl)                     │   │
│  │  /usr/local/cpanel/uapi/FRO/FRO.pm                        │   │
│  │  • list_alerts()                                           │   │
│  │  • approve_alert()                                         │   │
│  │  • quarantine_file()                                       │   │
│  │  • get_metrics()                                           │   │
│  │  • get_recommendations()                                   │   │
│  └────────┬────────────────────────────────────────────────────┘   │
│           │                                                         │
│  ┌────────┴──────────────────────────────────────────────────┐     │
│  │              FRO Core Libraries (Python)                  │     │
│  │  /opt/fro/lib/fro_utils.py                               │     │
│  │  • FRODatabase (SQLite wrapper)                           │     │
│  │  • PathValidator (security)                              │     │
│  │  • FileHasher (SHA-256)                                  │     │
│  │  • CMSDetector (WordPress/Joomla/etc)                    │     │
│  │  • Logging setup (file + syslog)                         │     │
│  └────────┬──────────────────────────────────────────────────┘     │
│           │                                                         │
│  ┌────────┴──────────────────────────────────────────────────┐     │
│  │         FRO Daemon Processes (systemd-managed)           │     │
│  │                                                           │     │
│  │  ┌──────────────────────────────────────────────────┐    │     │
│  │  │ FIM Watcher Daemon (per-user, as 'fro' user)    │    │     │
│  │  │ /opt/fro/daemon/fim_watcher.py                  │    │     │
│  │  │                                                  │    │     │
│  │  │ • Initializes inotify for /home/user/public_html
│  │  │ • Watches for IN_CLOSE_WRITE, IN_CREATE events  │    │     │
│  │  │ • Computes SHA-256 hashes on changes            │    │     │
│  │  │ • Classifies severity (critical/warning/info)   │    │     │
│  │  │ • Writes to /home/user/.fro/fim.db              │    │     │
│  │  │ • Pushes notifications via cPanel UAPI          │    │     │
│  │  └──────────────────────────────────────────────────┘    │     │
│  │                                                           │     │
│  │  ┌──────────────────────────────────────────────────┐    │     │
│  │  │ Metrics Collector (system-wide, as root)        │    │     │
│  │  │ /opt/fro/daemon/metrics_collector.py            │    │     │
│  │  │                                                  │    │     │
│  │  │ • Polls PHP-FPM status every 60 seconds         │    │     │
│  │  │ • Reads /var/cpanel/userdata/*/domain.yaml     │    │     │
│  │  │ • Stores metrics in /var/cpanel/fro/metrics.db  │    │     │
│  │  │ • Generates SRO recommendations (7-day window)  │    │     │
│  │  │ • Calculates optimal pm_max_children values     │    │     │
│  │  └──────────────────────────────────────────────────┘    │     │
│  │                                                           │     │
│  │  ┌──────────────────────────────────────────────────┐    │     │
│  │  │ Baseline Manager CLI (on-demand)                │    │     │
│  │  │ /opt/fro/daemon/baseline_manager.py             │    │     │
│  │  │                                                  │    │     │
│  │  │ • Creates initial file baselines                │    │     │
│  │  │ • Verifies baseline integrity                   │    │     │
│  │  │ • Resets baselines                              │    │     │
│  │  │ • Reports baseline statistics                   │    │     │
│  │  └──────────────────────────────────────────────────┘    │     │
│  └──────────────────────────────────────────────────────────┘     │
│                                                                     │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │              SQLite Databases                              │  │
│  │                                                            │  │
│  │  Per-Account: /home/$USER/.fro/fim.db                    │  │
│  │  • fim_events (append-only, WAL mode)                    │  │
│  │  • fim_baseline                                           │  │
│  │                                                            │  │
│  │  WHM-Level: /var/cpanel/fro/metrics.db                   │  │
│  │  • sro_phpfpm_metrics (time-series)                       │  │
│  │  • sro_phpfpm_config                                      │  │
│  │  • sro_recommendations                                    │  │
│  │  • sro_yaml_snapshots (for rollback)                      │  │
│  └──────────────────────────────────────────────────────────┘  │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

## File Structure

```
/opt/fro/                              # FRO root directory
├── daemon/
│   ├── fim_watcher.py                 # File integrity watcher (inotify)
│   ├── baseline_manager.py            # Baseline creation/verification CLI
│   ├── metrics_collector.py           # PHP-FPM metrics & SRO engine
│   └── requirements.txt               # Python dependencies
├── lib/
│   └── fro_utils.py                   # Shared utilities (logging, DB, validation)
├── config/
│   └── fro.conf                       # Configuration template
├── install.sh                         # Installation script
├── uninstall.sh                       # Uninstallation script
└── README.md                          # Documentation

/usr/local/cpanel/base/frontend/jupiter/fro/
├── index.live.php                     # Main dashboard
├── integrity.live.php                 # Integrity alerts view
├── optimizer.live.php                 # Optimizer metrics view
└── assets/
    ├── fro.css                        # Styling
    └── fro.js                         # Client-side logic

/usr/local/cpanel/whostmgr/docroot/cgi/fro/
├── admin_dashboard.php                # WHM admin home
├── bulk_optimizer.php                 # SRO bulk apply interface
├── policy_manager.php                 # FIM global settings
└── incident_feed.php                  # Cross-account alerts

/usr/local/cpanel/uapi/FRO/
├── FRO.pm                             # UAPI module (Perl)
└── lib/
    ├── Alerts.pm                      # Alert functions
    ├── Metrics.pm                     # Metrics functions
    └── Optimizer.pm                   # Optimizer functions

/var/cpanel/fro/
├── install.sh                         # Installation helper
├── uninstall.sh                       # Uninstallation helper
├── metrics.db                         # WHM-level metrics database
└── fro.conf                           # Plugin configuration
```

## Data Flow

### File Integrity Monitoring (FIM) Flow

```
1. User enables FRO for domain
   └─→ /opt/fro/daemon/baseline_manager.py --user alice --create-baseline
       ├─ Recursively hash all files in /home/alice/public_html
       ├─ Store hashes in /home/alice/.fro/fim.db (fim_baseline table)
       └─ Create index on file_path

2. FIM Watcher starts
   └─→ systemctl start fro-watcher@alice
       ├─ Initializes inotify on /home/alice/public_html
       ├─ Watches for: IN_CLOSE_WRITE, IN_CREATE, IN_DELETE, IN_ATTRIB
       ├─ Per event:
       │  ├─ Compute new file hash
       │  ├─ Lookup baseline hash
       │  ├─ Detect CMS type (WordPress/Joomla/etc)
       │  ├─ Classify severity (critical/warning/info)
       │  ├─ Insert into fim_events table
       │  └─ Push cPanel notification
       └─ Loop continues indefinitely

3. User reviews alerts in cPanel
   └─→ https://cpanel.example.com:2083/
       ├─ cPanel calls FRO::list_alerts() UAPI
       ├─ Reads from /home/alice/.fro/fim.db (unresolved events)
       └─ User selects action: Approve / Ignore / Quarantine

4. User approves change
   └─→ Click "Approve" on file change
       ├─ POST to integrity.live.php?action=approve&event_id=42
       ├─ Update fim_baseline table with new hash
       ├─ Mark fim_events.resolved = 1
       └─ Notify user via cPanel bell

5. Quarantine file (suspicious)
   └─→ Click "Quarantine"
       ├─ Move file to /home/alice/.fro/quarantine/filename_TIMESTAMP
       ├─ Mark event.resolved = 1
       └─ cPanel admin notified
```

### Smart Resource Optimizer (SRO) Flow

```
1. Metrics Collector starts (daily on server)
   └─→ systemctl start fro-collector
       ├─ Every 60 seconds:
       │  ├─ Get list of cPanel accounts (whmapi1 listaccts)
       │  ├─ For each account:
       │  │  ├─ Get list of domains (UAPI DomainInfo::list_domains)
       │  │  └─ For each domain:
       │  │     ├─ Parse /var/cpanel/userdata/$account/$domain.php-fpm.yaml
       │  │     ├─ Curl http://localhost/status?full&json (PHP-FPM status)
       │  │     ├─ Extract: active_processes, memory_usage_mb, response_time
       │  │     └─ INSERT into sro_phpfpm_metrics table
       │  └─ Store data points (7-day rolling window)
       │
       └─ Every hour:
          ├─ Generate recommendations from 7-day metrics
          ├─ For each domain:
          │  ├─ Analyze peak memory, response time patterns
          │  ├─ Calculate optimal pm_max_children:
          │  │  pm_max_children = (peak_memory_mb / avg_process_size_mb) * 1.2
          │  │  Capped by: (available_ram_mb - 2GB) / avg_process_size_mb
          │  ├─ Recommend pm strategy:
          │  │  - times_exhausted > 5    → 'dynamic'
          │  │  - avg_response_time > 200 → 'static'
          │  │  - otherwise               → 'dynamic'
          │  ├─ Calculate confidence score (0.0-1.0)
          │  └─ INSERT into sro_recommendations
          └─ WAL checkpoint for database cleanup

2. WHM admin reviews recommendations
   └─→ https://whm.example.com:2087/cgi/fro/bulk_optimizer.php
       ├─ Fetches pending recommendations (applied_at IS NULL)
       ├─ Displays in table with:
       │  • Current vs recommended settings
       │  • Confidence percentage
       │  • Reason for recommendation
       └─ Admin selects checkboxes for recommendations to apply

3. Admin clicks "Apply Selected"
   └─→ POST bulk_optimizer.php?action=apply
       ├─ For each selected recommendation:
       │  ├─ Snapshot current YAML to sro_yaml_snapshots
       │  ├─ Build new YAML with recommended settings
       │  ├─ Write to /var/cpanel/userdata/$account/$domain.php-fpm.yaml
       │  ├─ Execute: /scripts/php_fpm_config --rebuild
       │  ├─ Gracefully reload PHP-FPM pool
       │  └─ Mark recommendation.applied_at = NOW(), applied_by = 'admin_username'
       └─ Admin sees success message

4. Optional: Rollback a change
   └─→ Admin retrieves snapshot from database
       ├─ Query: SELECT yaml_content FROM sro_yaml_snapshots WHERE applied_at IS NOT NULL
       ├─ Restore YAML to previous content
       ├─ Rebuild PHP-FPM config
       └─ Mark snapshot.reverted_at = NOW()
```

## Security Model

### Authentication & Authorization

| Component | Auth Method | Required Role |
|-----------|-------------|---------------|
| cPanel Dashboard | LiveAPI Session | End-user (account owner) |
| Integrity Alerts | LiveAPI Session | End-user |
| WHM Dashboard | HTTP Basic Auth | root / WHM admin |
| Bulk Optimizer | HTTP Basic Auth | root only |
| Policy Manager | HTTP Basic Auth | root only |
| UAPI Calls | Token-based | Varies per function |
| Daemon Processes | System User | fro (for FIM), root (for SRO) |

### Path Validation

All file operations use `realpath()` to resolve symlinks and prevent directory traversal:

```python
# Example: Prevent directory traversal
safe_path = validate_user_path(username, user_input_path)
# Checks:
# 1. Path exists
# 2. Path resolves to /home/username/*
# 3. Path doesn't contain ../ or symlink escapes
# 4. User has read permission
```

### Database Security

- **WAL Mode:** Append-only writes, no truncation (prevents tampering by compromised accounts)
- **Parameterized Queries:** All SQL uses `?` placeholders to prevent injection
- **User Isolation:** Per-account databases owned by account user
- **Encryption:** Can integrate with cPanel's native database encryption

### Privilege Separation

```
fro user (unprivileged):
  ├─ Read: /home/*/public_html/* (recursive, CAP_DAC_READ_SEARCH)
  ├─ Write: /home/*/.fro/*.db (own databases only)
  ├─ Cannot: Write to cPanel configs, modify PHP-FPM YAML
  └─ Runs: fim_watcher.py

root user:
  ├─ Read: All PHP-FPM configs, cPanel userdata
  ├─ Write: /var/cpanel/fro/metrics.db
  ├─ Execute: /scripts/php_fpm_config --rebuild
  └─ Runs: metrics_collector.py
```

## Deployment Scenarios

### Scenario 1: Small Hosting Provider (< 100 accounts)

```
Server Configuration:
  • 2 CPU cores
  • 8 GB RAM
  • SSD storage (at least 10GB free)

Installation:
  1. bash /opt/fro/install.sh
  2. systemctl enable fro-collector
  3. For each account: systemctl enable fro-watcher@username

Performance Impact:
  • FIM: ~2-5% CPU increase (inotify lightweight)
  • SRO: ~3-8% CPU increase (metrics collection)
  • Total: ~5-13% CPU overhead
  • Memory: ~100-150 MB (daemons + databases)
  • Disk: ~5-10 GB for 7-day metrics window
```

### Scenario 2: Mid-Size Hosting Provider (100-500 accounts)

```
Server Configuration:
  • 4-8 CPU cores
  • 16-32 GB RAM
  • SSD storage with RAID-10 (at least 50GB free)
  • Optional: Separate metrics database on dedicated SSD

Installation:
  1. bash /opt/fro/install.sh
  2. Distribute fro-watcher@* across multiple CPUs
  3. Configure metrics collector on dedicated core (if available)

Optimization:
  • Prune old metrics: DELETE FROM sro_phpfpm_metrics WHERE collected_at < X
  • Index databases: CREATE INDEX idx_account ON sro_phpfpm_metrics(account)
  • Monitor inotify limit: cat /proc/sys/fs/inotify/max_user_watches
    (May need: echo 524288 > /proc/sys/fs/inotify/max_user_watches)

Performance Impact:
  • FIM: ~5-10% CPU (100-500 watchers)
  • SRO: ~10-15% CPU (larger dataset)
  • Total: ~15-25% CPU overhead
  • Memory: ~500 MB - 1 GB
  • Disk: ~20-50 GB for metrics
```

### Scenario 3: Enterprise/Large Hosting (500+ accounts)

```
Server Configuration:
  • 8-16 CPU cores
  • 32-64 GB RAM
  • NVMe storage with RAID-10 (at least 100GB free)
  • Optional: Dedicated metrics database server

Installation:
  1. bash /opt/fro/install.sh
  2. Configure MySQL for metrics (instead of SQLite)
  3. Deploy metrics_collector on separate server (optional)
  4. Scale fro-watcher@* with process manager (systemd slice)

Optimization:
  • Use MySQL for /var/cpanel/fro/metrics.db (replication support)
  • Implement metrics archival (move old data to cold storage)
  • Load balance FIM watchers across multiple processes
  • Enable compression for metrics older than 30 days

Performance Impact:
  • FIM: ~10-20% CPU
  • SRO: ~20-30% CPU (large dataset + recommendations)
  • Total: ~30-50% CPU overhead
  • Memory: ~2-5 GB
  • Disk: ~100-200 GB for metrics
```

## Monitoring & Maintenance

### Health Checks

```bash
# Check daemon status
systemctl status fro-collector fro-watcher@*

# Verify databases are accessible
sqlite3 /var/cpanel/fro/metrics.db "SELECT COUNT(*) FROM sro_phpfpm_metrics;"

# Check for database corruption
sqlite3 /var/cpanel/fro/metrics.db "PRAGMA integrity_check;"

# Monitor inotify limits
cat /proc/sys/fs/inotify/max_user_watches
cat /proc/sys/fs/inotify/max_queued_events

# Check disk usage
du -sh /opt/fro /var/cpanel/fro /home/*/.fro/
```

### Log Locations

```
/var/log/fro/
├── fim_watcher_*.log          # Per-user watcher logs
├── metrics_collector.log      # Metrics daemon logs
└── baseline_manager.log       # Baseline CLI logs

Journal logs (systemd):
journalctl -u fro-collector -f
journalctl -u 'fro-watcher@*' -f
```

### Database Maintenance

```bash
# Prune old metrics (keep last 30 days)
sqlite3 /var/cpanel/fro/metrics.db "
  DELETE FROM sro_phpfpm_metrics 
  WHERE collected_at < strftime('%s', 'now', '-30 days')
"

# Optimize database
sqlite3 /var/cpanel/fro/metrics.db "VACUUM; ANALYZE;"

# Checkpoint WAL
sqlite3 /var/cpanel/fro/metrics.db "PRAGMA wal_checkpoint(TRUNCATE);"
```

## Troubleshooting

### Issue: High CPU usage from fro-watcher

```bash
# Check number of files being watched
find /home/username/public_html -type f | wc -l

# If > 100,000 files, add exclusions
# Edit /opt/fro/daemon/fim_watcher.py and add patterns to EXCLUDED_DIRS

# Restart watcher
systemctl restart fro-watcher@username
```

### Issue: Database locked error

```bash
# Check for stale connections
lsof /var/cpanel/fro/metrics.db

# Force WAL checkpoint
sqlite3 /var/cpanel/fro/metrics.db "PRAGMA wal_checkpoint(RESTART);"

# Restart metrics collector
systemctl restart fro-collector
```

### Issue: Out of memory

```bash
# Check memory usage
free -h
ps aux | grep fro

# Analyze old data and archive
sqlite3 /var/cpanel/fro/metrics.db "
  SELECT DATE(datetime(collected_at, 'unixepoch')) as date, 
         COUNT(*) as count 
  FROM sro_phpfpm_metrics 
  GROUP BY DATE(datetime(collected_at, 'unixepoch'))
"

# Delete if necessary
sqlite3 /var/cpanel/fro/metrics.db "
  DELETE FROM sro_phpfpm_metrics 
  WHERE collected_at < strftime('%s', 'now', '-7 days')
"
```

## Version & Updates

Current Version: **1.0.0**  
Release Date: June 2026

### Upgrade Path

```bash
# Backup databases before upgrade
cp /var/cpanel/fro/metrics.db /var/cpanel/fro/metrics.db.backup
for db in /home/*/.fro/fim.db; do
  cp "$db" "$db.backup"
done

# Pull latest from repository
cd /opt/fro
git pull origin main

# Re-run installer (safe to run multiple times)
sudo bash /opt/fro/install.sh

# Restart daemons
sudo systemctl restart fro-collector fro-watcher@*
```

---

**Last Updated:** June 2026  
**Maintained by:** Kreetika Karki  
**Repository:** https://github.com/kreetika-karki-1/Cpanel_extension
