#!/usr/bin/env python3
"""
FRO File Integrity Monitor (FIM) Watcher Daemon
Monitors file changes via inotify and records integrity events to SQLite.
Designed to run as systemd service under 'fro' user.

Usage:
    /opt/fro/daemon/fim_watcher.py --user username [--debug]
    systemctl start fro-watcher
"""

import os
import sys
import signal
import argparse
import json
import time
from typing import Optional, Dict, List
from pathlib import Path

# Add parent dir to path for imports
sys.path.insert(0, '/opt/fro/lib')

from fro_utils import (
    setup_logger, FRODatabase, validate_user_path, get_excluded_paths,
    compute_file_hash, get_file_metadata, classify_severity, detect_cms,
    is_cms_core_file, call_cpanel_uapi
)

try:
    import inotify_simple
except ImportError:
    print("ERROR: inotify-simple not installed. Install with: pip3 install inotify-simple", file=sys.stderr)
    sys.exit(1)


class FIMWatcher:
    """
    inotify-based file integrity watcher for a single cPanel account.
    Monitors configured paths and records integrity events to SQLite.
    """
    
    def __init__(self, username: str, debug: bool = False):
        """
        Initialize watcher for a cPanel user account.
        
        Args:
            username: cPanel username
            debug: Enable debug logging
        """
        self.username = username
        self.user_home = f"/home/{username}"
        self.fro_db_dir = os.path.join(self.user_home, '.fro')
        self.db_path = os.path.join(self.fro_db_dir, 'fim.db')
        self.cms_type = None
        self.watched_paths = []
        self.excluded_paths = get_excluded_paths(username)
        
        log_level = 'DEBUG' if debug else 'INFO'
        self.logger = setup_logger(f'fim_watcher_{username}', log_level=log_level)
        
        self.running = True
        self.db = None
        self.inotify = None
    
    def initialize(self) -> bool:
        """
        Initialize database and inotify watcher.
        Sets up directory structure, tables, and inotify watches.
        
        Returns:
            True if successful, False otherwise
        """
        try:
            # Create FRO directory structure
            os.makedirs(self.fro_db_dir, mode=0o700, exist_ok=True)
            
            # Initialize database
            self.db = FRODatabase(self.db_path, logger=self.logger)
            self._create_tables()
            
            # Initialize inotify
            self.inotify = inotify_simple.INotify()
            self.logger.info(f"Initialized inotify watcher for user {self.username}")
            
            return True
        except Exception as e:
            self.logger.error(f"Initialization failed: {e}")
            return False
    
    def _create_tables(self):
        """Create FIM event table if it doesn't exist."""
        try:
            self.db.execute("""
                CREATE TABLE IF NOT EXISTS fim_events (
                    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    file_path TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    old_hash TEXT,
                    new_hash TEXT,
                    old_perms TEXT,
                    new_perms TEXT,
                    severity TEXT NOT NULL,
                    cms_type TEXT,
                    timestamp INTEGER NOT NULL,
                    resolved INTEGER DEFAULT 0
                )
            """)
            
            self.db.execute("""
                CREATE TABLE IF NOT EXISTS fim_baseline (
                    baseline_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    file_path TEXT UNIQUE NOT NULL,
                    hash TEXT NOT NULL,
                    perms TEXT NOT NULL,
                    size INTEGER NOT NULL,
                    mtime INTEGER NOT NULL,
                    created_at INTEGER NOT NULL
                )
            """)
            
            self.logger.info("FIM tables initialized")
        except Exception as e:
            self.logger.error(f"Table creation failed: {e}")
            raise
    
    def load_watched_paths(self) -> bool:
        """
        Load monitored paths from configuration and add inotify watches.
        Reads from FRO config file (default: /var/cpanel/fro/policies.json).
        
        Returns:
            True if at least one path was added
        """
        try:
            # Get default monitored path (public_html)
            public_html = os.path.join(self.user_home, 'public_html')
            
            # Validate and canonicalize path
            canonical_path = validate_user_path(self.username, public_html, logger=self.logger)
            if not canonical_path or not os.path.isdir(canonical_path):
                self.logger.warning(f"public_html not found or invalid for user {self.username}")
                return False
            
            self.watched_paths.append(canonical_path)
            
            # Detect CMS for severity classification
            self.cms_type = detect_cms(canonical_path, logger=self.logger)
            
            # Add recursive inotify watches
            self._add_recursive_watches(canonical_path)
            
            self.logger.info(f"Added {len(self.watched_paths)} watched paths for {self.username}")
            return True
        except Exception as e:
            self.logger.error(f"Failed to load watched paths: {e}")
            return False
    
    def _add_recursive_watches(self, root_path: str, max_depth: int = 20, current_depth: int = 0):
        """
        Recursively add inotify watches to all subdirectories.
        
        Args:
            root_path: Starting directory
            max_depth: Maximum recursion depth (prevent infinite loops)
            current_depth: Current recursion depth
        """
        if current_depth > max_depth:
            self.logger.warning(f"Max watch depth reached at {root_path}")
            return
        
        try:
            # Add watch to current directory
            watch_flags = inotify_simple.flags.CLOSE_WRITE | inotify_simple.flags.CREATE | \
                          inotify_simple.flags.DELETE | inotify_simple.flags.ATTRIB | \
                          inotify_simple.flags.MOVED_TO | inotify_simple.flags.MOVED_FROM
            
            wd = self.inotify.add_watch(root_path, watch_flags)
            self.logger.debug(f"Added inotify watch: {root_path} (wd={wd})")
            
            # Recurse into subdirectories
            try:
                for entry in os.scandir(root_path):
                    if entry.is_dir(follow_symlinks=False):
                        # Skip excluded paths
                        if any(entry.path.startswith(exc) for exc in self.excluded_paths):
                            continue
                        
                        self._add_recursive_watches(entry.path, max_depth, current_depth + 1)
            except PermissionError:
                self.logger.debug(f"Permission denied reading {root_path}")
            
        except Exception as e:
            self.logger.warning(f"Failed to add watch for {root_path}: {e}")
    
    def handle_event(self, event):
        """
        Process an inotify event and record to database.
        
        Args:
            event: inotify_simple event object
        """
        try:
            # Get full path from watch descriptor
            try:
                watched_path = [p for p in self.watched_paths if p in event.name][0]
            except (IndexError, TypeError):
                return
            
            file_path = event.name
            if not os.path.exists(file_path):
                if event.mask & inotify_simple.flags.DELETE:
                    # Record deletion
                    self._record_deletion_event(file_path)
                return
            
            # Get new hash and metadata
            new_hash = compute_file_hash(file_path, logger=self.logger)
            new_metadata = get_file_metadata(file_path, logger=self.logger)
            
            if not new_hash or not new_metadata:
                return
            
            # Check baseline
            baseline = self.db.fetch_one(
                "SELECT hash, perms FROM fim_baseline WHERE file_path = ?",
                (file_path,)
            )
            
            if baseline is None:
                # New file not in baseline
                event_type = 'created'
                old_hash = None
                old_perms = None
            else:
                # File changed
                if baseline['hash'] != new_hash:
                    event_type = 'modified'
                    old_hash = baseline['hash']
                else:
                    event_type = 'permission_changed'
                
                old_perms = baseline['perms']
            
            # Classify severity
            severity = classify_severity(file_path, event_type)
            is_core, cms_type = is_cms_core_file(file_path)
            
            # Record event
            self.db.insert('fim_events', {
                'file_path': file_path,
                'event_type': event_type,
                'old_hash': old_hash,
                'new_hash': new_hash,
                'old_perms': old_perms,
                'new_perms': new_metadata['perms'],
                'severity': severity,
                'cms_type': cms_type or self.cms_type or '',
                'timestamp': int(time.time()),
                'resolved': 0
            })
            
            self.logger.info(
                f"Recorded {severity} event: {event_type} on {file_path}"
            )
            
            # Send cPanel notification for critical events
            if severity == 'critical':
                self._send_notification(file_path, event_type)
            
        except Exception as e:
            self.logger.error(f"Error handling event: {e}")
    
    def _record_deletion_event(self, file_path: str):
        """Record deletion of a file."""
        try:
            baseline = self.db.fetch_one(
                "SELECT hash, perms FROM fim_baseline WHERE file_path = ?",
                (file_path,)
            )
            
            if baseline:
                severity = classify_severity(file_path, 'deleted')
                is_core, cms_type = is_cms_core_file(file_path)
                
                self.db.insert('fim_events', {
                    'file_path': file_path,
                    'event_type': 'deleted',
                    'old_hash': baseline['hash'],
                    'new_hash': None,
                    'old_perms': baseline['perms'],
                    'new_perms': None,
                    'severity': severity,
                    'cms_type': cms_type or self.cms_type or '',
                    'timestamp': int(time.time()),
                    'resolved': 0
                })
                
                self.logger.warning(f"Recorded file deletion: {file_path}")
                
                # Always notify on deletions
                self._send_notification(file_path, 'deleted')
        except Exception as e:
            self.logger.error(f"Error recording deletion: {e}")
    
    def _send_notification(self, file_path: str, event_type: str):
        """
        Send cPanel notification to end-user via UAPI.
        This triggers a bell notification in cPanel UI.
        
        Args:
            file_path: File that was changed
            event_type: Type of change
        """
        try:
            # Call UAPI to trigger notification
            message = f"File Integrity Alert: {event_type.upper()} detected on {file_path}"
            response = call_cpanel_uapi(
                self.username,
                'Fileman',
                'send_notification',
                {'message': message},
                logger=self.logger
            )
            
            if response:
                self.logger.debug(f"Sent notification: {message}")
        except Exception as e:
            self.logger.debug(f"Could not send notification: {e}")
    
    def run_loop(self):
        """
        Main event loop. Reads inotify events and processes them.
        Runs until SIGTERM received.
        """
        self.logger.info(f"Starting FIM watcher loop for {self.username}")
        
        try:
            while self.running:
                # Read events with timeout (1 second)
                events = self.inotify.read(timeout_ms=1000)
                
                for event in events:
                    self.handle_event(event)
        
        except KeyboardInterrupt:
            self.logger.info("Received interrupt signal")
        except Exception as e:
            self.logger.error(f"Watcher loop error: {e}")
        finally:
            self.cleanup()
    
    def cleanup(self):
        """Clean up resources and close connections."""
        self.running = False
        
        if self.db:
            self.db.close()
        
        if self.inotify:
            # inotify_simple doesn't have explicit close, but we can set to None
            self.inotify = None
        
        self.logger.info(f"Cleaned up watcher for {self.username}")
    
    def signal_handler(self, signum, frame):
        """Handle SIGTERM gracefully."""
        self.logger.info(f"Received signal {signum}, shutting down")
        self.running = False


def main():
    """Entry point for FIM watcher daemon."""
    parser = argparse.ArgumentParser(description='FRO File Integrity Monitor Daemon')
    parser.add_argument('--user', required=True, help='cPanel username')
    parser.add_argument('--debug', action='store_true', help='Enable debug logging')
    
    args = parser.parse_args()
    
    # Validate username (alphanumeric and underscore only)
    if not args.user or not all(c.isalnum() or c == '_' for c in args.user):
        print(f"ERROR: Invalid username: {args.user}", file=sys.stderr)
        sys.exit(1)
    
    # Initialize watcher
    watcher = FIMWatcher(args.user, debug=args.debug)
    
    if not watcher.initialize():
        print(f"ERROR: Failed to initialize watcher for {args.user}", file=sys.stderr)
        sys.exit(1)
    
    if not watcher.load_watched_paths():
        print(f"ERROR: Failed to load watched paths for {args.user}", file=sys.stderr)
        sys.exit(1)
    
    # Set up signal handlers
    signal.signal(signal.SIGTERM, watcher.signal_handler)
    signal.signal(signal.SIGINT, watcher.signal_handler)
    
    # Run main loop
    watcher.run_loop()
"""fim_watcher.py

Daemon that watches baselined directories using inotify (inotify_simple) and
logs file events into per-account SQLite DBs. Classifies severity for known
CMS paths and files.

Designed to run under systemd as user 'fro'. Uses WAL journal mode and append-only
insertion for events.
"""

import logging
import logging.handlers
import os
import signal
import sqlite3
import stat
import sys
import time
import hashlib
from fro_utils import get_db_path, open_db, is_path_allowed, init_db

try:
    from inotify_simple import INotify, flags
    HAVE_INOTIFY = True
except Exception:
    HAVE_INOTIFY = False

LOG = logging.getLogger('fro.fim_watcher')

WATCH_MASK = flags.CREATE | flags.DELETE | flags.MODIFY | flags.CLOSE_WRITE | flags.MOVED_TO | flags.MOVED_FROM if HAVE_INOTIFY else None

CRITICAL_PATTERNS = [
    'wp-load.php',
    '/wp-admin/',
    '/wp-includes/',
    'administrator/components/',
    '/app/code/',  # Magento
]

WARNING_PATTERNS = [
    '.php', '.htaccess', '/themes/', '/plugins/', '/extensions/'
]

INFO_PATTERNS = ['/uploads/', '/media/', '/logs/']

running = True


def sigterm_handler(signum, frame):
    global running
    LOG.info('Received SIGTERM, shutting down')
    running = False


def file_sha256(path):
    try:
        h = hashlib.sha256()
        with open(path, 'rb') as f:
            for chunk in iter(lambda: f.read(8192), b''):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return None


def classify_path(path):
    p = path.replace('\\', '/')
    for pat in CRITICAL_PATTERNS:
        if pat in p:
            return 'critical'
    for pat in WARNING_PATTERNS:
        if pat in p:
            return 'warning'
    for pat in INFO_PATTERNS:
        if pat in p:
            return 'info'
    return 'info'


def ensure_watch_dirs(conn, user):
    # For simplicity: watch /home/user/public_html if exists
    candidate = os.path.join('/home', user, 'public_html')
    if os.path.isdir(candidate):
        return [candidate]
    return []


def event_insert(conn, path, event_type, severity, old_hash, new_hash):
    c = conn.cursor()
    c.execute('''INSERT INTO events (path, event_type, severity, old_sha256, new_sha256, timestamp, resolved)
                 VALUES (?, ?, ?, ?, ?, ?, 0)
              ''', (path, event_type, severity, old_hash, new_hash, int(time.time())))
    conn.commit()


def watch_user(user):
    db_path = get_db_path(user)
    conn = open_db(db_path)
    init_db(conn)

    watch_dirs = ensure_watch_dirs(conn, user)
    if not watch_dirs:
        LOG.info('No watch directories for user %s', user)
        return

    # Use inotify if available; otherwise simple polling fallback
    if HAVE_INOTIFY:
        i = INotify()
        wd_map = {}
        for d in watch_dirs:
            try:
                wd = i.add_watch(d, WATCH_MASK)
                wd_map[wd] = d
                LOG.info('Watching %s for user %s', d, user)
            except Exception as e:
                LOG.exception('Failed to add watch for %s: %s', d, e)

        while running:
            for ev in i.read(timeout=1000):
                try:
                    dirname = wd_map.get(ev.wd, '')
                    name = ev.name
                    path = os.path.join(dirname, name)
                    evmask = flags.from_mask(ev.mask)
                    if 'CREATE' in evmask or 'MOVED_TO' in evmask:
                        evtype = 'created'
                    elif 'DELETE' in evmask or 'MOVED_FROM' in evmask:
                        evtype = 'deleted'
                    elif 'CLOSE_WRITE' in evmask or 'MODIFY' in evmask:
                        evtype = 'modified'
                    else:
                        evtype = 'modified'

                    old_hash = None
                    new_hash = None
                    if os.path.exists(path) and os.path.isfile(path):
                        new_hash = file_sha256(path)
                    # Attempt to read baseline hash
                    cur = conn.cursor()
                    cur.execute('SELECT sha256 FROM files WHERE path = ?', (path,))
                    row = cur.fetchone()
                    if row:
                        old_hash = row[0]

                    severity = classify_path(path)
                    event_insert(conn, path, evtype, severity, old_hash, new_hash)

                except Exception:
                    LOG.exception('Error processing inotify event')
            # loop
    else:
        # Simple polling fallback every 5 seconds
        LOG.info('inotify not available, falling back to polling')
        prev = {}
        while running:
            for d in watch_dirs:
                for root, dirs, files in os.walk(d):
                    for fname in files:
                        path = os.path.join(root, fname)
                        try:
                            if not os.path.isfile(path):
                                continue
                            sha = file_sha256(path)
                            if path not in prev:
                                # new file
                                event_insert(conn, path, 'created', classify_path(path), None, sha)
                                prev[path] = sha
                            elif prev[path] != sha:
                                event_insert(conn, path, 'modified', classify_path(path), prev[path], sha)
                                prev[path] = sha
                        except Exception:
                            continue
            time.sleep(5)


def discover_users():
    # For demo: list home directories under /home
    users = []
    for entry in os.listdir('/home'):
        p = os.path.join('/home', entry)
        if os.path.isdir(p):
            users.append(entry)
    return users


def main():
    # Setup logging to syslog
    handler = logging.handlers.SysLogHandler(address='/dev/log')
    fmt = logging.Formatter('%(name)s[%(process)d]: %(levelname)s: %(message)s')
    handler.setFormatter(fmt)
    LOG.addHandler(handler)
    LOG.setLevel(logging.INFO)

    signal.signal(signal.SIGTERM, sigterm_handler)

    users = discover_users()
    LOG.info('Discovered users: %s', ','.join(users))

    try:
        while running:
            for u in users:
                watch_user(u)
            time.sleep(10)
    except KeyboardInterrupt:
        LOG.info('Interrupted, exiting')


if __name__ == '__main__':
    main()
