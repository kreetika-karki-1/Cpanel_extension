#!/usr/bin/env python3
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
