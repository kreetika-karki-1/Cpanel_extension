#!/usr/bin/env python3
"""baseline_manager.py

CLI tool to create or reset baselines for a given cPanel user.
Scans directories recursively, computes SHA-256 for files and stores metadata
in per-account SQLite DB at /home/<user>/.fro/fim.db

Note: This script should be installed under /opt/fro/daemon/
"""

import argparse
import hashlib
import os
import sqlite3
import stat
import sys
import time
from fro_utils import get_db_path, init_db, is_path_allowed, open_db

EXCLUDE_NAMES = {'.cpanel', '.softaculous', 'tmp', '.cagefs', '.lastlogin'}
DEFAULT_PATH = 'public_html'


def file_sha256(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(8192), b''):
            h.update(chunk)
    return h.hexdigest()


def scan_and_store(user, start_path):
    db_path = get_db_path(user)
    conn = open_db(db_path)
    c = conn.cursor()
    init_db(conn)

    base_home = os.path.join('/home', user)
    real_start = os.path.realpath(start_path)
    if not real_start.startswith(base_home):
        raise SystemExit('Start path must be within /home/{}'.format(user))

    for root, dirs, files in os.walk(real_start):
        # Apply exclusions
        dirs[:] = [d for d in dirs if d not in EXCLUDE_NAMES]
        for fname in files:
            try:
                path = os.path.join(root, fname)
                if not os.path.islink(path) and os.path.isfile(path):
                    st = os.stat(path)
                    sha = file_sha256(path)
                    c.execute('''INSERT OR REPLACE INTO files
                                (path, sha256, permissions, size, mtime, resolved)
                                VALUES (?, ?, ?, ?, ?, 1)
                                ''', (path, sha, oct(stat.S_IMODE(st.st_mode)), st.st_size, int(st.st_mtime)))
            except (OSError, IOError) as e:
                print('Skipping', path, 'due to', e)

    conn.commit()
    conn.close()


def main():
    parser = argparse.ArgumentParser(description='Create/reset baseline for user')
    parser.add_argument('--user', required=True, help='cPanel username')
    parser.add_argument('--path', help='Path to scan (default: /home/<user>/public_html)')
    args = parser.parse_args()

    user = args.user
    start = args.path or os.path.join('/home', user, DEFAULT_PATH)

    if not os.path.exists(start):
        print('Start path does not exist:', start)
        sys.exit(1)

    print('Scanning', start, 'for user', user)
    scan_and_store(user, start)
    print('Baseline created/updated at', time.asctime())


if __name__ == '__main__':
    main()
