"""fro_utils.py

Shared utilities for FRO daemons: DB helpers, path validation and basic logging setup.
"""

import os
import sqlite3
import stat

# Per-account DBs live at /home/<user>/.fro/fim.db
# WHM DB lives at /var/cpanel/fro/whm.db


def get_db_path(user):
    homedir = os.path.join('/home', user)
    dbdir = os.path.join(homedir, '.fro')
    os.makedirs(dbdir, exist_ok=True, mode=0o700)
    return os.path.join(dbdir, 'fim.db')


def open_db(db_path):
    conn = sqlite3.connect(db_path, timeout=30, isolation_level=None)
    conn.execute('PRAGMA journal_mode=WAL')
    conn.execute('PRAGMA foreign_keys=ON')
    return conn


def init_db(conn):
    c = conn.cursor()
    # files table stores baseline
    c.execute('''CREATE TABLE IF NOT EXISTS files (
                     path TEXT PRIMARY KEY,
                     sha256 TEXT,
                     permissions TEXT,
                     size INTEGER,
                     mtime INTEGER,
                     resolved INTEGER DEFAULT 1
                 )''')
    # events are append-only
    c.execute('''CREATE TABLE IF NOT EXISTS events (
                     id INTEGER PRIMARY KEY AUTOINCREMENT,
                     path TEXT,
                     event_type TEXT,
                     severity TEXT,
                     old_sha256 TEXT,
                     new_sha256 TEXT,
                     timestamp INTEGER,
                     resolved INTEGER DEFAULT 0
                 )''')
    conn.commit()


def open_whm_db():
    dbdir = '/var/cpanel/fro'
    os.makedirs(dbdir, exist_ok=True)
    dbpath = os.path.join(dbdir, 'whm.db')
    conn = sqlite3.connect(dbpath, timeout=30, isolation_level=None)
    conn.execute('PRAGMA journal_mode=WAL')
    conn.execute('PRAGMA foreign_keys=ON')
    return conn


def init_whm_db(conn):
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS metrics (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    domain TEXT,
                    timestamp INTEGER,
                    data TEXT
                 )''')
    c.execute('''CREATE TABLE IF NOT EXISTS recommendations (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    domain TEXT,
                    timestamp INTEGER,
                    data TEXT
                 )''')
    conn.commit()


def is_path_allowed(user, path):
    # Ensure path resolves under /home/<user>
    try:
        real = os.path.realpath(path)
        home = os.path.realpath(os.path.join('/home', user))
        return real.startswith(home)
    except Exception:
        return False
