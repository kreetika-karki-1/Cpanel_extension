#!/usr/bin/env python3
"""
FRO Utilities Library
Shared logging, database connection, and path validators for FRO daemons.
"""

import os
import sys
import sqlite3
import logging
import hashlib
import json
from pathlib import Path
from typing import Optional, Dict, List, Tuple
from logging.handlers import SysLogHandler
import subprocess
import re

# ============================================================================
# LOGGING SETUP
# ============================================================================

def setup_logger(name: str, log_level=logging.INFO) -> logging.Logger:
    """
    Initialize logger with syslog handler for systemd integration.
    
    Args:
        name: Logger name (typically __name__ from caller)
        log_level: logging.INFO, logging.DEBUG, etc.
    
    Returns:
        Configured logger instance
    """
    logger = logging.getLogger(name)
    logger.setLevel(log_level)
    
    # Syslog handler for systemd journalctl
    try:
        syslog_handler = SysLogHandler(address='/dev/log')
        formatter = logging.Formatter(
            f'[%(name)s] %(levelname)s: %(message)s'
        )
        syslog_handler.setFormatter(formatter)
        logger.addHandler(syslog_handler)
    except Exception as e:
        # Fallback to stderr if syslog unavailable
        console_handler = logging.StreamHandler(sys.stderr)
        console_handler.setFormatter(
            logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        )
        logger.addHandler(console_handler)
    
    return logger


# ============================================================================
# DATABASE OPERATIONS
# ============================================================================

class FRODatabase:
    """
    Unified SQLite interface for FRO per-account and WHM-level databases.
    Enforces WAL mode for immutable audit logs and safe concurrent access.
    """
    
    def __init__(self, db_path: str, logger: logging.Logger = None):
        """
        Initialize database connection with WAL mode and foreign key support.
        
        Args:
            db_path: Absolute path to SQLite DB file
            logger: Logger instance (optional)
        """
        self.db_path = db_path
        self.logger = logger or setup_logger('FRODatabase')
        self.connection = None
        self._connect()
    
    def _connect(self):
        """Establish SQLite connection with production-grade settings."""
        try:
            os.makedirs(os.path.dirname(self.db_path), mode=0o755, exist_ok=True)
            self.connection = sqlite3.connect(self.db_path, check_same_thread=False)
            # Enable WAL for durability and concurrency
            self.connection.execute('PRAGMA journal_mode=WAL')
            # Enable foreign key constraints
            self.connection.execute('PRAGMA foreign_keys=ON')
            # Set synchronous to NORMAL for balance of speed vs durability
            self.connection.execute('PRAGMA synchronous=NORMAL')
            self.connection.row_factory = sqlite3.Row
            self.logger.debug(f"Connected to DB: {self.db_path}")
        except sqlite3.Error as e:
            self.logger.error(f"Failed to connect to DB {self.db_path}: {e}")
            raise
    
    def execute(self, query: str, params: Tuple = ()) -> sqlite3.Cursor:
        """
        Execute parameterized SQL query safely.
        
        Args:
            query: SQL query with ? placeholders
            params: Tuple of parameter values
        
        Returns:
            Cursor object
        """
        try:
            cursor = self.connection.execute(query, params)
            self.connection.commit()
            return cursor
        except sqlite3.Error as e:
            self.logger.error(f"Query error: {e} | Query: {query}")
            self.connection.rollback()
            raise
    
    def fetch_one(self, query: str, params: Tuple = ()) -> Optional[sqlite3.Row]:
        """Fetch single row (or None if no results)."""
        cursor = self.execute(query, params)
        return cursor.fetchone()
    
    def fetch_all(self, query: str, params: Tuple = ()) -> List[sqlite3.Row]:
        """Fetch all rows matching query."""
        cursor = self.execute(query, params)
        return cursor.fetchall()
    
    def insert(self, table: str, data: Dict) -> int:
        """
        Generic insert with parameterized values.
        
        Args:
            table: Table name
            data: Dict of column -> value pairs
        
        Returns:
            Last inserted row ID
        """
        columns = ', '.join(data.keys())
        placeholders = ', '.join(['?' for _ in data])
        query = f"INSERT INTO {table} ({columns}) VALUES ({placeholders})"
        cursor = self.execute(query, tuple(data.values()))
        return cursor.lastrowid
    
    def update(self, table: str, data: Dict, where: str, where_params: Tuple = ()):
        """
        Generic update with parameterized values.
        
        Args:
            table: Table name
            data: Dict of column -> value pairs to update
            where: WHERE clause (e.g., "id = ?")
            where_params: Tuple of parameters for WHERE clause
        """
        set_clause = ', '.join([f'{k} = ?' for k in data.keys()])
        query = f"UPDATE {table} SET {set_clause} WHERE {where}"
        params = tuple(data.values()) + where_params
        self.execute(query, params)
    
    def close(self):
        """Close database connection gracefully."""
        if self.connection:
            self.connection.close()
            self.logger.debug(f"Closed DB connection: {self.db_path}")
    
    def __del__(self):
        """Ensure connection is closed on object destruction."""
        self.close()


# ============================================================================
# PATH VALIDATION & SANITIZATION
# ============================================================================

def validate_user_path(user: str, path: str, logger: logging.Logger = None) -> Optional[str]:
    """
    Validate that a given path belongs to a cPanel user's home directory.
    Prevents directory traversal attacks.
    
    Args:
        user: cPanel username
        path: Path to validate (may contain ..)
        logger: Logger instance (optional)
    
    Returns:
        Canonical real path if valid, None if invalid
    """
    lgr = logger or setup_logger('validate_user_path')
    
    # Resolve to absolute canonical path
    try:
        user_home = f"/home/{user}"
        if not os.path.exists(user_home):
            lgr.warning(f"User home not found: {user_home}")
            return None
        
        # realpath resolves symlinks and .. sequences
        canonical_path = os.path.realpath(path)
        canonical_home = os.path.realpath(user_home)
        
        # Ensure path is within user's home
        if not canonical_path.startswith(canonical_home + os.sep) and canonical_path != canonical_home:
            lgr.warning(f"Path traversal attempt: {user} requested {path} (resolves to {canonical_path})")
            return None
        
        return canonical_path
    except Exception as e:
        lgr.error(f"Path validation error for {user}:{path}: {e}")
        return None


def get_excluded_paths(user: str, logger: logging.Logger = None) -> List[str]:
    """
    Return list of default excluded paths for a user.
    These should never be monitored for integrity changes.
    
    Args:
        user: cPanel username
        logger: Logger instance (optional)
    
    Returns:
        List of absolute paths to exclude
    """
    lgr = logger or setup_logger('get_excluded_paths')
    user_home = f"/home/{user}"
    
    default_excludes = [
        ".cpanel",
        ".softaculous",
        "tmp",
        ".cagefs",
        ".lastlogin",
        ".cache",
        ".session",
        ".trash",
    ]
    
    excluded_paths = []
    for exclude in default_excludes:
        full_path = os.path.join(user_home, exclude)
        excluded_paths.append(full_path)
    
    return excluded_paths


def is_cms_core_file(file_path: str) -> Tuple[bool, str]:
    """
    Classify a file as CMS core (WordPress, Joomla, Magento, Laravel).
    Used to assign severity levels to integrity events.
    
    Args:
        file_path: Absolute path to file
    
    Returns:
        Tuple of (is_core: bool, cms_type: str)
    """
    filename = os.path.basename(file_path)
    dirpath = os.path.dirname(file_path)
    
    # WordPress core detection
    wp_core_files = [
        'wp-load.php', 'wp-config.php', 'wp-settings.php',
        'index.php', 'wp-login.php', 'wp-activate.php'
    ]
    if filename in wp_core_files or '/wp-admin/' in file_path or '/wp-includes/' in file_path:
        return (True, 'WordPress')
    
    # Joomla core detection
    joomla_core_paths = ['/administrator/', '/libraries/', '/plugins/']
    if any(path in file_path for path in joomla_core_paths):
        joomla_core_files = ['index.php', 'configuration.php']
        if filename in joomla_core_files:
            return (True, 'Joomla')
    
    # Magento core detection
    magento_core_paths = ['/app/code/', '/app/etc/', '/var/']
    if any(path in file_path for path in magento_core_paths):
        return (True, 'Magento')
    
    # Laravel core detection
    laravel_core_files = ['artisan', 'composer.json']
    if filename in laravel_core_files:
        return (True, 'Laravel')
    
    return (False, '')


def classify_severity(file_path: str, event_type: str) -> str:
    """
    Classify event severity based on file type and event type.
    
    Args:
        file_path: Absolute path to file
        event_type: 'created', 'modified', 'deleted', 'permission_changed'
    
    Returns:
        Severity level: 'critical', 'warning', or 'info'
    """
    is_core, cms_type = is_cms_core_file(file_path)
    
    if is_core:
        return 'critical'
    
    # .htaccess modifications are warnings
    if os.path.basename(file_path) == '.htaccess':
        return 'warning'
    
    # Plugin/theme files in common locations
    if any(plugin_dir in file_path for plugin_dir in ['/plugins/', '/themes/', '/modules/']):
        return 'warning'
    
    # Default: uploads, media, and other user content
    return 'info'


# ============================================================================
# FILE HASHING & INTEGRITY
# ============================================================================

def compute_file_hash(file_path: str, algorithm='sha256', logger: logging.Logger = None) -> Optional[str]:
    """
    Compute cryptographic hash of file contents.
    
    Args:
        file_path: Absolute path to file
        algorithm: 'sha256', 'sha1', 'md5'
        logger: Logger instance (optional)
    
    Returns:
        Hex digest or None if error
    """
    lgr = logger or setup_logger('compute_file_hash')
    
    try:
        hash_obj = hashlib.new(algorithm)
        with open(file_path, 'rb') as f:
            # Read in chunks to handle large files efficiently
            for chunk in iter(lambda: f.read(8192), b''):
                hash_obj.update(chunk)
        return hash_obj.hexdigest()
    except Exception as e:
        lgr.warning(f"Failed to hash {file_path}: {e}")
        return None


def get_file_metadata(file_path: str, logger: logging.Logger = None) -> Optional[Dict]:
    """
    Extract file metadata: size, permissions, mtime.
    
    Args:
        file_path: Absolute path to file
        logger: Logger instance (optional)
    
    Returns:
        Dict with keys: size, perms (octal string), mtime (unix timestamp)
    """
    lgr = logger or setup_logger('get_file_metadata')
    
    try:
        stat_info = os.stat(file_path)
        return {
            'size': stat_info.st_size,
            'perms': oct(stat_info.st_mode)[-3:],
            'mtime': int(stat_info.st_mtime),
        }
    except Exception as e:
        lgr.warning(f"Failed to stat {file_path}: {e}")
        return None


# ============================================================================
# CMS DETECTION
# ============================================================================

def detect_cms(base_path: str, logger: logging.Logger = None) -> Optional[str]:
    """
    Detect CMS type in a given directory.
    
    Args:
        base_path: Absolute path to scan (typically public_html)
        logger: Logger instance (optional)
    
    Returns:
        CMS type string ('WordPress', 'Joomla', 'Magento', 'Laravel') or None
    """
    lgr = logger or setup_logger('detect_cms')
    
    cms_markers = {
        'WordPress': ['wp-content', 'wp-admin', 'wp-config.php'],
        'Joomla': ['components', 'modules', 'administrator/components'],
        'Magento': ['app/etc/local.xml', 'app/etc/env.php'],
        'Laravel': ['artisan', 'app', 'bootstrap', 'config'],
    }
    
    for cms_name, markers in cms_markers.items():
        if all(os.path.exists(os.path.join(base_path, marker)) for marker in markers):
            lgr.info(f"Detected {cms_name} at {base_path}")
            return cms_name
    
    return None


# ============================================================================
# CPANEL UAPI INTERFACE (subprocess-based)
# ============================================================================

def call_cpanel_uapi(user: str, module: str, function: str, args: Dict = None, logger: logging.Logger = None) -> Optional[Dict]:
    """
    Call cPanel UAPI via /usr/local/cpanel/bin/uapi subprocess.
    
    Args:
        user: cPanel username
        module: UAPI module name (e.g., 'Fileman', 'Email')
        function: UAPI function name
        args: Dict of arguments to pass
        logger: Logger instance (optional)
    
    Returns:
        Parsed JSON response or None on error
    """
    lgr = logger or setup_logger('call_cpanel_uapi')
    
    try:
        cmd = ['/usr/local/cpanel/bin/uapi', '--user', user, module, function]
        
        # Add arguments as key=value pairs
        if args:
            for key, value in args.items():
                cmd.append(f'{key}={value}')
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        
        if result.returncode != 0:
            lgr.error(f"UAPI call failed: {result.stderr}")
            return None
        
        return json.loads(result.stdout)
    except Exception as e:
        lgr.error(f"Error calling UAPI {module}::{function}: {e}")
        return None


# ============================================================================
# SHELL ESCAPE & EXECUTION (for privileged operations)
# ============================================================================

def safe_shell_exec(command: List[str], logger: logging.Logger = None, timeout: int = 30) -> Tuple[int, str, str]:
    """
    Execute shell command safely with no shell interpretation.
    Uses subprocess.run with shell=False to prevent injection.
    
    Args:
        command: List of command tokens (no shell parsing)
        logger: Logger instance (optional)
        timeout: Command timeout in seconds
    
    Returns:
        Tuple of (return_code, stdout, stderr)
    """
    lgr = logger or setup_logger('safe_shell_exec')
    
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            shell=False  # CRITICAL: Prevents shell injection
        )
        return (result.returncode, result.stdout, result.stderr)
    except subprocess.TimeoutExpired:
        lgr.error(f"Command timeout: {' '.join(command)}")
        return (124, '', 'Command timeout')
    except Exception as e:
        lgr.error(f"Command execution error: {e}")
        return (1, '', str(e))


if __name__ == '__main__':
    # Quick test
    logger = setup_logger('fro_utils_test', log_level=logging.DEBUG)
    logger.info("FRO utilities module loaded successfully")
