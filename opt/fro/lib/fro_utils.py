#!/usr/bin/env python3
"""
FRO Core Utilities Library
Provides shared logging, database connections, path validation, and CMS detection.
"""

import sqlite3
import logging
import logging.handlers
import os
import sys
import hashlib
import re
from pathlib import Path
from typing import Optional, Dict, List, Tuple
from datetime import datetime, timedelta
import pwd

# ============================================================================
# LOGGING CONFIGURATION
# ============================================================================

def setup_logging(name: str, level=logging.INFO, syslog_enabled=True):
    """
    Configure logging with both file and syslog output.
    
    Args:
        name: Logger name (typically __name__)
        level: Logging level (default: INFO)
        syslog_enabled: Whether to include syslog handler
    
    Returns:
        Configured logger instance
    """
    logger = logging.getLogger(name)
    logger.setLevel(level)
    
    # File handler: /var/log/fro/
    log_dir = "/var/log/fro"
    os.makedirs(log_dir, exist_ok=True)
    
    file_handler = logging.FileHandler(f"{log_dir}/{name}.log")
    file_handler.setLevel(level)
    
    # Formatter
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - [%(process)d] - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)
    
    # Syslog handler
    if syslog_enabled:
        try:
            syslog_handler = logging.handlers.SysLogHandler(address='/dev/log')
            syslog_handler.setLevel(level)
            syslog_formatter = logging.Formatter(f'fro[%(process)d]: %(levelname)s - %(message)s')
            syslog_handler.setFormatter(syslog_formatter)
            logger.addHandler(syslog_handler)
        except Exception as e:
            logger.warning(f"Could not connect to syslog: {e}")
    
    return logger


# ============================================================================
# DATABASE OPERATIONS
# ============================================================================

class FRODatabase:
    """
    Wrapper for FRO SQLite database connections with WAL mode and thread safety.
    """
    
    def __init__(self, db_path: str, logger: logging.Logger = None):
        """
        Initialize database connection.
        
        Args:
            db_path: Full path to SQLite database file
            logger: Logger instance (optional)
        """
        self.db_path = db_path
        self.logger = logger or logging.getLogger(__name__)
        self._ensure_dir()
        self.conn = None
    
    def _ensure_dir(self):
        """Ensure parent directory exists."""
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
    
    def connect(self) -> sqlite3.Connection:
        """
        Open database connection with WAL mode and row factory.
        
        Returns:
            sqlite3.Connection object
        """
        try:
            self.conn = sqlite3.connect(self.db_path, timeout=10.0)
            self.conn.row_factory = sqlite3.Row
            
            # Enable WAL mode for append-only immutable logs
            self.conn.execute('PRAGMA journal_mode=WAL')
            self.conn.execute('PRAGMA synchronous=NORMAL')
            self.logger.debug(f"Connected to {self.db_path}")
            return self.conn
        except sqlite3.Error as e:
            self.logger.error(f"Database connection failed: {e}")
            raise
    
    def execute(self, query: str, params: Tuple = ()) -> sqlite3.Cursor:
        """
        Execute parameterized query (protection against SQL injection).
        
        Args:
            query: SQL query string
            params: Tuple of query parameters
        
        Returns:
            sqlite3.Cursor object
        """
        if not self.conn:
            self.connect()
        try:
            return self.conn.execute(query, params)
        except sqlite3.Error as e:
            self.logger.error(f"Query execution failed: {e}\nQuery: {query}")
            raise
    
    def commit(self):
        """Commit transaction."""
        if self.conn:
            self.conn.commit()
    
    def close(self):
        """Close database connection."""
        if self.conn:
            self.conn.close()
            self.conn = None
    
    def __del__(self):
        """Ensure connection is closed on object destruction."""
        self.close()


# ============================================================================
# PATH VALIDATION & SECURITY
# ============================================================================

class PathValidator:
    """
    Validates and sanitizes file paths to prevent directory traversal attacks.
    """
    
    # Disallowed paths that should never be monitored
    SYSTEM_PATHS = [
        '/usr', '/bin', '/sbin', '/lib', '/etc', '/sys', '/proc', '/root',
        '/boot', '/dev', '/var/spool', '/var/lock'
    ]
    
    # Default exclusions within monitored paths
    DEFAULT_EXCLUSIONS = [
        '.cpanel', '.softaculous', '.tmp', 'tmp', '.cagefs', '.lastlogin',
        '.cache', '.composer', 'node_modules', '__pycache__', '.git',
        '.svn', '.hg', 'wp-content/cache', 'wp-content/uploads',
        'var/tmp', 'var/cache'
    ]
    
    @staticmethod
    def is_safe_path(path: str, base_dir: str = None) -> bool:
        """
        Validate that a path is safe to monitor.
        
        Args:
            path: Path to validate
            base_dir: Optional base directory to confine path to
        
        Returns:
            True if path is safe, False otherwise
        """
        try:
            # Resolve symlinks and remove . and ..
            real_path = os.path.realpath(path)
            
            # Reject if path doesn't exist or isn't readable
            if not os.path.exists(real_path):
                return False
            
            # Reject system paths
            for sys_path in PathValidator.SYSTEM_PATHS:
                if real_path.startswith(sys_path):
                    return False
            
            # Confine to base_dir if specified
            if base_dir:
                real_base = os.path.realpath(base_dir)
                if not real_path.startswith(real_base):
                    return False
            
            return True
        except (OSError, ValueError):
            return False
    
    @staticmethod
    def should_exclude(file_path: str, exclusions: List[str] = None) -> bool:
        """
        Check if a file path matches exclusion patterns.
        
        Args:
            file_path: File path to check
            exclusions: List of exclusion patterns (default: DEFAULT_EXCLUSIONS)
        
        Returns:
            True if path should be excluded, False otherwise
        """
        if exclusions is None:
            exclusions = PathValidator.DEFAULT_EXCLUSIONS
        
        basename = os.path.basename(file_path)
        
        for pattern in exclusions:
            if pattern in file_path or pattern == basename:
                return True
            # Check for glob-like patterns
            if re.match(f".*{re.escape(pattern)}.*", file_path):
                return True
        
        return False


# ============================================================================
# HASHING & FILE OPERATIONS
# ============================================================================

class FileHasher:
    """
    Compute and verify file hashes (SHA-256).
    """
    
    CHUNK_SIZE = 65536  # 64KB chunks for large files
    
    @staticmethod
    def compute_hash(file_path: str, logger: logging.Logger = None) -> Optional[str]:
        """
        Compute SHA-256 hash of a file.
        
        Args:
            file_path: Path to file
            logger: Logger instance (optional)
        
        Returns:
            Hex digest string or None if file cannot be read
        """
        try:
            sha256_hash = hashlib.sha256()
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(FileHasher.CHUNK_SIZE), b''):
                    sha256_hash.update(chunk)
            return sha256_hash.hexdigest()
        except (OSError, IOError) as e:
            if logger:
                logger.warning(f"Could not hash file {file_path}: {e}")
            return None
    
    @staticmethod
    def get_file_metadata(file_path: str) -> Dict:
        """
        Get file metadata (size, mtime, permissions).
        
        Args:
            file_path: Path to file
        
        Returns:
            Dictionary with file metadata
        """
        try:
            stat = os.stat(file_path)
            return {
                'size': stat.st_size,
                'mtime': int(stat.st_mtime),
                'permissions': oct(stat.st_mode)[-3:],
                'uid': stat.st_uid,
                'gid': stat.st_gid
            }
        except OSError:
            return {}


# ============================================================================
# CMS DETECTION & CLASSIFICATION
# ============================================================================

class CMSDetector:
    """
    Detect CMS installations and classify file severity.
    """
    
    # CMS-specific core files (map of CMS name -> list of core files)
    CMS_SIGNATURES = {
        'wordpress': [
            'wp-load.php', 'wp-config.php', 'wp-settings.php',
            'wp-admin/includes/misc.php', 'wp-includes/load.php'
        ],
        'joomla': [
            'components/com_content/content.php',
            'includes/framework.php', 'libraries/joomla/factory.php'
        ],
        'magento': [
            'app/Mage.php', 'shell/abstract.php',
            'var/generation/Magento/Framework/App/Bootstrap.php'
        ],
        'laravel': [
            'bootstrap/app.php', 'artisan', 'config/app.php'
        ],
        'drupal': [
            'includes/bootstrap.inc', 'includes/common.inc',
            'core/lib/Drupal.php'
        ]
    }
    
    @staticmethod
    def detect_cms(base_path: str) -> Optional[str]:
        """
        Detect CMS installed at base_path.
        
        Args:
            base_path: Base directory to check
        
        Returns:
            CMS name string or None if not detected
        """
        for cms_name, signatures in CMSDetector.CMS_SIGNATURES.items():
            for sig_file in signatures:
                full_path = os.path.join(base_path, sig_file)
                if os.path.exists(full_path):
                    return cms_name
        return None
    
    @staticmethod
    def classify_file_severity(file_path: str, base_path: str) -> str:
        """
        Classify file change severity based on location and CMS type.
        
        Args:
            file_path: Path to changed file
            base_path: Base monitoring directory
        
        Returns:
            Severity level: 'critical', 'warning', or 'info'
        """
        relative_path = os.path.relpath(file_path, base_path)
        
        # Detect CMS
        cms = CMSDetector.detect_cms(base_path)
        
        # Critical: core CMS files
        if cms:
            cms_sigs = CMSDetector.CMS_SIGNATURES.get(cms, [])
            for sig in cms_sigs:
                if sig in relative_path:
                    return 'critical'
        
        # Critical: system files
        if relative_path.startswith('.htaccess') or relative_path.startswith('web.config'):
            return 'critical'
        
        # Warning: plugin/theme files, config files
        if any(x in relative_path for x in ['plugin', 'theme', 'wp-content', 'app/code', 'config']):
            return 'warning'
        
        # Info: uploads, media, logs
        if any(x in relative_path for x in ['uploads', 'media', 'logs', 'tmp', 'cache']):
            return 'info'
        
        # Default: warning
        return 'warning'


# ============================================================================
# USER & GROUP UTILITIES
# ============================================================================

class UserUtils:
    """
    Utilities for working with system users and groups.
    """
    
    @staticmethod
    def get_user_home(username: str) -> Optional[str]:
        """
        Get home directory for a user.
        
        Args:
            username: Username to look up
        
        Returns:
            Home directory path or None if user not found
        """
        try:
            return pwd.getpwnam(username).pw_dir
        except KeyError:
            return None
    
    @staticmethod
    def get_cpanel_user_list() -> List[str]:
        """
        Get list of cPanel account usernames.
        
        Returns:
            List of username strings
        """
        users = []
        passwd_file = '/etc/passwd'
        
        try:
            with open(passwd_file, 'r') as f:
                for line in f:
                    parts = line.strip().split(':')
                    if len(parts) >= 3:
                        username = parts[0]
                        # Skip system users (uid < 500)
                        try:
                            uid = int(parts[2])
                            if uid >= 500:
                                users.append(username)
                        except ValueError:
                            continue
        except IOError:
            pass
        
        return users


# ============================================================================
# TIME & DATE UTILITIES
# ============================================================================

class TimeUtils:
    """
    Time and date utility functions.
    """
    
    @staticmethod
    def get_unix_timestamp(days_ago: int = 0) -> int:
        """
        Get Unix timestamp for a date.
        
        Args:
            days_ago: Number of days in the past (0 = now)
        
        Returns:
            Unix timestamp
        """
        return int((datetime.now() - timedelta(days=days_ago)).timestamp())
    
    @staticmethod
    def format_timestamp(ts: int) -> str:
        """
        Format Unix timestamp as human-readable string.
        
        Args:
            ts: Unix timestamp
        
        Returns:
            Formatted datetime string
        """
        return datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')


# ============================================================================
# INITIALIZATION
# ============================================================================

if __name__ == "__main__":
    # Basic test
    logger = setup_logging(__name__)
    logger.info("FRO utilities library loaded successfully")
    
    # Test path validation
    test_path = "/home/testuser/public_html"
    if PathValidator.is_safe_path(test_path):
        logger.info(f"Path {test_path} is safe")
    else:
        logger.warning(f"Path {test_path} is not safe")
