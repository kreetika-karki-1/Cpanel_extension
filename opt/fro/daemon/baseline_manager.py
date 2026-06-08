#!/usr/bin/env python3
"""
FRO Baseline Manager
CLI tool to create, reset, and manage file integrity baselines for cPanel users.

Usage:
    /opt/fro/daemon/baseline_manager.py --user username --create-baseline [--path /path]
    /opt/fro/daemon/baseline_manager.py --user username --reset-baseline
    /opt/fro/daemon/baseline_manager.py --user username --verify [--path /path]
"""

import os
import sys
import argparse
import time
from pathlib import Path
from typing import Optional, List

# Add parent dir to path for imports
sys.path.insert(0, '/opt/fro/lib')

from fro_utils import (
    setup_logger, FRODatabase, validate_user_path, get_excluded_paths,
    compute_file_hash, get_file_metadata, detect_cms
)


class BaselineManager:
    """
    Manages file integrity baselines for a cPanel user.
    Creates initial hashes, detects changes, and provides verification reports.
    """
    
    def __init__(self, username: str, debug: bool = False):
        """
        Initialize baseline manager for a user.
        
        Args:
            username: cPanel username
            debug: Enable debug logging
        """
        self.username = username
        self.user_home = f"/home/{username}"
        self.fro_db_dir = os.path.join(self.user_home, '.fro')
        self.db_path = os.path.join(self.fro_db_dir, 'fim.db')
        self.excluded_paths = get_excluded_paths(username)
        
        log_level = 'DEBUG' if debug else 'INFO'
        self.logger = setup_logger(f'baseline_manager_{username}', log_level=log_level)
        
        self.db = None
        self.files_processed = 0
        self.total_size = 0
    
    def initialize(self) -> bool:
        """Initialize database connection."""
        try:
            os.makedirs(self.fro_db_dir, mode=0o700, exist_ok=True)
            self.db = FRODatabase(self.db_path, logger=self.logger)
            self._create_tables()
            return True
        except Exception as e:
            self.logger.error(f"Failed to initialize: {e}")
            return False
    
    def _create_tables(self):
        """Ensure baseline table exists."""
        try:
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
        except Exception as e:
            self.logger.error(f"Table creation failed: {e}")
            raise
    
    def create_baseline(self, base_path: Optional[str] = None) -> bool:
        """
        Create or update baseline for all files in a directory.
        Recursively scans directory and computes SHA-256 hashes.
        
        Args:
            base_path: Directory to scan (default: /home/user/public_html)
        
        Returns:
            True if successful
        """
        try:
            if not base_path:
                base_path = os.path.join(self.user_home, 'public_html')
            
            # Validate path
            canonical_path = validate_user_path(self.username, base_path, logger=self.logger)
            if not canonical_path:
                self.logger.error(f"Invalid path: {base_path}")
                return False
            
            if not os.path.isdir(canonical_path):
                self.logger.error(f"Path is not a directory: {canonical_path}")
                return False
            
            self.logger.info(f"Starting baseline creation for {canonical_path}")
            start_time = time.time()
            
            # Recursively process files
            self._process_directory(canonical_path)
            
            elapsed = time.time() - start_time
            self.logger.info(
                f"Baseline complete: {self.files_processed} files, "
                f"{self.total_size / (1024*1024):.2f} MB in {elapsed:.2f}s"
            )
            
            return True
        except Exception as e:
            self.logger.error(f"Baseline creation failed: {e}")
            return False
    
    def _process_directory(self, dir_path: str, max_depth: int = 20, current_depth: int = 0):
        """
        Recursively process files in directory for baselining.
        
        Args:
            dir_path: Directory to process
            max_depth: Maximum recursion depth
            current_depth: Current recursion depth
        """
        if current_depth > max_depth:
            self.logger.warning(f"Max depth reached at {dir_path}")
            return
        
        try:
            entries = os.scandir(dir_path)
        except PermissionError:
            self.logger.debug(f"Permission denied: {dir_path}")
            return
        except Exception as e:
            self.logger.warning(f"Error scanning {dir_path}: {e}")
            return
        
        for entry in entries:
            try:
                # Skip excluded paths
                if any(entry.path.startswith(exc) for exc in self.excluded_paths):
                    continue
                
                if entry.is_symlink():
                    continue
                
                if entry.is_dir(follow_symlinks=False):
                    self._process_directory(entry.path, max_depth, current_depth + 1)
                elif entry.is_file(follow_symlinks=False):
                    self._process_file(entry.path)
            
            except Exception as e:
                self.logger.debug(f"Error processing entry {entry.path}: {e}")
        
        try:
            entries.close()
        except:
            pass
    
    def _process_file(self, file_path: str):
        """
        Compute hash and metadata for a single file, store in baseline.
        
        Args:
            file_path: Absolute path to file
        """
        try:
            file_hash = compute_file_hash(file_path, logger=self.logger)
            file_metadata = get_file_metadata(file_path, logger=self.logger)
            
            if not file_hash or not file_metadata:
                return
            
            # Insert or replace in baseline
            self.db.execute("""
                INSERT OR REPLACE INTO fim_baseline 
                (file_path, hash, perms, size, mtime, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                file_path,
                file_hash,
                file_metadata['perms'],
                file_metadata['size'],
                file_metadata['mtime'],
                int(time.time())
            ))
            
            self.files_processed += 1
            self.total_size += file_metadata['size']
            
            if self.files_processed % 100 == 0:
                self.logger.info(f"Processed {self.files_processed} files...")
        
        except Exception as e:
            self.logger.debug(f"Error processing file {file_path}: {e}")
    
    def reset_baseline(self, base_path: Optional[str] = None) -> bool:
        """
        Clear baseline and all events, then create fresh baseline.
        
        Args:
            base_path: Directory to baseline (default: public_html)
        
        Returns:
            True if successful
        """
        try:
            self.logger.warning(f"Resetting baseline for {self.username}")
            
            # Clear tables
            self.db.execute("DELETE FROM fim_baseline")
            self.db.execute("DELETE FROM fim_events")
            
            self.logger.info("Cleared existing baseline and events")
            
            # Create new baseline
            return self.create_baseline(base_path)
        
        except Exception as e:
            self.logger.error(f"Reset failed: {e}")
            return False
    
    def verify_baseline(self, base_path: Optional[str] = None) -> bool:
        """
        Verify all files against current baseline.
        Reports any changes found.
        
        Args:
            base_path: Directory to verify (default: public_html)
        
        Returns:
            True if all files match baseline
        """
        try:
            if not base_path:
                base_path = os.path.join(self.user_home, 'public_html')
            
            canonical_path = validate_user_path(self.username, base_path, logger=self.logger)
            if not canonical_path:
                return False
            
            self.logger.info(f"Starting baseline verification for {canonical_path}")
            
            changes = []
            missing = []
            
            # Get all baseline entries
            baseline_files = self.db.fetch_all("""
                SELECT file_path, hash, perms FROM fim_baseline
            """)
            
            for baseline in baseline_files:
                file_path = baseline['file_path']
                baseline_hash = baseline['hash']
                baseline_perms = baseline['perms']
                
                if not os.path.exists(file_path):
                    missing.append(file_path)
                    continue
                
                current_hash = compute_file_hash(file_path, logger=self.logger)
                current_metadata = get_file_metadata(file_path, logger=self.logger)
                
                if not current_hash:
                    continue
                
                # Check for changes
                if current_hash != baseline_hash:
                    changes.append({
                        'file': file_path,
                        'type': 'hash_mismatch',
                        'old': baseline_hash,
                        'new': current_hash
                    })
                
                if current_metadata and current_metadata['perms'] != baseline_perms:
                    changes.append({
                        'file': file_path,
                        'type': 'permissions_changed',
                        'old': baseline_perms,
                        'new': current_metadata['perms']
                    })
            
            # Report results
            if changes:
                self.logger.warning(f"Found {len(changes)} file changes:")
                for change in changes[:10]:  # Show first 10
                    self.logger.warning(f"  {change['type']}: {change['file']}")
                if len(changes) > 10:
                    self.logger.warning(f"  ... and {len(changes) - 10} more")
            
            if missing:
                self.logger.warning(f"Found {len(missing)} missing files:")
                for file_path in missing[:10]:
                    self.logger.warning(f"  {file_path}")
                if len(missing) > 10:
                    self.logger.warning(f"  ... and {len(missing) - 10} more")
            
            if not changes and not missing:
                self.logger.info("Baseline verification passed: all files match")
                return True
            
            return False
        
        except Exception as e:
            self.logger.error(f"Verification failed: {e}")
            return False
    
    def get_baseline_stats(self) -> dict:
        """
        Get statistics about current baseline.
        
        Returns:
            Dict with stats
        """
        try:
            total_files = self.db.fetch_one(
                "SELECT COUNT(*) as count FROM fim_baseline"
            )
            
            total_size = self.db.fetch_one(
                "SELECT SUM(size) as total FROM fim_baseline"
            )
            
            total_events = self.db.fetch_one(
                "SELECT COUNT(*) as count FROM fim_events WHERE resolved = 0"
            )
            
            return {
                'baseline_files': total_files['count'] if total_files else 0,
                'baseline_size_mb': (total_size['total'] or 0) / (1024 * 1024),
                'unresolved_events': total_events['count'] if total_events else 0
            }
        except Exception as e:
            self.logger.error(f"Failed to get stats: {e}")
            return {}


def main():
    """Entry point for baseline manager CLI."""
    parser = argparse.ArgumentParser(
        description='FRO Baseline Manager - File integrity baseline management'
    )
    parser.add_argument('--user', required=True, help='cPanel username')
    parser.add_argument('--path', default=None, help='Directory path (default: public_html)')
    parser.add_argument('--create-baseline', action='store_true', help='Create/update baseline')
    parser.add_argument('--reset-baseline', action='store_true', help='Reset and recreate baseline')
    parser.add_argument('--verify', action='store_true', help='Verify baseline integrity')
    parser.add_argument('--stats', action='store_true', help='Show baseline statistics')
    parser.add_argument('--debug', action='store_true', help='Enable debug logging')
    
    args = parser.parse_args()
    
    # Validate username
    if not args.user or not all(c.isalnum() or c == '_' for c in args.user):
        print(f"ERROR: Invalid username: {args.user}", file=sys.stderr)
        sys.exit(1)
    
    # Initialize manager
    manager = BaselineManager(args.user, debug=args.debug)
    
    if not manager.initialize():
        print(f"ERROR: Failed to initialize baseline manager", file=sys.stderr)
        sys.exit(1)
    
    # Execute command
    success = False
    
    if args.create_baseline:
        success = manager.create_baseline(args.path)
        if success:
            print(f"✓ Baseline created successfully for {args.user}")
    
    elif args.reset_baseline:
        success = manager.reset_baseline(args.path)
        if success:
            print(f"✓ Baseline reset successfully for {args.user}")
    
    elif args.verify:
        success = manager.verify_baseline(args.path)
        if success:
            print(f"✓ Baseline verification passed for {args.user}")
        else:
            print(f"✗ Baseline verification failed for {args.user}")
    
    elif args.stats:
        stats = manager.get_baseline_stats()
        print(f"Baseline Statistics for {args.user}:")
        print(f"  Files in baseline: {stats.get('baseline_files', 0)}")
        print(f"  Total size: {stats.get('baseline_size_mb', 0):.2f} MB")
        print(f"  Unresolved events: {stats.get('unresolved_events', 0)}")
        success = True
    
    else:
        parser.print_help()
        sys.exit(1)
    
    # Close database
    if manager.db:
        manager.db.close()
    
    sys.exit(0 if success else 1)


if __name__ == '__main__':
    main()
