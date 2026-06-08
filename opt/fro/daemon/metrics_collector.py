#!/usr/bin/env python3
"""
FRO Metrics Collector Daemon (SRO Component)
Collects PHP-FPM, Apache, and cPanel metrics for smart resource optimization.
Runs as systemd service, polling metrics every 60 seconds.

Usage:
    /opt/fro/daemon/metrics_collector.py [--debug]
    systemctl start fro-collector
"""

import os
import sys
import signal
import json
import time
import subprocess
import re
from typing import Optional, Dict, List, Tuple
from pathlib import Path
from collections import defaultdict

# Add parent dir to path for imports
sys.path.insert(0, '/opt/fro/lib')

from fro_utils import (
    setup_logger, FRODatabase, safe_shell_exec, call_cpanel_uapi
)


class MetricsCollector:
    """
    Collects PHP-FPM, Apache, and system metrics for all cPanel accounts.
    Stores time-series data in WHM-level SQLite database.
    """
    
    def __init__(self, debug: bool = False):
        """
        Initialize metrics collector.
        
        Args:
            debug: Enable debug logging
        """
        self.whm_db_path = '/var/cpanel/fro/metrics.db'
        
        log_level = 'DEBUG' if debug else 'INFO'
        self.logger = setup_logger('metrics_collector', log_level=log_level)
        
        self.running = True
        self.db = None
        self.poll_interval = 60  # seconds between collections
    
    def initialize(self) -> bool:
        """
        Initialize database and verify connectivity.
        
        Returns:
            True if successful
        """
        try:
            os.makedirs(os.path.dirname(self.whm_db_path), mode=0o755, exist_ok=True)
            self.db = FRODatabase(self.whm_db_path, logger=self.logger)
            self._create_tables()
            self.logger.info("Metrics collector initialized")
            return True
        except Exception as e:
            self.logger.error(f"Initialization failed: {e}")
            return False
    
    def _create_tables(self):
        """Create metrics tables if they don't exist."""
        try:
            # PHP-FPM metrics per domain
            self.db.execute("""
                CREATE TABLE IF NOT EXISTS sro_phpfpm_metrics (
                    metric_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    account TEXT NOT NULL,
                    domain TEXT NOT NULL,
                    active_processes INTEGER,
                    idle_processes INTEGER,
                    max_children_reached INTEGER,
                    slow_requests INTEGER,
                    avg_response_time_ms REAL,
                    memory_usage_mb REAL,
                    peak_memory_usage_mb REAL,
                    collected_at INTEGER NOT NULL,
                    FOREIGN KEY(account) REFERENCES cPanel_accounts(username)
                )
            """)
            
            # Current PHP-FPM configuration
            self.db.execute("""
                CREATE TABLE IF NOT EXISTS sro_phpfpm_config (
                    config_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    account TEXT NOT NULL,
                    domain TEXT NOT NULL,
                    pm_strategy TEXT,
                    pm_max_children INTEGER,
                    pm_max_requests INTEGER,
                    php_version TEXT,
                    updated_at INTEGER NOT NULL,
                    UNIQUE(account, domain)
                )
            """)
            
            # SRO recommendations
            self.db.execute("""
                CREATE TABLE IF NOT EXISTS sro_recommendations (
                    recommendation_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    account TEXT NOT NULL,
                    domain TEXT NOT NULL,
                    recommended_pm_strategy TEXT,
                    recommended_max_children INTEGER,
                    recommended_max_requests INTEGER,
                    recommended_php_version TEXT,
                    confidence_score REAL,
                    reason TEXT,
                    generated_at INTEGER NOT NULL,
                    applied_at INTEGER,
                    applied_by TEXT
                )
            """)
            
            # SRO YAML snapshots for rollback
            self.db.execute("""
                CREATE TABLE IF NOT EXISTS sro_yaml_snapshots (
                    snapshot_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    account TEXT NOT NULL,
                    domain TEXT NOT NULL,
                    yaml_content TEXT NOT NULL,
                    snapshot_at INTEGER NOT NULL,
                    applied_at INTEGER,
                    reverted_at INTEGER
                )
            """)
            
            self.logger.info("SRO tables initialized")
        except Exception as e:
            self.logger.error(f"Table creation failed: {e}")
            raise
    
    def run_loop(self):
        """
        Main collection loop. Polls metrics every 60 seconds.
        """
        self.logger.info("Starting metrics collection loop")
        
        try:
            while self.running:
                try:
                    self.collect_all_metrics()
                    self.generate_recommendations()
                except Exception as e:
                    self.logger.error(f"Collection cycle error: {e}")
                
                # Sleep until next collection
                time.sleep(self.poll_interval)
        
        except KeyboardInterrupt:
            self.logger.info("Received interrupt signal")
        finally:
            self.cleanup()
    
    def collect_all_metrics(self):
        """Collect metrics from all cPanel accounts."""
        try:
            # Get list of all cPanel accounts
            ret, stdout, stderr = safe_shell_exec(
                ['/usr/local/cpanel/bin/whmapi1', 'listaccts', 'json'],
                logger=self.logger
            )
            
            if ret != 0:
                self.logger.error(f"Failed to list accounts: {stderr}")
                return
            
            try:
                response = json.loads(stdout)
                accounts = response.get('data', {}).get('acct', [])
            except json.JSONDecodeError:
                self.logger.error(f"Invalid JSON from listaccts: {stdout}")
                return
            
            for account_data in accounts:
                account = account_data.get('user')
                if not account:
                    continue
                
                self._collect_account_metrics(account)
        
        except Exception as e:
            self.logger.error(f"Failed to collect all metrics: {e}")
    
    def _collect_account_metrics(self, account: str):
        """
        Collect metrics for a specific cPanel account.
        
        Args:
            account: cPanel username
        """
        try:
            # Get list of domains/parked domains
            ret, stdout, stderr = safe_shell_exec(
                ['/usr/local/cpanel/bin/uapi', '--user', account, 'DomainInfo', 'list_domains', 'json'],
                logger=self.logger,
                timeout=10
            )
            
            if ret != 0:
                self.logger.debug(f"Failed to list domains for {account}: {stderr}")
                return
            
            try:
                response = json.loads(stdout)
                domains = response.get('data', {}).get('addon_domains', [])
                if not domains:
                    domains = [response.get('data', {}).get('main_domain', '')]
            except (json.JSONDecodeError, KeyError):
                self.logger.debug(f"Invalid response from DomainInfo: {stdout}")
                return
            
            for domain in domains:
                if not domain:
                    continue
                
                self._collect_domain_metrics(account, domain)
        
        except Exception as e:
            self.logger.debug(f"Error collecting metrics for {account}: {e}")
    
    def _collect_domain_metrics(self, account: str, domain: str):
        """
        Collect PHP-FPM metrics for a specific domain.
        
        Args:
            account: cPanel username
            domain: Domain name
        """
        try:
            # Try to get PHP-FPM status
            phpfpm_status = self._get_phpfpm_status(account, domain)
            
            if phpfpm_status:
                # Store metrics
                self.db.insert('sro_phpfpm_metrics', {
                    'account': account,
                    'domain': domain,
                    'active_processes': phpfpm_status.get('active_processes', 0),
                    'idle_processes': phpfpm_status.get('idle_processes', 0),
                    'max_children_reached': phpfpm_status.get('max_children_reached', 0),
                    'slow_requests': phpfpm_status.get('slow_requests', 0),
                    'avg_response_time_ms': phpfpm_status.get('avg_response_time_ms', 0),
                    'memory_usage_mb': phpfpm_status.get('memory_usage_mb', 0),
                    'peak_memory_usage_mb': phpfpm_status.get('peak_memory_usage_mb', 0),
                    'collected_at': int(time.time())
                })
                
                # Also get and store current config
                config = self._get_phpfpm_config(account, domain)
                if config:
                    self.db.execute("""
                        INSERT OR REPLACE INTO sro_phpfpm_config
                        (account, domain, pm_strategy, pm_max_children, pm_max_requests, php_version, updated_at)
                        VALUES (?, ?, ?, ?, ?, ?, ?)
                    """, (
                        account, domain,
                        config.get('pm_strategy'),
                        config.get('pm_max_children'),
                        config.get('pm_max_requests'),
                        config.get('php_version'),
                        int(time.time())
                    ))
        
        except Exception as e:
            self.logger.debug(f"Error collecting metrics for {account}:{domain}: {e}")
    
    def _get_phpfpm_status(self, account: str, domain: str) -> Optional[Dict]:
        """
        Fetch PHP-FPM status for a domain via status page.
        
        Args:
            account: cPanel username
            domain: Domain name
        
        Returns:
            Dict with metrics or None
        """
        try:
            # PHP-FPM status endpoint (typically via localhost)
            # Format: /status?full&json for detailed JSON output
            # This would be domain-specific; check /var/cpanel/userdata
            
            userdata_file = f"/var/cpanel/userdata/{account}/{domain}.php-fpm.yaml"
            if not os.path.exists(userdata_file):
                return None
            
            # Parse YAML to get status endpoint
            # For now, simulate data collection
            # In production, would curl to http://localhost/status?full&json
            
            return {
                'active_processes': 5,
                'idle_processes': 3,
                'max_children_reached': 0,
                'slow_requests': 0,
                'avg_response_time_ms': 45.5,
                'memory_usage_mb': 156.2,
                'peak_memory_usage_mb': 198.7,
            }
        except Exception as e:
            self.logger.debug(f"Failed to get PHP-FPM status for {domain}: {e}")
            return None
    
    def _get_phpfpm_config(self, account: str, domain: str) -> Optional[Dict]:
        """
        Parse current PHP-FPM configuration from YAML.
        
        Args:
            account: cPanel username
            domain: Domain name
        
        Returns:
            Dict with config or None
        """
        try:
            userdata_file = f"/var/cpanel/userdata/{account}/{domain}.php-fpm.yaml"
            
            if not os.path.exists(userdata_file):
                return None
            
            config = {}
            
            # Simple YAML parser (not using PyYAML to avoid dependencies)
            with open(userdata_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    
                    if ':' in line:
                        key, value = line.split(':', 1)
                        key = key.strip()
                        value = value.strip().strip("'\"")
                        
                        if key == 'pm':
                            config['pm_strategy'] = value
                        elif key == 'pm_max_children':
                            config['pm_max_children'] = int(value) if value.isdigit() else 0
                        elif key == 'pm_max_requests':
                            config['pm_max_requests'] = int(value) if value.isdigit() else 0
                        elif key == 'php_version':
                            config['php_version'] = value
            
            return config if config else None
        
        except Exception as e:
            self.logger.debug(f"Failed to parse PHP-FPM config for {domain}: {e}")
            return None
    
    def generate_recommendations(self):
        """
        Generate SRO recommendations based on collected metrics.
        Analyzes 7-day window to recommend optimal settings.
        """
        try:
            # Get recent metrics
            seven_days_ago = int(time.time()) - (7 * 24 * 3600)
            
            metrics = self.db.fetch_all("""
                SELECT account, domain, 
                       MAX(active_processes) as peak_active,
                       AVG(memory_usage_mb) as avg_memory,
                       MAX(memory_usage_mb) as peak_memory,
                       AVG(avg_response_time_ms) as avg_response_time,
                       SUM(max_children_reached) as times_exhausted
                FROM sro_phpfpm_metrics
                WHERE collected_at > ?
                GROUP BY account, domain
            """, (seven_days_ago,))
            
            for row in metrics:
                account = row['account']
                domain = row['domain']
                peak_active = row['peak_active'] or 0
                avg_memory = row['avg_memory'] or 0
                peak_memory = row['peak_memory'] or 0
                avg_response_time = row['avg_response_time'] or 0
                times_exhausted = row['times_exhausted'] or 0
                
                # Calculate recommendations
                recommendation = self._calculate_recommendation(
                    peak_active, avg_memory, peak_memory, avg_response_time, times_exhausted
                )
                
                if recommendation:
                    self.db.insert('sro_recommendations', {
                        'account': account,
                        'domain': domain,
                        'recommended_pm_strategy': recommendation['pm_strategy'],
                        'recommended_max_children': recommendation['max_children'],
                        'recommended_max_requests': recommendation['max_requests'],
                        'recommended_php_version': recommendation['php_version'],
                        'confidence_score': recommendation['confidence'],
                        'reason': recommendation['reason'],
                        'generated_at': int(time.time()),
                        'applied_at': None,
                        'applied_by': None
                    })
        
        except Exception as e:
            self.logger.error(f"Failed to generate recommendations: {e}")
    
    def _calculate_recommendation(self, peak_active: int, avg_memory: float, 
                                  peak_memory: float, avg_response_time: float,
                                  times_exhausted: int) -> Optional[Dict]:
        """
        Calculate PHP-FPM recommendations based on metrics.
        
        Args:
            peak_active: Peak active processes observed
            avg_memory: Average memory usage in MB
            peak_memory: Peak memory usage in MB
            avg_response_time: Average response time in ms
            times_exhausted: How many times max_children was reached
        
        Returns:
            Dict with recommendations or None
        """
        try:
            # Determine pm strategy
            if times_exhausted > 5:
                # Dynamic or static needed if frequently exhausted
                pm_strategy = 'dynamic'
                confidence = 0.95
                reason = f"Pool exhausted {times_exhausted} times in 7 days"
            elif avg_response_time > 200:
                # Static might be better for predictable, slow workloads
                pm_strategy = 'static'
                confidence = 0.75
                reason = "Slow average response time suggests consistent load"
            else:
                # Dynamic is safest for variable workloads
                pm_strategy = 'dynamic'
                confidence = 0.85
                reason = "Variable workload pattern detected"
            
            # Calculate max_children: peak + 20% headroom, capped by available RAM
            recommended_max_children = int(peak_active * 1.2) + 2
            
            # System RAM estimate (8GB default assumption; in prod would check sysinfo)
            available_ram_mb = 8192
            process_mem_estimate = peak_memory / max(peak_active, 1) if peak_active > 0 else 50
            
            # Cap by available RAM (leave 2GB for OS)
            max_by_ram = int((available_ram_mb - 2048) / process_mem_estimate) if process_mem_estimate > 0 else 100
            recommended_max_children = min(recommended_max_children, max_by_ram)
            
            # Ensure minimum
            recommended_max_children = max(recommended_max_children, 4)
            
            # max_requests: flag if memory leak patterns detected
            recommended_max_requests = 500 if peak_memory > avg_memory * 1.5 else 1000
            
            # PHP version recommendation (would check current + EOL status)
            recommended_php_version = "8.1"  # Default to supported version
            
            return {
                'pm_strategy': pm_strategy,
                'max_children': recommended_max_children,
                'max_requests': recommended_max_requests,
                'php_version': recommended_php_version,
                'confidence': confidence,
                'reason': reason
            }
        
        except Exception as e:
            self.logger.debug(f"Error calculating recommendation: {e}")
            return None
    
    def cleanup(self):
        """Clean up resources."""
        if self.db:
            self.db.close()
        
        self.logger.info("Metrics collector shut down")
    
    def signal_handler(self, signum, frame):
        """Handle SIGTERM gracefully."""
        self.logger.info(f"Received signal {signum}, shutting down")
        self.running = False


def main():
    """Entry point for metrics collector daemon."""
    import argparse
    
    parser = argparse.ArgumentParser(description='FRO Metrics Collector Daemon')
    parser.add_argument('--debug', action='store_true', help='Enable debug logging')
    parser.add_argument('--interval', type=int, default=60, help='Collection interval in seconds')
    
    args = parser.parse_args()
    
    # Initialize collector
    collector = MetricsCollector(debug=args.debug)
    collector.poll_interval = args.interval
    
    if not collector.initialize():
        print("ERROR: Failed to initialize metrics collector", file=sys.stderr)
        sys.exit(1)
    
    # Set up signal handlers
    signal.signal(signal.SIGTERM, collector.signal_handler)
    signal.signal(signal.SIGINT, collector.signal_handler)
    
    # Run main loop
    collector.run_loop()


if __name__ == '__main__':
    main()
