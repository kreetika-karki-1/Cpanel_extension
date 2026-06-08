#!/usr/bin/env python3
"""metrics_collector.py

Polls PHP-FPM status pages and Apache/mod_status (if available) and writes
metrics into the WHM-level SQLite DB at /var/cpanel/fro/whm.db

This should be run as root or a dedicated user with permission to read
/var/cpanel/userdata and to reach domain status pages.
"""

import json
import logging
import logging.handlers
import os
import sqlite3
import signal
import sys
import time
import urllib.request
from urllib.error import URLError
from fro_utils import open_whm_db, init_whm_db

running = True
LOG = logging.getLogger('fro.metrics_collector')


def sigterm_handler(signum, frame):
    global running
    LOG.info('SIGTERM received, shutting down')
    running = False


def fetch_url(url, timeout=5):
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            return resp.read().decode('utf-8')
    except URLError as e:
        LOG.debug('Failed to fetch %s: %s', url, e)
        return None


def parse_php_fpm_status(body):
    try:
        data = json.loads(body)
        return {
            'active_processes': int(data.get('active_processes', 0)),
            'idle_processes': int(data.get('idle_processes', 0)),
            'accepted_conn': int(data.get('accepted_conn', 0)),
            'max_children_reached': int(data.get('max_children_reached', 0)),
            'slow_requests': int(data.get('slow_requests', 0)),
            'avg_response_time_ms': float(data.get('avg_response_time', 0.0)) if data.get('avg_response_time') else 0.0,
        }
    except Exception:
        return None


def collect_for_domain(domain, status_url):
    body = fetch_url(status_url)
    if not body:
        return None
    return parse_php_fpm_status(body)


def store_metric(conn, domain, metric):
    c = conn.cursor()
    c.execute('''INSERT INTO metrics (domain, timestamp, data)
                 VALUES (?, ?, ?)''', (domain, int(time.time()), json.dumps(metric)))
    conn.commit()


def discover_domains():
    # Read /var/cpanel/userdata to find domains and attempt to construct status URLs.
    domains = []
    base = '/var/cpanel/userdata'
    if not os.path.isdir(base):
        return domains
    for user in os.listdir(base):
        ud = os.path.join(base, user)
        if not os.path.isdir(ud):
            continue
        # Look for files ending with .php-fpm.yaml or domain data files
        for fname in os.listdir(ud):
            if fname.endswith('.php-fpm.yaml'):
                domain = fname.replace('.php-fpm.yaml', '')
                # try http://domain/status?full&json
                url = f'http://{domain}/status?full&json'
                domains.append((domain, url))
    return domains


def main():
    handler = logging.handlers.SysLogHandler(address='/dev/log')
    LOG.addHandler(handler)
    LOG.setLevel(logging.INFO)

    signal.signal(signal.SIGTERM, sigterm_handler)

    conn = open_whm_db()
    init_whm_db(conn)

    while running:
        domains = discover_domains()
        for domain, url in domains:
            metric = collect_for_domain(domain, url)
            if metric:
                store_metric(conn, domain, metric)
                LOG.info('Collected metrics for %s', domain)
        time.sleep(60)


if __name__ == '__main__':
    main()
