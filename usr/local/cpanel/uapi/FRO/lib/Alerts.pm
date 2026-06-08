package Alerts;

use strict;
use warnings;
use DBI;
use JSON;

# Minimal Alerts.pm that reads per-account DB and returns recent events

sub db_path_for_user {
    my ($user) = @_;
    return "/home/$user/.fro/fim.db";
}

sub list_alerts {
    my ($user) = @_;
    my $db = db_path_for_user($user);
    my $dbh = DBI->connect("dbi:SQLite:dbname=$db", '', '', { RaiseError => 0, PrintError => 0 });
    my $sth = $dbh->prepare('SELECT path,event_type,severity,old_sha256,new_sha256,timestamp FROM events WHERE timestamp > ? ORDER BY timestamp DESC LIMIT 200');
    my $since = time() - 86400;
    $sth->execute($since);
    my @rows;
    while (my $r = $sth->fetchrow_hashref) {
        push @rows, { %$r };
    }
    $dbh->disconnect if $dbh;
    return { alerts => \\@rows, files_changed_today => scalar(@rows), unreviewed => scalar(@rows), last_scan => '' };
}

sub approve_alert {
    my ($user, $path) = @_;
    # Approve means update files table baseline to new sha and mark events resolved
    my $db = db_path_for_user($user);
    my $dbh = DBI->connect("dbi:SQLite:dbname=$db", '', '', { RaiseError => 1 });
    my $e = $dbh->prepare('SELECT new_sha256 FROM events WHERE path = ? ORDER BY timestamp DESC LIMIT 1');
    $e->execute($path);
    my $row = $e->fetchrow_arrayref;
    return 0 unless $row;
    my $newsha = $row->[0];
    my $upd = $dbh->prepare('INSERT OR REPLACE INTO files (path, sha256, permissions, size, mtime, resolved) VALUES (?, ?, ?, ?, ?, 1)');
    # We'll attempt to stat the file
    my ($perm, $size, $mtime) = ('',0,0);
    if (-f $path) {
        my @s = stat($path);
        $perm = sprintf('%o', $s[2] & 07777);
        $size = $s[7];
        $mtime = $s[9];
    }
    $upd->execute($path, $newsha, $perm, $size, $mtime);
    my $r = $dbh->do('UPDATE events SET resolved=1 WHERE path = ?', undef, $path);
    $dbh->disconnect;
    return 1;
}

sub quarantine {
    my ($user, $path) = @_;
    my $quarantine_dir = "/home/$user/.fro/quarantine";
    mkdir $quarantine_dir unless -d $quarantine_dir;
    my $ts = time();
    my $base = (split('/', $path))[-1];
    my $dest = "$quarantine_dir/$base.$ts";
    if (-e $path) {
        rename($path, $dest);
        return 1;
    }
    return 0;
}

1;
