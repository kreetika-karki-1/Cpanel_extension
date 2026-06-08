package Metrics;

use strict;
use warnings;
use DBI;
use JSON;

sub whm_db {
    my $db = '/var/cpanel/fro/whm.db';
    return DBI->connect("dbi:SQLite:dbname=$db", '', '', { RaiseError => 1 });
}

sub get_metrics {
    my ($user) = @_;
    # For demo: return empty or last N metrics
    my $dbh = whm_db();
    my $sth = $dbh->prepare('SELECT domain,timestamp,data FROM metrics ORDER BY timestamp DESC LIMIT 50');
    $sth->execute();
    my @out;
    while (my $r = $sth->fetchrow_hashref) {
        push @out, { domain => $r->{domain}, timestamp => $r->{timestamp}, data => decode_json($r->{data}) };
    }
    $dbh->disconnect;
    return { metrics => \@out };
}

1;
