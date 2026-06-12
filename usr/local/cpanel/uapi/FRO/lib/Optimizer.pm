package Optimizer;

use strict;
use warnings;
use DBI;
use JSON;

sub get_recommendations {
    my ($user) = @_;
    # Simple recommendation engine using recent metrics from whm.db
    my $db = '/var/cpanel/fro/whm.db';
    my $dbh = DBI->connect("dbi:SQLite:dbname=$db", '', '', { RaiseError => 1 });
    my $sth = $dbh->prepare('SELECT domain,timestamp,data FROM metrics ORDER BY timestamp DESC LIMIT 100');
    $sth->execute();
    # Aggregate by domain
    my %agg;
    while (my $r = $sth->fetchrow_hashref) {
        my $dom = $r->{domain};
        my $d = eval { decode_json($r->{data}) } || {};
        $agg{$dom} ||= { peaks => 0, samples => 0, peak_active => 0, avg_response => 0 };
        $agg{$dom}->{samples}++;
        $agg{$dom}->{peak_active} = $d->{active_processes} if ($d->{active_processes} // 0) > $agg{$dom}->{peak_active};
        $agg{$dom}->{avg_response} += ($d->{avg_response_time_ms} // 0);
    }
    my @recs;
    for my $dom (keys %agg) {
        my $g = $agg{$dom};
        my $avg_resp = $g->{samples} ? $g->{avg_response}/$g->{samples} : 0;
        # pm.max_children suggestion: peak_active * 1.2 rounded
        my $suggest = int(($g->{peak_active} * 1.2) + 0.5) || 2;
        push @recs, { domain => $dom, suggestion => { 'pm' => 'dynamic', 'pm.max_children' => $suggest }, summary => "Suggest pm.max_children=$suggest based on 7-day peak" };
    }
    $dbh->disconnect;
    return { recommendations => \@recs, summary => 'Recommendations generated' };
}

1;
