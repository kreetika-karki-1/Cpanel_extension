package FRO;

use strict;
use warnings;
use lib '/usr/local/cpanel/uapi/FRO/lib';
use Alerts;
use Metrics;
use Optimizer;

sub list_alerts {
    my ($args) = @_;
    # args: user
    my $user = $args->{user} || '';
    my $alerts = Alerts::list_alerts($user);
    return { status => 1, data => $alerts };
}

sub approve_alert {
    my ($args) = @_;
    my $user = $args->{user};
    my $path = $args->{path};
    my $res = Alerts::approve_alert($user, $path);
    return { status => $res ? 1 : 0 };
}

sub quarantine_file {
    my ($args) = @_;
    my $user = $args->{user};
    my $path = $args->{path};
    my $res = Alerts::quarantine($user, $path);
    return { status => $res ? 1 : 0 };
}

sub get_metrics {
    my ($args) = @_;
    return Metrics::get_metrics($args->{user});
}

sub get_recommendations {
    my ($args) = @_;
    return Optimizer::get_recommendations($args->{user});
}

1;
