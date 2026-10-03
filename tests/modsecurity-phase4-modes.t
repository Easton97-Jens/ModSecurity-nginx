#!/usr/bin/perl
use warnings; use strict;
use Test::More;
use JSON::PP qw(decode_json);
BEGIN { use FindBin; chdir($FindBin::Bin); }
use lib 'lib';
use Test::Nginx;

# Native off/default late-deny finalization intentionally causes the nginx
# header-already-sent alert. Audit those alerts explicitly below.
my $t = Test::Nginx->new()->has(qw/http/)->todo_alerts();
$t->write_file_expand('nginx.conf', <<'EOC');
%%TEST_GLOBALS%%
daemon off;
events {}
http {
    %%TEST_GLOBALS_HTTP%%
    server {
        listen 127.0.0.1:8080;
        server_name localhost;
        default_type text/plain;
        modsecurity on;
        modsecurity_phase4_log %%TESTDIR%%/phase4.log;
        modsecurity_rules '
            SecRuleEngine On
            SecResponseBodyAccess On
            SecResponseBodyMimeType text/plain
            SecRule RESPONSE_BODY "@rx Hello" "id:910001,phase:4,deny,log,status:403"
        ';
        location /off { modsecurity_phase4_mode off; }
        location /default { }
        location /safe { modsecurity_phase4_mode safe; }
        location /strict { modsecurity_phase4_mode strict; }
    }
}
EOC

for my $mode (qw/off default safe strict/) {
    $t->write_file('/' . $mode, 'Hello ' . $mode);
}
$t->run();
$t->plan(19);

is(http_get('/off'), '', 'off preserves native late-deny failure');
is(http_get('/default'), '', 'off is the default');
like(http_get('/safe'), qr/Hello safe/, 'safe continues after a late rule intervention');
is(http_get('/strict'), '', 'strict aborts after headers are committed');

my $log = $t->read_file('phase4.log');
my @events;
my $valid_json = eval {
    @events = map { decode_json($_) } grep { length $_ } split /\n/, $log;
    1;
};
ok($valid_json, 'every Phase4 event is valid JSON');
diag($@) unless $valid_json;
is(scalar @events, 2, 'off and default off emit no dedicated Phase4 event');
my %event = map { $_->{uri} => $_ } @events;
is($event{'/safe'}->{actual_action}, 'log_only', 'safe action logged');
is($event{'/safe'}->{reason}, 'response_committed_safe', 'safe reason logged');
is($event{'/strict'}->{actual_action}, 'connection_abort', 'strict action logged');
is($event{'/strict'}->{reason}, 'response_committed_strict', 'strict reason logged');
is($event{'/safe'}->{mode}, 'safe', 'safe mode logged');
is($event{'/strict'}->{mode}, 'strict', 'strict mode logged');
ok(@events && !grep({ !$_->{header_sent} } @events), 'header_sent is true for late interventions');
ok(@events && !grep({ $_->{event} ne 'phase4_intervention' } @events), 'event kind is stable');
unlike($log, qr/Hello off|Hello default|Hello safe|Hello strict/, 'response body is absent from Phase4 log');

# Stop first so the explicit alert audit includes all worker output.
$t->stop();
my @alerts = $t->read_file('error.log') =~ /^.*\[alert\].*$/gm;
my $expected_alert = qr/\[alert\].*header already sent\b.*request: "GET \/(?:off|default) HTTP\/1\.[01]"/;
my @late_alerts = grep { /$expected_alert/ } @alerts;
is(scalar @late_alerts, 2, 'native off/default each cause one expected late-finalization alert');
is(scalar(grep { /request: "GET \/off HTTP\/1\.[01]"/ } @late_alerts), 1, 'explicit off has one expected alert');
is(scalar(grep { /request: "GET \/default HTTP\/1\.[01]"/ } @late_alerts), 1, 'default off has one expected alert');
my @unexpected_alerts = grep { !/$expected_alert/ } @alerts;
is(join("\n", @unexpected_alerts), '', 'no unexpected nginx alerts');
