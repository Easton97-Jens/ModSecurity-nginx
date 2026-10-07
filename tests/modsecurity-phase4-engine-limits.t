#!/usr/bin/perl
use warnings; use strict;
use Test::More;
use JSON::PP qw(decode_json);
BEGIN { use FindBin; chdir($FindBin::Bin); }
use lib 'lib';
use Test::Nginx;

# Exercise libModSecurity's real append result and queued intervention. The
# static file exceeds the connector's file-reading chunk size; its legacy
# limit is deliberately smaller than the engine's inspection limit.
my $t = Test::Nginx->new()->has(qw/http/)->todo_alerts();
my $prefix = 'ENGINE_PREFIX_' . ('A' x 50); # exactly 64 bytes
my $body = $prefix . ('B' x 70000) . 'ENGINE_TAIL_MARKER';
my $locations = '';
my $rule_id = 950000;

for my $action (qw/partial reject/) {
    my $engine_action = $action eq 'partial' ? 'ProcessPartial' : 'Reject';
    for my $mode (qw/off safe strict/) {
        my $prefix_id = ++$rule_id;
        my $tail_id = ++$rule_id;
        $locations .= <<EOC;
        location = /$action-$mode {
            modsecurity_phase4_mode $mode;
            # Clear and add in separate loads so the engine merges sequentially.
            modsecurity_rules 'SecResponseBodyMimeTypesClear';
            modsecurity_rules '
                SecRuleEngine On
                SecResponseBodyAccess On
                SecResponseBodyMimeType text/plain
                SecResponseBodyLimit 64
                SecResponseBodyLimitAction $engine_action
                SecRule RESPONSE_BODY "\@streq $prefix" "id:$prefix_id,phase:4,pass,log,msg:engine-prefix-exact64-$action-$mode"
                SecRule RESPONSE_BODY "\@contains ENGINE_TAIL_MARKER" "id:$tail_id,phase:4,pass,log,msg:engine-tail-seen-$action-$mode"
            ';
        }
EOC
        $t->write_file('/' . $action . '-' . $mode, $body);
    }
}

$t->write_file_expand('nginx.conf', <<EOC);
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
        modsecurity_phase4_body_limit 1;
        modsecurity_phase4_log %%TESTDIR%%/phase4-engine-limits.log;
$locations
    }
}
EOC

$t->run();
$t->plan(37);

for my $mode (qw/off safe strict/) {
    my $response = http_get('/partial-' . $mode);
    like($response, qr/^HTTP\/1\.1 200 OK/, "$mode accepts engine ProcessPartial");
    my ($headers, $payload) = split /\x0d\x0a\x0d\x0a/, $response, 2;
    is($payload, $body, "$mode ProcessPartial forwards the entire static file");
}

# Static response headers have already passed the header filter when the
# engine queues its body-limit 403. Preserve each existing late-deny policy.
is(http_get('/reject-off'), '', 'off preserves native late engine Reject abort');
my $safe_response = http_get('/reject-safe');
like($safe_response, qr/^HTTP\/1\.1 200 OK/, 'safe continues after engine Reject');
my ($safe_headers, $safe_payload) = split /\x0d\x0a\x0d\x0a/, $safe_response, 2;
is($safe_payload, $body, 'safe engine Reject forwards the complete static file');
is(http_get('/reject-strict'), '', 'strict aborts after engine Reject');

$t->stop();
my $log = $t->read_file('phase4-engine-limits.log');
my @events;
my $valid_json = eval {
    @events = map { decode_json($_) } grep { length $_ } split /\n/, $log;
    1;
};
ok($valid_json, 'every engine-limit Phase4 event is valid JSON');
diag($@) unless $valid_json;
is(scalar @events, 2, 'only safe and strict engine Reject emit dedicated events');
my %event = map { $_->{uri} => $_ } @events;
ok(!grep({ $_->{uri} =~ m{^/partial-} } @events), 'ProcessPartial emits no intervention event in any mode');
ok(!exists $event{'/reject-off'}, 'off engine Reject emits no dedicated event');

for my $mode (qw/safe strict/) {
    my $item = $event{'/reject-' . $mode} || {};
    is($item->{event}, 'phase4_intervention', "$mode engine Reject event kind");
    is($item->{mode}, $mode, "$mode engine Reject retains the selected mode");
    is($item->{waf_status}, 403, "$mode retains the engine's body-limit 403");
    is($item->{wanted_action}, 'deny', "$mode retains the engine's deny decision");
    is($item->{actual_action}, $mode eq 'safe' ? 'log_only' : 'connection_abort',
        "$mode applies the existing late-intervention action");
    is($item->{reason}, 'response_committed_' . $mode, "$mode records the existing late-intervention reason");
    ok($item->{header_sent}, "$mode engine Reject occurs after response headers are committed");
}
unlike($log, qr/ENGINE_PREFIX_|B{100,}|ENGINE_TAIL_MARKER/,
    'raw Phase4 event log contains no response bytes');

my $error_log = $t->read_file('error.log');
for my $mode (qw/off safe strict/) {
    is(scalar(() = $error_log =~ /engine-prefix-exact64-partial-\Q$mode\E/g), 1,
        "$mode engine RESPONSE_BODY is exactly the first 64 bytes");
}
unlike($error_log, qr/engine-tail-seen-/, 'engine inspection excludes the tail in every mode');
unlike($error_log, qr/engine-prefix-exact64-reject-/,
    'engine Reject does not expose a partial inspection prefix');
unlike($error_log, qr/response body inspection append failed/,
    'the engine Reject append result is not mistaken for an API failure');

# Native off finalization has the same expected alert as other late denials.
my @alerts = $error_log =~ /^.*\[alert\].*$/gm;
my $expected_alert = qr/\[alert\].*header already sent\b.*request: "GET \/reject-off HTTP\/1\.[01]"/;
is(scalar(grep { /$expected_alert/ } @alerts), 1, 'off engine Reject has one expected late-finalization alert');
is(join("\n", grep { !/$expected_alert/ } @alerts), '', 'no unexpected nginx alerts');
