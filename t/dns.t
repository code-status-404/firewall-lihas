use strict;
use warnings;
use Test::More;
use lib 'lib';

use LiHAS::Firewall::DNSUtil qw(
  _normalise_name _valid_ipv4 _interpret_records dns_names_from_rule_line
);

{
  package Local::RR;
  sub new { my ($class, %arg) = @_; return bless \%arg, $class }
  sub name { return $_[0]{name} }
  sub type { return $_[0]{type} }
  sub rdatastr { return $_[0]{data} }
  sub ttl { return $_[0]{ttl} }
}

sub rr { return Local::RR->new(@_) }

is(_normalise_name('WWW.Example.ORG.'), 'www.example.org',
  'host names are canonicalised');
ok(!defined _normalise_name('bad name.example'),
  'invalid host name is rejected');
ok(_valid_ipv4('192.0.2.1'), 'IPv4 address is accepted');
ok(!_valid_ipv4('alias.example.org'), 'CNAME text is not an address');
is_deeply(
  [dns_names_from_rule_line('-A fwd-eth0 -s dns-Client.Example. -d dns-api.example -j ACCEPT')],
  ['api.example', 'client.example'],
  'generated privclients rule exposes source and destination DNS names',
);

my $direct = _interpret_records('a.example', {}, [
  rr(name => 'a.example.', type => 'A', data => '192.0.2.1', ttl => 60),
  rr(name => 'a.example.', type => 'AAAA', data => '2001:db8::1', ttl => 60),
], 8, 5);
is($direct->{state}, 'addresses', 'direct A response is complete');
is_deeply($direct->{addresses}, {'192.0.2.1' => 60}, 'only IPv4 A records survive');

my $cname = _interpret_records('alias.example', {}, [
  rr(name => 'alias.example.', type => 'CNAME', data => 'target.example.', ttl => 30),
  rr(name => 'target.example.', type => 'A', data => '192.0.2.2', ttl => 300),
], 8, 5);
is_deeply($cname->{addresses}, {'192.0.2.2' => 30},
  'CNAME chain resolves to A and uses the shortest TTL');

my $follow = _interpret_records('alias.example', {}, [
  rr(name => 'alias.example.', type => 'CNAME', data => 'target.example.', ttl => 20),
], 8, 5);
is($follow->{state}, 'follow', 'missing terminal A causes a follow-up query');
is($follow->{target}, 'target.example', 'follow-up addresses the CNAME target');

my $ttl_zero = _interpret_records('a.example', {}, [
  rr(name => 'a.example.', type => 'A', data => '192.0.2.3', ttl => 0),
], 8, 5);
is($ttl_zero->{addresses}{'192.0.2.3'}, 5, 'TTL zero is clamped, not treated as deletion');

my $loop = _interpret_records('a.example', {}, [
  rr(name => 'a.example.', type => 'CNAME', data => 'b.example.', ttl => 30),
  rr(name => 'b.example.', type => 'CNAME', data => 'a.example.', ttl => 30),
], 8, 5);
is($loop->{state}, 'error', 'CNAME loop is rejected');

done_testing();
