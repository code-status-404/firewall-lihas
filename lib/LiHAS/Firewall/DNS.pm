package LiHAS::Firewall::DNS;
use warnings;
use strict;
use POE;
use Log::Log4perl qw(:easy);
use LiHAS::Firewall::DNSUtil qw(_normalise_name _interpret_records);

my $named = POE::Component::Client::DNS->spawn(Alias => "named");

sub _schedule_reload {
  my ($kernel, $heap) = @_;
  $heap->{dns_reload_pending} = 1;
  $kernel->delay('firewall_reload_dns', 10);
}

sub _apply_result {
  my ($kernel, $heap, $host, $addresses) = @_;
  my $dbh = $heap->{dbh};
  my ($configured) = $dbh->selectrow_array(
    'SELECT 1 FROM hostnames WHERE hostname=?', undef, $host
  );
  return 0 if not $configured;
  my %old;
  my $select = $dbh->prepare('SELECT ip, time_first, time_valid_till FROM hostnames_current WHERE hostname=?');
  $select->execute($host);
  while (my ($ip, $first, $valid_till) = $select->fetchrow_array()) {
    $old{$ip} = { first => $first, valid_till => $valid_till };
  }

  my %new = map { $_ => 1 } keys %{$addresses};
  my $changed = join("\0", sort keys %old) ne join("\0", sort keys %new);
  my $now = time();

  eval {
    $dbh->begin_work;
    my $insert = $dbh->prepare('INSERT INTO hostnames_current (hostname,time_first,time_valid_till,ip) VALUES (?,?,?,?)');
    my $update = $dbh->prepare('UPDATE hostnames_current SET time_valid_till=? WHERE hostname=? AND ip=?');
    my $history = $dbh->prepare('INSERT INTO dnshistory (hostname,time_first,time_valid_till,ip,active) VALUES (?,?,?,?,0)');
    my $delete = $dbh->prepare('DELETE FROM hostnames_current WHERE hostname=? AND ip=?');
    foreach my $ip (keys %old) {
      next if exists $new{$ip};
      $history->execute($host, $old{$ip}{first}, $old{$ip}{valid_till}, $ip);
      $delete->execute($host, $ip);
    }
    foreach my $ip (keys %new) {
      my $ttl = $addresses->{$ip};
      if (exists $old{$ip}) {
        $update->execute($now + $ttl, $host, $ip);
      } else {
        $insert->execute($host, $now, $now + $ttl, $ip);
      }
    }
    $dbh->commit;
    1;
  } or do {
    my $error = $@ || 'unknown database error';
    eval { $dbh->rollback };
    ERROR "DNS update for $host failed: $error";
    return 0;
  };

  delete $heap->{dns_failures}{$host};
  delete $heap->{dns_next_retry}{$host};
  if ($changed) {
    INFO "DNS $host changed to: ".join(', ', sort keys %new);
    _schedule_reload($kernel, $heap);
  } else {
    DEBUG "DNS $host unchanged: ".join(', ', sort keys %new);
  }
  return 1;
}

sub _temporary_failure {
  my ($kernel, $heap, $host, $reason) = @_;
  my $failures = ++$heap->{dns_failures}{$host};
  my $base = $heap->{refresh_dns_minimum} || 30;
  my $power = $failures > 5 ? 5 : $failures - 1;
  my $delay = $base * (2 ** $power);
  $delay = $heap->{dns_retry_maximum} if $delay > $heap->{dns_retry_maximum};
  $heap->{dns_next_retry}{$host} = time() + $delay;
  WARN "DNS lookup for $host failed ($reason), retry in ${delay}s";

  # Resolver failures keep the last answer for a bounded grace period.
  my $cutoff = time() - $heap->{dns_max_stale};
  my $sth = $heap->{dbh}->prepare('DELETE FROM hostnames_current WHERE hostname=? AND time_valid_till<?');
  $sth->execute($host, $cutoff);
  _schedule_reload($kernel, $heap) if $sth->rows > 0;
}

sub dns_query {
  my ($kernel, $heap, $type, $name, $context) = @_[KERNEL, HEAP, ARG0, ARG1, ARG2];
  $name = _normalise_name($name);
  return if not defined $name;
  $context ||= { original_host => $name, visited => [], cname_ttl => undef };
  my $original = $context->{original_host} || $name;
  return if ($heap->{dns_next_retry}{$original} || 0) > time();
  my $query_key = $original."\0".$name;
  return if $heap->{dns_query_in_flight}{$query_key};
  $heap->{dns_query_in_flight}{$query_key} = 1;
  my $response = $named->resolve(
    event => 'dns_response', host => $name, type => $type,
    context => $context, timeout => 20,
  );
  $kernel->yield(dns_response => $response) if $response;
}

sub dns_update {
  my ($kernel, $heap) = @_[KERNEL, HEAP];
  my $lookahead = $heap->{refresh_dns_minimum};
  my $sth = $heap->{dbh}->prepare('SELECT DISTINCT hostname FROM hostnames_current WHERE time_valid_till<=?');
  $sth->execute(time() + $lookahead);
  while (my ($hostname) = $sth->fetchrow_array()) {
    $kernel->yield('dns_query', 'A', $hostname);
  }
  $kernel->delay('dns_update', $lookahead);
}

sub dns_response {
  my ($kernel, $heap, $response) = @_[KERNEL, HEAP, ARG0];
  my $queried = _normalise_name($response->{host});
  my $context = $response->{context} || {};
  my $original = _normalise_name($context->{original_host} || $queried);
  return if not defined $original;
  delete $heap->{dns_query_in_flight}{$original."\0".$queried} if defined $queried;

  if (not defined $response->{response}) {
    _temporary_failure($kernel, $heap, $original, 'timeout/no response');
    return;
  }
  my $packet = $response->{response};
  my $rcode = eval { $packet->header->rcode } || 'UNKNOWN';
  if ($rcode ne 'NOERROR') {
    if ($rcode eq 'NXDOMAIN') {
      WARN "DNS $original does not exist (NXDOMAIN)";
      _apply_result($kernel, $heap, $original, {});
    } else {
      _temporary_failure($kernel, $heap, $original, $rcode);
    }
    return;
  }

  my @rr = $packet->answer();
  push @rr, $packet->additional();
  my $result = _interpret_records(
    $queried, $context, \@rr, $heap->{dns_cname_max_depth}, $heap->{dns_ttl_minimum}
  );
  if ($result->{state} eq 'addresses') {
    _apply_result($kernel, $heap, $original, $result->{addresses});
  } elsif ($result->{state} eq 'follow') {
    DEBUG "DNS CNAME continuation $queried -> $result->{target}";
    $kernel->yield('dns_query', 'A', $result->{target}, {
      original_host => $original, visited => $result->{visited},
      cname_ttl => $result->{cname_ttl},
    });
  } elsif ($result->{state} eq 'error') {
    _temporary_failure($kernel, $heap, $original, $result->{reason});
  } else {
    WARN "DNS $original returned no A record";
    _apply_result($kernel, $heap, $original, {});
  }
}

1;
