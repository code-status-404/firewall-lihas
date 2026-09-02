package LiHAS::Firewall::DNSUtil;
use warnings;
use strict;
use Exporter qw(import);
use Socket qw(AF_INET inet_pton);

our @EXPORT_OK = qw(_normalise_name _valid_ipv4 _interpret_records dns_names_from_rule_line);

sub _normalise_name {
  my ($name) = @_;
  return undef if not defined $name;
  $name =~ s/^\s+|\s+$//g;
  $name =~ s/\.$//;
  $name = lc $name;
  return undef if length($name) == 0 or length($name) > 253;
  return undef if $name !~ /\A(?=.{1,253}\z)(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?\.)*[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?\z/;
  return $name;
}

sub _valid_ipv4 {
  my ($address) = @_;
  return defined($address) && defined(inet_pton(AF_INET, $address));
}

sub dns_names_from_rule_line {
  my ($line) = @_;
  my %names;
  while (defined($line) && $line =~ /-[sd]\s+dns-([a-zA-Z0-9_.-]+)/g) {
    my $name = _normalise_name($1);
    $names{$name} = 1 if defined $name;
  }
  return sort keys %names;
}

sub _interpret_records {
  my ($queried, $context, $rr, $max_depth, $ttl_minimum) = @_;
  my (%cnames, %records);
  foreach my $answer (@{$rr}) {
    my $owner = _normalise_name(eval { $answer->name });
    next if not defined $owner;
    if ($answer->type eq 'CNAME') {
      my $target = _normalise_name($answer->rdatastr());
      $cnames{$owner} = [$target, $answer->ttl()] if defined $target;
    } elsif ($answer->type eq 'A') {
      my $ip = $answer->rdatastr();
      $records{$owner}{$ip} = $answer->ttl() if _valid_ipv4($ip);
    }
  }

  my $current = $queried;
  my %visited = map { $_ => 1 } @{$context->{visited} || []};
  my $chain_ttl = $context->{cname_ttl};
  my $depth = scalar keys %visited;
  while (defined $cnames{$current}) {
    return { state => 'error', reason => 'CNAME loop or depth exceeded' }
      if $visited{$current}++ || ++$depth > $max_depth;
    my ($target, $ttl) = @{$cnames{$current}};
    $chain_ttl = $ttl if !defined($chain_ttl) || $ttl < $chain_ttl;
    $current = $target;
  }

  if ($records{$current} && keys %{$records{$current}}) {
    my %addresses;
    foreach my $ip (keys %{$records{$current}}) {
      my $ttl = $records{$current}{$ip};
      $ttl = $chain_ttl if defined($chain_ttl) && $chain_ttl < $ttl;
      $ttl = $ttl_minimum if $ttl < $ttl_minimum;
      $addresses{$ip} = $ttl;
    }
    return { state => 'addresses', addresses => \%addresses };
  }
  return {
    state => 'follow', target => $current, visited => [keys %visited],
    cname_ttl => $chain_ttl,
  } if $current ne $queried;
  return { state => 'empty' };
}

1;
