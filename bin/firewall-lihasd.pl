#!/usr/bin/perl
# Copyright (C) 2011-2014 Adrian Reyer support@lihas.de
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

# Requirements: libxml-application-config-perl liblog-log4perl-perl liblog-dispatch-perl

BEGIN {
  my $DEBUG=0;
  my $DAEMON=1;
	use strict;
	use warnings;
  use Getopt::Long qw(GetOptions);
  Getopt::Long::Configure qw(gnu_getopt);
  use Data::Dumper;
  use Module::Load;
  
  use Log::Log4perl qw(:easy);
  Log::Log4perl::init('/etc/firewall.lihas.d/log4perl.conf');
  if (! Log::Log4perl::initialized()) { WARN "uninit"; } else { INFO "init"; }
  
  INFO "$0 starting\n";
  
  GetOptions(
    'debug|d' => \&DEBUG
  ) or ERROR "Unknown Option\n";
  if ($DEBUG) { $DAEMON=0; }

  if ($DAEMON==1) {
    use Net::Server::Daemonize qw(daemonize check_pid_file unlink_pid_file);    # or any other daemonization module
    daemonize(
      'root',
      'root',
      '/var/run/firewall-lihasd.pid'
    );
  }
}

=head1 NAME

firewall-lihasd
Daemon supporting firewall-lihas by resolving dns-names

=cut

use warnings;
use strict;

$SIG{__WARN__} = sub {
  local $Log::Log4perl::caller_depth =
        $Log::Log4perl::caller_depth + 1;
  WARN @_;
};

sub try_load {
  my $mod = shift;
  eval("use $mod");
  if ($@) {
    #print "\$@ = $@\n";
    return(0);
  } else {
    return(1);
  }
}

use Module::Load::Conditional qw[check_install];
$Module::Load::Conditional::VERBOSE = 1;

use XML::Application::Config;
use POE qw(Component::Client::Ping Component::Client::DNS );
# use Test::More skip_all => "Derzeit keine Tests";
use lib "/etc/firewall.lihas.d/lib";
my $module = 'POE::Component::Server::HTTP';
my $have_httpd=0;
my $rv = check_install(module => 'POE::Component::Server::HTTP');
if ( not defined($rv) ) {
  $have_httpd = 0;
} else {
  $have_httpd = 1;
  Module::Load->load('POE::Component::Server::HTTP');
}
use HTTP::Status qw(:constants);
use LiHAS::Firewall::Ping;
use LiHAS::Firewall::DNS;
use LiHAS::Firewall::DNSUtil qw(_normalise_name dns_names_from_rule_line);
use URI::Escape qw(uri_escape);
use Fcntl qw(:flock);
my %feature;
use DBI;

my $cfg = new XML::Application::Config("LiHAS-Firewall","/etc/firewall.lihas.d/config.xml");
if (defined $cfg->find('feature/connectivity/@enabled') && ( $cfg->find('feature/connectivity/@enabled') !~ /^(|0)$/)) {
  eval { require LiHAS::Firewall::Connectivity }; if ($@) { WARN "No connectivity test support: $@"; $feature{'connectivity'}=0; } else { $feature{'connectivity'}=1; }
} else { $feature{'connectivity'}=0; }

if ($cfg->find('feature/portal/@enabled') !~ /^(|0)$/ ) {
  if ($have_httpd) {
    eval { require LiHAS::Firewall::Portal }; if ($@) { WARN "No portal support: $@"; $feature{'portal'}=0; } else { $feature{'portal'}=1; }
  } else {
    WARN "Portal support wanted, but POE::Component::Server::HTTP not available";
    WARN 'Either install POE::Component::Server::HTTP or disable portal support with feature/portal/@enabled=0 in config.xml';
  }
} else { $feature{'portal'}=0; }

=head1 Functions

=cut
#=head2 firewall_reload_ipsec
#
#Reloads the ipsec.secrets with current IPs from database
#=cut
#sub firewall_reload_ipsec {
#  my ($kernel, $session, $heap) = @_[KERNEL, SESSION, HEAP];
#  my $ipsecsecretssource;
#  if ( -r $heap->{configpath}."/feature/ipsec/ipsec.secrets.dns"; ) {
#    if ( ! open($ipsecsecretssource, $heap->{configpath}."/feature/ipsec/ipsec.secrets.dns")) {
#      $logger->fatal("cannot open < ".$heap->{configpath}."/feature/ipsec/ipsec.secrets.dns: $!");
#    } else {
#      if ( ! open() ) {
#      } else {
#        if ( ! open($ipsecsecretsdest, $cfg->find('/applicationconfig/application/feature/ipsec/secretsfile')) {
#          $logger->fatal("cannot open > ".$cfg->find('/applicationconfig/application/feature/ipsec/secretsfile').": $!");
#        } else {
#          foreach my $line (<$ipsecsecretssource>) {
#            chop $line;
#            $line =~ m/^#/ && next;
#            $line =~ m/^[ \t]*$/ && next;
#            if ( $line =~ m/^([\S]*)[\s]+([\S]*)[\s]+:[\s]+PSK[\s]+([\S]*)(.*)$/ ) {
#            }
#          }
#        }
#      }
#      close($ipsecsecretssource);
#    }
#  }
#}

=head2 expand_dns

Expands dns-* to the corresponding IPs from DB
=cut
sub expand_dns {
  my ($arg_ref) = @_;
  my $line = $arg_ref->{line};
  my $depth = $arg_ref->{depth};
  my %replacedns = %{$arg_ref->{replacedns}};
  my %replacehostcount = %{$arg_ref->{replacehostcount}};
  my $outline = "";

  $line =~ s/-A (in|out|fwd|post|pre)/-A dns-$1/;
  if ( $line =~ m/([sd][ \t]+)dns-([a-zA-Z0-9_\.-]+)\b/ ) {
    my $name = $2;
    if ( not defined $replacedns{$name}{count} ) {
      WARN "expand_dns: dns-$name unresolved, skipping line $line";
      return "";
    }
    foreach my $ip (values(@{$replacedns{$name}{ips}})) {
      my $thisline = $line;
      $thisline =~ s/([sd][ \t]+)dns-$name/$1$ip/;
      $outline .= expand_dns({line=>$thisline, replacehostcount=>\%replacehostcount, replacedns=>\%replacedns, depth=>$depth+1});
		}
    return $outline;
  } else {
    return $line;
  }
}
=head2 firewall_reload_dns

Reloads the iptables dns-* chains with current IPs from database
=cut
sub firewall_reload_dns {
  my ($kernel, $session, $heap) = @_[KERNEL, SESSION, HEAP];
  my %replacedns;
  my %replacehostcount;
  my ($hostname, $ip, $table);
  my ($dh, $fh);
  my $logger = Log::Log4perl->get_logger('firewalld.reload.dns');
  if (! Log::Log4perl::initialized()) { $logger->warn("uninit"); }
  return if not $heap->{dns_active};

  open(my $lock, '>>', $heap->{datapath}.'/dns-reload.lock')
    or do { $logger->error("cannot open DNS reload lock: $!"); $kernel->delay('firewall_reload_dns', 30); return; };
  flock($lock, LOCK_EX)
    or do { $logger->error("cannot lock DNS reload: $!"); $kernel->delay('firewall_reload_dns', 30); return; };

  my $iptcmd="";

  my $sql = "UPDATE vars_num SET value=? WHERE name=?";
  my $sth = $heap->{dbh}->prepare("$sql");
  $sth->execute(0,'fw_reload_dns');

  $sql = "SELECT hostname, ip FROM hostnames_current";
  $sth = $heap->{dbh}->prepare("$sql");
  $sth->execute();
  $sth->bind_columns(\$hostname, \$ip);
  while ($sth->fetch()) {
    push(@{$replacedns{$hostname}{ips}}, "$ip");
    $replacedns{$hostname}{count}+=1;
  }
  if ( ! opendir($dh, $heap->{datapath}) ) { $logger->fatal("can't opendir ".$heap->{datapath}.": $!\n"); exit 1; };
	my @dnsfiles = grep { /^dns-/ && -f $heap->{datapath}."/$_" } readdir($dh);
  closedir $dh;
  my %allchains;
	my $ruleset = "";
  open(my $fhiptsave, '-|', '/usr/sbin/iptables-save')
    or do { $logger->error("cannot start iptables-save: $!"); $kernel->delay('firewall_reload_dns', 30); return; };
  foreach my $iptsaveline (<$fhiptsave>) {
    if ( $iptsaveline =~ m/^.. dns-/ ) {
			next;
    } elsif ( $iptsaveline =~ m/^\*([^ \t\n\r]*)/ ) {
      $table=$1;
    } elsif ( $iptsaveline =~ m/^:([^ \t\n\r]*)/ ) {
      $allchains{$table}{$1} = 1;
    } elsif ( $iptsaveline =~ m/^COMMIT/ ) {
			# Add DNS-dependent rules here
			foreach my $file (grep { /^dns-$table$/ } @dnsfiles) {
  		  if ( ! open($fh, "<", $heap->{datapath}."/$file")) { $logger->fatal("cannot open < ".$heap->{datapath}."/$file: $!"); exit 1};
  		  foreach my $line (<$fh>) {
  		    my $expandline = expand_dns({line=>$line, replacehostcount=>\%replacehostcount, replacedns=>\%replacedns, depth=>0});
					if (not defined $expandline) {
						WARN "unresolveable: line=>$line";
					}
					$ruleset .= $expandline;
  		  }
  		  close($fh);
  		}
    }
		$ruleset .= $iptsaveline;
  }
  if (!close($fhiptsave)) {
    $logger->error("iptables-save failed: $?");
    $kernel->delay('firewall_reload_dns', 30);
    return;
  }
	DEBUG "/usr/sbin/iptables-restore start";
  open(my $fhipttest, '|-', '/usr/sbin/iptables-restore', '--test')
    or do { $logger->error("cannot test DNS ruleset: $!"); $kernel->delay('firewall_reload_dns', 30); return; };
	print $fhipttest $ruleset;
  if (!close($fhipttest)) {
    $logger->error("DNS ruleset validation failed; active firewall was not changed");
    $kernel->delay('firewall_reload_dns', 30);
    return;
  }
  open(my $fhiptrestore, '|-', '/usr/sbin/iptables-restore')
    or do { $logger->error("cannot start iptables-restore: $!"); $kernel->delay('firewall_reload_dns', 30); return; };
	print $fhiptrestore $ruleset;
  if (!close($fhiptrestore)) {
    $logger->error("iptables-restore failed: $?");
    $kernel->delay('firewall_reload_dns', 30);
    return;
  }
	$heap->{dns_reload_pending} = 0;
	DEBUG "/usr/sbin/iptables-restore end";
}

=head2 firewall_find_dnsnames

Collects names from generated dns-* rules, hostgroups and explicit config.xml
entries.  Reading the generated rules is what permits dns-* directly in
privclients and other supported rule sources.

=cut
sub firewall_find_dnsnames {
  my ($kernel, $session, $heap) = @_[KERNEL, SESSION, HEAP];
  return if not $heap->{dns_active};
  my %names;

  # Generated dns-* files are the authoritative source.  They also contain
  # names used directly in privclients, nolog, reject and included files.
  if (opendir(my $dh, $heap->{datapath})) {
    my @files = grep { /^dns-(?:raw|filter|mangle|nat)$/ && -f $heap->{datapath}."/$_" } readdir($dh);
    closedir($dh);
    foreach my $file (@files) {
      open(my $fh, '<', $heap->{datapath}."/$file") or do { WARN "cannot read $file: $!"; next; };
      while (my $line = <$fh>) {
        $names{$_} = 1 foreach dns_names_from_rule_line($line);
      }
      close($fh);
    }
  } else {
    WARN "cannot scan $heap->{datapath} for DNS rules: $!";
  }

  # Keep hostgroups as a compatibility source, including names not currently
  # referenced by a generated rule.
  my $groups = $heap->{configpath}."/groups";
  if (opendir(my $dh, $groups)) {
    my @files = grep { /^hostgroup-/ && -f "$groups/$_" } readdir($dh);
    closedir($dh);
    foreach my $file (@files) {
      open(my $fh, '<', "$groups/$file") or do { WARN "cannot read $groups/$file: $!"; next; };
      while (my $line = <$fh>) {
        $line =~ s/#.*$//;
        chomp($line);
        next if $line !~ /^\s*dns-([^\s]+)\s*$/;
        my $name = _normalise_name($1);
        $names{$name} = 1 if defined $name;
      }
      close($fh);
    }
  }

  # Explicit config entries are useful for pre-warming or external consumers.
  eval {
    my $xml = XML::XPath->new(filename => '/etc/firewall.lihas.d/config.xml');
    foreach my $node ($xml->findnodes('/applicationconfig/application/dns/host/@name')) {
      my $name = _normalise_name($node->getNodeValue());
      $names{$name} = 1 if defined $name;
    }
  };
  WARN "cannot read explicit DNS hosts from config.xml: $@" if $@;

  my $dbh = $heap->{dbh};
  my $changed = 0;
  eval {
    $dbh->begin_work;
    $dbh->do('DELETE FROM hostnames');
    my $insert = $dbh->prepare('INSERT OR IGNORE INTO hostnames (hostname) VALUES (?)');
    $insert->execute($_) foreach sort keys %names;
    my $delete = $dbh->prepare('DELETE FROM hostnames_current WHERE hostname NOT IN (SELECT hostname FROM hostnames)');
    $delete->execute();
    $changed = $delete->rows > 0;
    $dbh->commit;
    1;
  } or do {
    my $error = $@ || 'unknown database error';
    eval { $dbh->rollback };
    ERROR "cannot update configured DNS names: $error";
  };
  LiHAS::Firewall::DNS::_schedule_reload($kernel, $heap) if $changed;

  my $sth = $dbh->prepare('SELECT hostname FROM hostnames WHERE hostname NOT IN (SELECT hostname FROM hostnames_current)');
  $sth->execute();
  while (my ($hostname) = $sth->fetchrow_array()) {
    $kernel->yield('dns_query', 'A', $hostname);
  }
  $kernel->delay('firewall_find_dnsnames', $heap->{refresh_dns_config});
}

=head2 firewall_create_db

Setup the db according to the config.xml
TODO: Unify with firewall-lihas.pl

=cut
sub firewall_create_db {
  my ($kernel, $heap) = @_[KERNEL, HEAP];
  foreach my $sql (split(/;/,$cfg->find('database/create'))) {
    if ( defined $sql ) {
      chomp $sql;
      $sql =~ s/\n//g;
      $heap->{dbh}->do("$sql");
    }
  }
}


use POE::Component::Server::TCP;
use XML::XPath;


sub session_default {
  my ($event, $args) = @_[ARG0, ARG1];
  ERROR( "Session ", $_[SESSION]->ID, " caught unhandled event $event with (".$$args[0].").\n");
}

=head2 
manage_server
paste xml-like stuff:
<application name="LiHAS-Firewall"><manage><feature><portal><cmd name="reload">reload</cmd></portal></feature></manage></application>
=cut

sub manage_server {
  POE::Component::Server::TCP->new(
    Address => '127.0.0.1',
    Port => 83,
    ClientConnected => sub {
      $_[HEAP]{client}->put("<application name=\"LiHAS-Firewall\"></application>");
      if (! Log::Log4perl::initialized()) { WARN "uninit"; } else { WARN "init"; }
    },

    ClientInput => sub {
      my ($sender, $kernel, $client_input) = @_[SESSION, KERNEL, ARG0];
      $kernel->post(firewalld => manage_server_got_line => $sender->postback('client_output'), $client_input);
    },

    InlineStates => {
      client_output => sub {
        my ($heap, $response) = @_[HEAP, ARG1];
        $heap->{client}->put($response->[0]) if defined $heap->{client};
            # that is, if $heap->{client} is still connected
        $_[KERNEL]->yield("shutdown");
      },
    },
  );
}

=head2
session_start
=cut
sub session_start {
  my ($kernel, $heap) = @_[KERNEL, HEAP];
  $heap->{dbh} = DBI->connect(
    $cfg->find('database/dbd/@connectorstring'), undef, undef,
    { RaiseError => 1, PrintError => 0, AutoCommit => 1 }
  );
  $heap->{datapath} = $cfg->find('config/@db_dbd');
  $heap->{configpath} = $cfg->find('config/@path');
  $heap->{portalname} = $cfg->find('/applicationconfig/application/feature/portal/name');

  firewall_create_db(@_);
  # fw dns-rules need a reload for initially

  $kernel->alias_set('firewalld');

  my $sql = "DELETE FROM vars_num WHERE name=?";
  my $sth = $heap->{dbh}->prepare($sql);
  $sth->execute('fw_reload_dns');
  $sql = "INSERT INTO vars_num (name, value) VALUES (?,?)";
  $sth = $heap->{dbh}->prepare($sql);
  $sth->execute('fw_reload_dns', 1);

  $heap->{refresh_dns_config} = $cfg->find('dns/@refresh_dns_config');
  $heap->{refresh_dns_minimum} = $cfg->find('dns/@refresh_dns_minimum');
  $heap->{dns_active} = $cfg->find('dns/@active') !~ /^(?:|0)$/;
  $heap->{dns_ttl_minimum} = $cfg->find('dns/@ttl_minimum') || 5;
  $heap->{dns_max_stale} = $cfg->find('dns/@max_stale') || 3600;
  $heap->{dns_retry_maximum} = $cfg->find('dns/@retry_maximum') || 300;
  $heap->{dns_cname_max_depth} = $cfg->find('dns/@cname_max_depth') || 8;
  $heap->{feature_portal} = $cfg->find('feature/portal/@enabled');
  $kernel->yield('timer_ping');
  $kernel->yield('firewall_find_dnsnames') if $heap->{dns_active};
  if ($feature{'portal'}!=0) {
    $kernel->yield('portal_init');
    $kernel->yield('portal_ipset_init');
  }
  $kernel->yield('dns_update') if $heap->{dns_active};
  $kernel->yield('firewall_reload_dns') if $heap->{dns_active};
  manage_server();
  return 0;
}

sub session_stop {
  my ($kernel, $heap) = @_[KERNEL, HEAP];
  $heap->{dbh}->disconnect;
  return 0;
}

our $mainsession = POE::Session->create(
  inline_states => {
    _start => \&session_start,
    _stop => \&session_stop,
    _default => \&session_default,
    timer_ping => \&LiHAS::Firewall::Ping::timer_ping,
    ping_client_start => \&LiHAS::Firewall::Ping::ping_client_start,
    client_send_ping => \&LiHAS::Firewall::Ping::client_send_ping,
    client_got_pong => \&LiHAS::Firewall::Ping::client_got_pong,
    dns_update => \&LiHAS::Firewall::DNS::dns_update,
    dns_query => \&LiHAS::Firewall::DNS::dns_query,
    dns_response => \&LiHAS::Firewall::DNS::dns_response,
    portal_init => \&LiHAS::Firewall::Portal::portal_init,
    portal_ipset_init => \&LiHAS::Firewall::Portal::portal_ipset_init,
    firewall_find_dnsnames => \&firewall_find_dnsnames,
    firewall_reload_dns => \&firewall_reload_dns,
    manage_server_got_line => sub {
      my ($kernel, $heap, $postback, $client_input) = @_[KERNEL, HEAP, ARG0 .. $#_];
      # stash the postback on the heap
      $heap->{postback} = $postback;
      $kernel->yield(manage_server_eval_line => $client_input);
    },
    manage_server_eval_line => sub {
      my ($heap, $client_input) = @_[HEAP, ARG0 .. $#_];
      my $postback = $heap->{postback};
      my $client_output;

      my $request = XML::XPath->new(xml => $client_input);
      my $cmd="";
#      foreach my $cmd ( $request->findvalue('//cmd[@name]') ) {
#        if ( $cmd =~ /^reload$/ ) {
#    $_[KERNEL]->yield('portal_ipset_init');
    $client_output="<application name=\"LiHAS-Firewall\"><response>$cmd started</response></application>";
#  } else {
#    $client_output="<application name=\"LiHAS-Firewall\"><response>Unknown command $cmd</response></application>";
#        };
#      }
      $_[KERNEL]->yield('portal_ipset_init');
      $postback->($client_output);
    },
  }
)->ID;

if ($have_httpd) {
  WARN "http_redirector pre";
  my $aliases = POE::Component::Server::HTTP->new(
    Port => 81,
    ContentHandler => {
      '/' => \&handler1,
    },
    Headers => { Server => 'Portal Redirection Server' },
  );
  sub handler1 {
      my ($request, $response) = @_;
      $response->code(HTTP_TEMPORARY_REDIRECT);
      $response->header(
        Location => "http://portalserver.lan:82/cgi-bin/portal-cgi.pl?redirect_url=".uri_escape($request->header('Server')."/".$request->uri),
        Expires => "Sat, 01 Jan 2000 00:00:00 GMT",
        );
      return 0;
  }
  #POE::Kernel->call($aliases->{httpd}, "shutdown");
  #POE::Kernel->call($aliases->{tcp}, "shutdown");
}

POE::Kernel->run();
exit 0;
# vim: ts=2 sw=2 sts=2 sr noet
