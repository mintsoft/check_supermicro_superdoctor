#!/usr/bin/perl
use strict;
use warnings;

use Nagios::Plugin;
use Net::SNMP;

my $np = Nagios::Plugin->new(
    usage => "Usage: %s -H|--host=<hostname> -P|--protocol=<snmpversion> -c|--community=<communitystring> [-t|--timeout=<timeout>]\n",
    plugin => $0,
    shortname => 'check_supermicro_superdoctor',
    blurb => 'Checks SuperDoctor via SNMP for basic issues',
    timeout => 10
);
$np->add_arg(
    spec => 'host|H=s',
    help => '-H --host=STRING hostname running superdoctor and SNMP',
    required => 1
);
$np->add_arg(
    spec => 'protocol|P=i',
    help => '-p --protocol=INTEGER SNMP version (1,2,3)',
    required => 1,
    default => "2"
);
$np->add_arg(
    spec => 'community|c=s',
    help => '-c --community=STRING community string',
    required => 1
);

$np->getopts;

my $community = $np->opts->community;
my $hostname = $np->opts->host;
my $version = $np->opts->protocol;

my $systemTree=".1.3.6.1.4.1.10876.2.1.1.1.1";
my $systemColumns = {
    "2" => "Name",
    "4" => "Value",
    "9" => "Divisor",
    "10" => "Monitored",
    "11" => "Unit",
    "12" => "Status"
};

my $RAMTree=".1.3.6.1.4.1.10876.100.1.3.1";
my $RAMColumns = {
    "1" => "Tag",
    "3" => "Status",
    "4" => "Bank",
    "5" => "Location",
    "8" => "Manufacturer",
    "9" => "PartNo",
    "10" => "SerialNo",
    "11" => "Capacity",
    "15" => "Errors",
    "16" => "ECCErrors",
    "17" => "UECCErrors"
};

my @criticals = ();
my @warnings = ();

my ($session, $error) = Net::SNMP->session(
    -community  =>  $community,
    -hostname   =>  $hostname,
    -version    =>  $version,
    -timeout    =>  10,
);

my $systemHealth = getHashFromSNMP($session, $systemTree, $systemColumns);
my $RAMHealth = getHashFromSNMP($session, $RAMTree, $RAMColumns);

$session->close();

for my $RAM (@{$RAMHealth}) {
    push @criticals, "RAM Errors (Status: $RAM->{'Status'}, Errors: $RAM->{'Errors'}, Correctable: $RAM->{'ECCErrors'}, Uncorrectable: $RAM->{'UECCErrors'}) on $RAM->{'Location'}/$RAM->{'Tag'} ($RAM->{'Manufacturer'}, $RAM->{'PartNo'}, Serial: $RAM->{'SerialNo'})"
        if($RAM->{'Status'} > 0 or $RAM->{'Errors'} > 0 or $RAM->{'ECCErrors'} or $RAM->{'UECCErrors'} > 0);
}

for my $check (@{$systemHealth}) {
    next unless $check->{'Monitored'} == 1;

    my $value = $check->{'Value'};
    $value /= $check->{'Divisor'} if $check->{'Divisor'} > 0;

    push @criticals, "$check->{'Name'} is CRITICAL ($value $check->{'Unit'})" if $check->{'Status'} == 2;
    push @warnings, "$check->{'Name'} is WARNING ($value $check->{'Unit'})" if $check->{'Status'} == 1 ;

    $np->add_perfdata(
        label => $check->{'Name'},
        value => $value,
        uom => $check->{'Unit'},
    );
}

$np->nagios_exit('CRITICAL', join(', ', @criticals)) if (scalar @criticals > 0);
$np->nagios_exit('WARNING', join(', ', @warnings)) if (scalar @warnings > 0);
$np->nagios_exit('OK', "");

sub getHashFromSNMP
{
    my ($session, $tree, $columns) = @_;
    my $health = [];
    
    my @Oids = map {"${tree}.${_}"} sort keys %{$columns};
    my $snmpResult = $session->get_entries(-columns => \@Oids);

    for my $oid (sort keys %{$snmpResult}) {
        my ($counter,$index) = $oid =~ /\.(\d+)\.(\d+)$/;
        $health->[$index-1]->{$columns->{$counter}} = $snmpResult->{$oid};
    }
    return $health;
}