#!/usr/bin/perl
use strict;
use JSON;
use lib '/opt/pptools';
use ppenv;
use Getopt::Std;
use URI::Escape;
use PPOPS::PP_Inventory;
use LWP::UserAgent;
use Spreadsheet::WriteExcel;
use Data::Dumper;

my $http  = "http";
my $host='inventory.proofpoint.com';
my $api='/cmdb_api/v1/system/';
my $req_type   = "application/json";
my @failures;
my %opt;
getopts('f:',\%opt);
my $DEBUG = $opt{'d'} ? 1 : 0;
my $output_filename = $opt{'f'} ? $opt{'f'} : "";

if($output_filename eq "" || @ARGV < 1)
{
	print <<EOM;
Usage: $0 -f <FILENAME> <start_date> [end_date]
-f: name of excel file (include .xls)
EOM
	exit;
}

my ($fh,$parms,$query,$workbook,$worksheet,$fh,$format1,$format2,$dateformat,$csvfilename,$row,$col);
my $excelfile='';
my $data;

open $fh, ">$output_filename" or die "Failed to open filehandle: $!";

# Fetch records from API
# print STDERR "getting records for query: $http://$host$api?_format=json&$field=$filter\n";
# my $response = $ua->get( "$http://$host$api?_format=json&$query" );
# if ( $response->code == 200 ) {
# 	print STDERR "got 200 ok\n";
# 	$data=&eat_json($response->content,{allow_nonref=>1});
# 
# }
# else
# {
# 	exit;
# }

my $start_date = $ARGV[0];
my $end_date = $ARGV[1];

my @query = ('entity_name=device',
	     'change_time>=' . $start_date,
#	     'change_time<' . $end_date,
	     'field_name=data_center_code');

$data=&getRecs('inv_audit', \@query);

my %system_hash;
for my $change (@$data) {
	my $fqdn = $change->{entity_key};
	next if (!defined($change->{old_value}) ||
		 !defined($change->{new_value}));

	if (exists $system_hash{$fqdn}) {
		push @{$system_hash{$fqdn}}, $change;
	} else {
		$system_hash{$fqdn} = [ $change ];
	}
}

my @final;
for my $fqdn (keys %system_hash) {
	my $data = $system_hash{$fqdn};
	next if (!@$data);

	my $old_dc = $$data[0]->{old_value};
	my $new_dc = $$data[-1]->{new_value};
	my $moved_time = $$data[-1]->{change_time};
	next if ($old_dc eq $new_dc);

	@query = ('fqdn=' . $fqdn, 'status!=disposed');

	$data = &getRecs('system', \@query);
	next if (!@$data);

	if (@$data) {
		my $system = $$data[0];
		next if ($system->{is_virtual} eq 'true');
		next if ($system->{manufacturer} =~ /^(Bochs|KVM|Red Hat|VMWare)/);

		$system->{date_moved} = $moved_time;
		$system->{old_data_center_code} = $old_dc;
		$system->{new_data_center_code} = $new_dc;
		push @final, $system;
	}
}

my @fields = ('fqdn', 'asset_tag_number', 'serial_number', 'old_data_center_code',
	      'new_data_center_code', 'date_moved',
	      'manufacturer', 'product_name',
	      #'is_virtual', 'virtual', 'notes'
	     );

# init worksheet counters/vars
my $row=0;
$workbook  = Spreadsheet::WriteExcel->new($fh);
$worksheet = $workbook->add_worksheet();
$format1 = $workbook->add_format();
$format1->set_properties(bold => 1);
$format2 = $workbook->add_format();
$format2->set_properties(text_wrap => 1);
$dateformat=$workbook->add_format(num_format=> 'yyyy/mm/dd');

my @headers = @fields;

for (my $k = 0; $k < scalar(@headers); $k++) {
	$worksheet->write_string($row, $k, $headers[$k], $format1);
}

$row++;

for my $system (@final) {
	for (my $k = 0; $k < scalar(@headers); $k++) {
		my $data = $system->{$headers[$k]};
		$worksheet->write_string($row, $k, $data);
	}

	$row++;
}

$workbook->close();
binmode $fh;
print $fh $excelfile;
exit;







