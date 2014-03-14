#!perl

############
# Copyright 2011-2013 Proofpoint, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#  http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
############

use strict;
use Text::CSV_XS;
use JSON;
use LWP::UserAgent;
use Getopt::Std;
my %opt;
getopts('f:dprH',\%opt);
my $DEBUG = $opt{'d'} ? 1 : 0;
my $FILE = $opt{'f'} ? $opt{'f'} : "";
my $PARSEONLY = $opt{'p'} ? 1 : 0;
my $RUNTESTS = $opt{'r'} ? 1 : 0;
my $HALT = $opt{'H'} ? 1 : 0;

if(length($FILE) == 0)
{
print "usage: inv_test.pl -f <testcase file>
    -f: csv file with testcases (see cmdb_tests.csv)
    -p: parse testcase file only 
    -r: run tests
    -d: debug
";
exit;
}

my $ua = LWP::UserAgent->new;
$ua->timeout(320);


my @rows;
my $csv = Text::CSV_XS->new ({binary => 1 }) or die "Cannot use CSV: ".Text::CSV->error_diag ();
open my $fh,  $FILE or die "$FILE: $!";
my @fields;
my @tests;
while (my $row = $csv->getline($fh)) 
{
    if(scalar @fields)
    {
        my $t={};
        if($row->[0])
        {
            for(my $f=0;$f<scalar(@fields);$f++)
            {
                $t->{$fields[$f]} = $row->[$f];
            }
            push @tests, $t;
        }
    }
    else
    {
        @fields=@$row;
    }
}


if ($PARSEONLY)
{
    print to_json(\@tests,{pretty=>1});
    print "\n";
}

if($RUNTESTS)
{
    my $testResults={
        pass => 0,
        fail => 0
    };
    foreach my $test (@tests)
    {
        my $result=&execTest($test);
        print "$result\n";
        if($result=~'FAIL')
        {
            $$testResults{'fail'}++;
        }
        else
        {
            $$testResults{'pass'}++;
        }
        if($result=~'FAIL' && $HALT)
        {
            last;
        }
        print "\n";
    }    
    print "Complete: Total: " . ($$testResults{'pass'} + $$testResults{'fail'}) . " Pass: $$testResults{'pass'}  Fail: $$testResults{'fail'}\n";
}

sub makeUrlQueryStr()
{
    my $datastr=shift;
    my $data=from_json($datastr,{allow_nonref=>1});
    my $querystr="";
    foreach my $key (keys(%{$data}))
    {
        $querystr.="&" if($querystr);
        $querystr.=$key . "=" . $data->{$key};
    }
    return $querystr;
}

sub execTest()
{
    my $test = shift;
    my $response;
    my @expected_result;

### assemble request from test data
    my $testurl=$test->{'host:port'} . $test->{'baseurl'} . $test->{'entity'} . '/';
    if ($test->{'method'} ne 'POST')
    {
        $testurl.=$test->{'entity_key'};
    }
    $test->{'user/pass'}=~m|(.+)/(.+)|;
    my $user=$1;
    my $pass=$2;
    my $result='';
    $test->{'host:port'}=~m|//(.*)|;
    my $hostport=$1;
    $ua->credentials($hostport,'Operations Only',$user,$pass);
    if($test->{'method'} eq 'GET')
    {
        if($test->{'data'})
        {
            $testurl.="?" . &makeUrlQueryStr( $test->{'data'} );
        }
        $response = $ua->get($testurl);
    }
    else
    {
        my $request = HTTP::Request->new($test->{'method'} => $testurl);
        $request->content_type('application/json');
        $request->content($test->{'data'}) if($test->{'data'});
        $response = $ua->request($request);
    }
    print "### executing test: " . $test->{'testname'} . " with url (" . $test->{'method'} . "): $testurl" ;

    if($response->code == 501)
    {
        $result.="\nHTTP ERROR: " . $response->status_line;
        exit;
    }

### evaluate results
    if($response->code != $test->{'returncode'})
    {
        $result.="\nHTTPFAIL: got returncode of " .  $response->code . ", expected " . $test->{'returncode'};
    }
    else
    {
        $result.="\nHTTPPASS: got returncode of " .  $response->code;
    }
    if($test->{'result type'} eq 'header')
    {
        @expected_result = split(/[=~]/,$test->{'result check'});
        $test->{'result check'}=~m/([=!])/;
        my $operator=$1;
        if( ( $operator eq '=' && $response->header($expected_result[0]) ne $expected_result[1])
           || ( $operator eq '~' && $response->header($expected_result[0])!~/$expected_result[1]/)
        )
        {
            $result.="\nFAIL: got header " . $expected_result[0] . ": " . $response->header($expected_result[0]) . ", expected " . $expected_result[1];
        }
        else
        {
            $result.="\nPASS: got header " . $test->{'result check'};
        }
    }
    if($test->{'result type'} eq 'data')
    {
        my $returndata;
        @expected_result = split('=',$test->{'result check'});
        eval {
            $returndata=from_json($response->content,{allow_nonref=>1});
            if(ref($returndata) eq 'ARRAY')
            {
                $returndata=$$returndata[0];
            }
        };
        if($@ || $returndata->{$expected_result[0]} ne $expected_result[1])
        {
            if($@)
            {
                $result.="\nFAIL: could not decode response: $@";
            }
            else
            {
                $result.="\nFAIL: got data " . $expected_result[0] . ": " . $returndata->{$expected_result[0]} . ", expected " . $expected_result[1];                
            }
        }
        else
        {
            $result.="\nPASS: got data " . $test->{'result check'};
        }

    }
    if($test->{'result type'} eq 'results')
    {
        my $returndata=from_json($response->content,{allow_nonref=>1});
        if(scalar(@$returndata) != $test->{'result check'} )
        {
            $result.="\nFAIL: got " . scalar(@$returndata) . "restults, expected " . $test->{'result check'};
        }
        else
        {
            $result.="\nPASS: got " . $test->{'result check'} . " results";
        }

    }
    return $result;
}





