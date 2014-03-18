#!/usr/bin/perl

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

package cmdb_api;
use strict;
use warnings;
use lib '/opt/pptools';
use ppenv;
use URI::Escape;
use Apache2::RequestRec ();
use Apache2::Request;
use Apache2::RequestIO ();
use Apache2::Connection;
use Apache2::Access;
use APR::Brigade ();
use APR::Bucket ();
use Log::Log4perl qw(:easy);
use Apache2::Filter ();
use Apache2::Const -compile => qw(OK HTTP_NOT_FOUND HTTP_OK HTTP_FAILED_DEPENDENCY HTTP_NOT_ACCEPTABLE HTTP_NO_CONTENT HTTP_INTERNAL_SERVER_ERROR DECLINED HTTP_ACCEPTED HTTP_CREATED HTTP_UNAUTHORIZED SERVER_ERROR MODE_READBYTES HTTP_CONFLICT HTTP_FORBIDDEN HTTP_METHOD_NOT_ALLOWED);
use APR::Const    -compile => qw(SUCCESS BLOCK_READ);
use constant IOBUFSIZE => 8192;
use JSON;
use XML::Parser;
use XML::Simple;
use Apache::DBI;
use Date::Manip;
use Optconfig;
use DBI;

sub eat_json {
   my ($json_text, $opthash) = @_;
    return ($JSON::VERSION > 2.0 ? from_json($json_text, $opthash) : JSON->new()->jsonToObj($json_text, $opthash));
}

sub make_json {
   my ($obj, $opthash) = @_;
    return ($JSON::VERSION > 2.0 ? to_json($obj, $opthash) : JSON->new()->objToJson($obj, $opthash));
}


my $opt = Optconfig->new('cmdb_api', { 'driver=s' => 'mysql',
                                      'dbuser=s' => 'dbuser',
                                      'dbpass=s' => 'dbpass',
                                      'dbhost' => 'localhost',
                                      'database' => 'inventory',
                                      'debug' => 1,
                                      'prism_domain' => 'prism.ppops.net',
                                      'logconfig' => '/var/www/cmdb_api/log4perl.conf',
                                      'lexicon' => '/var/www/cmdb_api/pp_lexicon.xml',
                                      'ipaddress_attribute' => "ip_address",
                                      "traffic_control_search_fields" => ["fqdn","macaddress","ipaddress"],
                                      'entities' => {
                                      		acl=>'Acl',
											vip=>'Generic',
											datacenter_subnet=>'Generic',
											data_center=>'Generic',
											role=>'Generic',
											pod_cluster=>'Generic',
											snat=>'Generic',
											pool=>'Generic',
											cluster=>'Generic',
											hardware_model=>'Generic',
											cluster_mta=>'Generic',
											system=>'System',
											device=>'System',
											blade_chassis=>'System',
											console_server=>'System',
											firewall=>'System',
											load_balancer=>'System',
											network_switch=>'System',
											power_strip=>'System',
											router=>'System',
											storage_head=>'System',
											storage_shelf=>'System',
											device_ip=>'Generic',
											newhostname=>'Provision',
											pcmsystemname=>'ProvisionPcm',
											user=>'Generic',
											currentUser=>'User',
											inv_audit=>'Generic',
											audit=>'Audit',
											inv_normalizer=>'Generic',
											fact=>'TrafficControl',
											change_queue=>'ChangeQueue',
											ip=>'Generic',
											service_instance=>'Generic',
											service_instance_data=>'Generic',
											instance_size=>'Generic',
									        instance_location=>'Generic',
									        column_lkup=>'Column_lkup',
					     					environments=>'Environments',
					     					environmentservice=>'Environments'
                                      }
                                    });

my $valid_entity_apis={
	'Environments' => 1,
	'ChangeQueue' => 1,
	'System' => 1,
	'Generic' => 1,
	'Audit' => 1
};

my $DEBUG=$opt->{'debug'};
my $DBHOST=$opt->{'dbhost'};
my $DBUSER=$opt->{'dbuser'};
my $DBPASS=$opt->{'dbpass'};
my $DATABASE=$opt->{'database'};
my $IPADDRESSFIELD=$opt->{'ipaddress_attribute'};
my $DRIVER=$opt->{'driver'};
my ($lexicon,$tree,$parser);
my ($parms);
my $log_config_file=$opt->{'logconfig'};

Log::Log4perl::init($log_config_file);

my $logger = Log::Log4perl->get_logger('inventory.cmdb_api');
unless($lexicon)
{
#TODO this hardcoded path is bad fix it	
	$lexicon=$opt->{'lexicon'};
}

# database connection
our $dbh;
#valid api types. these must exist and be parsable in the lexicon if they are 'Generic' 
# or have provided do<ENTITY>GET/PUT/POST functions

my $valid_entities = $opt->{'entities'};

my $versions=[ 'v1' ];

$parser= XML::Simple->new( );
eval { $tree=$parser->XMLin($lexicon); };
# show error and die if xml parsing of the lexicon failed
if($@)
{
	$logger->fatal("error parsing $lexicon\n$@");
	exit;
}

$logger->info("$lexicon is xml ok"); 

our $tree_extended;
$tree_extended=&eat_json(&make_json($tree));
# loop through entities and add base attributes to things that subclass other stuff
foreach(keys(%{$tree_extended->{entities}}))
{
	if($tree_extended->{entities}->{$_}->{extends})
	{
		my $extends=&lkupXMLPath($tree->{entities}->{$_}->{extends});
		foreach my $attr (keys(%$extends))
		{
			$tree_extended->{entities}->{$_}->{$attr}=$extends->{$attr};
		}
	}
}
$logger->debug("lexicon: " . &make_json($tree,{pretty=>1,allow_nonref=>1}) ) if ($logger->is_debug());
$logger->debug("lexicon extended: " . &make_json($tree_extended,{pretty=>1,allow_nonref=>1}) ) if ($logger->is_debug());

sub lkupXMLPath()
{
	my $str=shift;
	my @seg=split('/',$str);
	shift(@seg);
	shift(@seg);
	my $rtn='$tree->{' . shift(@seg) . '}';
	foreach(@seg)
	{
		$rtn.='->{' . $_ . '}';
	}
	return eval($rtn);
}

# mod perl2 handler
sub handler() {
 	$dbh=DBI->connect("DBI:$DRIVER:database=$DATABASE;host=$DBHOST",$DBUSER,$DBPASS);
	my $r = shift;
	my $up_uri = $r->unparsed_uri();
	$up_uri =~ s/.+\?//;
	my $uri = uri_unescape($up_uri);
	my $req=Apache2::Request->new($r);
	my ($requestObject,$data,$formatted_data);
	%{$$requestObject{'query'}}=%{$req->param} if $req->param;	
	$$requestObject{'getparams'}=$uri;
	$$requestObject{'stat'}=Apache2::Const::HTTP_OK;
	$$requestObject{'_format'}=$$requestObject{'query'}{'_format'} || 'json';
	$$requestObject{'method'}=$req->method();
	@{$$requestObject{'path'}}=split('/',$req->uri());
	$$requestObject{'pathstr'}=$req->uri();
	$$requestObject{'user'}=&doGenericGET({entity=>'user',path=>[$req->user]}) if $req->user;
	$$requestObject{'http_auth_user'}=$req->user if $req->user;
	$$requestObject{'ip_address'}=$r->connection->remote_ip();
	if($$requestObject{'method'} ne 'GET')
	{
		$$requestObject{'body'}= read_post($r);
	}
	else
	{
		$$requestObject{'body'}='';
	}
	shift(@{$$requestObject{'path'}});
	if(shift(@{$$requestObject{'path'}}) eq 'cmdb_api')
	{
	    $$requestObject{'requested_api'}=shift(@{$$requestObject{'path'}});
		$$requestObject{'entity'}=shift(@{$$requestObject{'path'}});	
		$logger->debug(&make_json($requestObject,{pretty=>1,allow_nonref=>1,allow_blessed=>1})) if ($logger->is_debug());
		# do help if it was asked
		if( exists $requestObject->{'query'}->{'help'} || exists $requestObject->{'query'}->{'lexicon'})
		{
			$requestObject->{'help'}=1;
			if(!$requestObject->{'requested_api'})
			{
				$r->print(&make_json($versions));
    			return Apache2::Const::OK;
				
			}		
			elsif( !$requestObject->{'entity'})
			{
				my $ents=[];
				my $lex={};
				if($requestObject->{'query'}->{'lexicon'})
				{
					foreach(keys(%$valid_entities))
					{
						$lex->{$_}= $tree->{entities}->{$_};
						no strict 'refs';
						# check each attribute and populate enumerations if needed
						foreach my $attr (keys(%{$lex->{$_}}))
						{
							if($lex->{$_}->{$attr} && ref($lex->{$_}->{$attr}) eq 'HASH' && 
								defined $lex->{$_}->{$attr}->{'enumeration'} && 
								defined $lex->{$_}->{$attr}->{'enumeration'}->{'entity'} && 
								defined $lex->{$_}->{$attr}->{'enumeration'}->{'attribute'})
							{
								$lex->{$_}->{$attr}->{'enumeration'}->{'enumerator'}=&doColumn_lkupGET($requestObject,$lex->{$_}{$attr}{'enumeration'}{'entity'},$lex->{$_}{$attr}{'enumeration'}->{'attribute'});
							}
						}
					}					
					$r->print(&make_json($lex));
				}
				else
				{
					foreach(keys(%$valid_entities))
					{
						push(@$ents,$_) if ( $valid_entity_apis->{ $valid_entities->{$_} } == 1 );
					}					
					$r->print(&make_json($ents));
				}
    			return Apache2::Const::OK;
			}
			else
			{
				#$r->print(&make_json(&getFieldList($requestObject->{'entity'})));
				$r->print(&make_json( $tree->{entities}->{$requestObject->{'entity'}}, {pretty => 1,allow_nonref=>1}));
    			return Apache2::Const::OK;
			}

		}

		
		# check for valid entity
		unless($$requestObject{'entity'} && $$valid_entities{$$requestObject{'entity'}})
		{
			$logger->debug( "valid entities:") if ($logger->is_debug());
			$logger->debug( "entity lkup: $$valid_entities{$$requestObject{'entity'}}") if ($logger->is_debug());
			$r->print('valid entity required');
			return Apache2::Const::HTTP_NOT_ACCEPTABLE;
		}

		#deal with the connection and produce data
		$data=&ProcessRequest($requestObject);
		$r->status($$requestObject{'stat'});
		if($$requestObject{'stat'} eq '500')
		{
			$data={
				success => 'false',
				message => $data
			};
		}
		$logger->debug( "final return of status: $$requestObject{'stat'}") if ($logger->is_debug());
		
#TODO reconcile the '"string" data that comes back from above and how we output it (errors, etc...)
		if($$requestObject{'headers_out'})
		{
			$r->headers_out->add($$requestObject{'headers_out'}[0]=>$$requestObject{'headers_out'}[1]);
		}
#TODO make output format based on accept content header
		if(!defined $data && keys(%{$$requestObject{'query'}}) > 0 )
		{
			$data = [];
		}
		# set output format
		if(defined $data)
		{
			if($$requestObject{'_format'} eq 'json')
			{		
				$r->content_type('application/json');		
				$formatted_data=&make_json($data,{pretty=>1,allow_nonref=>1,allow_blessed=>1});
			}
			elsif($$requestObject{'_format'} eq 'xml')
			{
				$r->content_type('text/xml');			
				$formatted_data=XMLout($data);		
			}
			elsif($$requestObject{'_format'} eq 'text')
			{
				$logger->debug( "output data as text") if ($logger->is_debug());
				$formatted_data=$data;
			}
			$r->print($formatted_data);
		}
	}
	else
	{
		$logger->error("error parsing api str");
	}
    return Apache2::Const::OK;
}

sub doFieldNormalization()
{
	my($entity,$field,$value)=@_;
	my $newvalue;
	$value=~s/^\ //g if defined $value;
	$value=~s/\ $//g if defined $value;
	my $matchers=$dbh->selectall_arrayref('select matcher,sub_value from inv_normalizer where entity_name=? and field_name=?',
		{},($entity,$field));
	foreach(@$matchers)
	{
		
		if($value=~m/$$_[0]/i)
		{
			$logger->debug( "matched with $$_[0] and subbing $$_[1]") if ($logger->is_debug());
			return $$_[1];
		}
	}
	if(ref $value eq 'ARRAY')
	{
		$value=join(',',@$value);
	}
	return $value;
}

	
# lifted from mod_perl2 docs,  does body content read for post/put 	
sub read_post {
     my $r = shift;
     my $bb = APR::Brigade->new($r->pool,$r->connection->bucket_alloc);
     my $data = '';
     my $seen_eos = 0;
     do {
         $r->input_filters->get_brigade($bb, Apache2::Const::MODE_READBYTES,APR::Const::BLOCK_READ, IOBUFSIZE);
         for (my $b = $bb->first; $b; $b = $bb->next($b)) {
             if ($b->is_eos) {
                 $seen_eos++;
                 last;
             }
             if ($b->read(my $buf)) {
                 $data .= $buf;
             }
             $b->remove; # optimization to reuse memory
         }
     } while (!$seen_eos);
     $bb->destroy;
     return $data;
 }




#processes lexicon to get fields for an entity
sub getFieldList()
{
	my $entity=shift;
	my $bare=shift || 0;
	my @arr;
	foreach(keys(%{$tree->{entities}->{$entity}}))
	{
		next if ($_ eq 'key' || $_ eq 'extends' || $_ eq 'table');
		push(@arr,$_);
	}
	if($valid_entities->{$entity} eq 'system' && !$bare)
	{
		foreach(keys(%{$tree->{entities}->{device}}))
		{
			next if ($_ eq 'key' || $_ eq 'extends' || $_ eq 'table');
			push(@arr,$_);
		}		
	}
	$logger->info("processed fields for $entity : " . join(',',@arr) );
	return \@arr;
}

sub runACL()
{
	my($req,$r,$entity,$changes,$blocked_changes)=@_;
	my($groups) = $req->{'user'}->{'groups'};
	if(ref $groups ne 'ARRAYREF')
	{
		$logger->debug("groups ref= ".ref $groups) if ($logger->is_debug());
		$groups = [split(',',$groups)] if $groups; 
	}
 	my $acls = $dbh->selectall_arrayref("select * from acl where entity=?", { Slice => {} },($entity));
	foreach my $field (keys(%$changes))
	{
		foreach my $acl (@$acls)
		{
			#skip if acl group not in users grouplist
			next unless(grep(/^$acl->{'acl_group'}$/,@$groups));
			# skip of the field the acl applies to isn't being changed
			next unless($field eq $acl->{'field'}  || $acl->{'field'} eq '*');
			$logger->info("found acl to process: " . &make_json($acl) );
			my $eval=$acl->{'logic'};
			my $out=&doEval($req,$r,$field,$changes,$acl->{'logic'});
			if($@)
			{
				die 'error compiling ACL';
			}
			if( $out )
			{
				$logger->info("acl ran and blocked"); 
				$blocked_changes->{ $field }=$changes->{ $field };
				delete $changes->{ $field };
			}
		}
	}
	return ($changes,$blocked_changes);
}

sub doEval()
{
	my($req,$r,$f,$changes,$logic)=@_;
	#$logger->debug("ACL EVAL: $logic ")
	return eval($logic);
}


# looks for function to process the request, based on entity specification in $valid_entities and http method
sub ProcessRequest()
{
	$logger->info("detemining request process function");
	
	my $requestObject=shift;
	my $func='do' . $$valid_entities{$$requestObject{'entity'}} . $$requestObject{'method'};
	if($$requestObject{'method'} eq 'PUT')
	{
		unless ($$requestObject{'path'}[0])
		{
			$$requestObject{'stat'}=Apache2::Const::HTTP_INTERNAL_SERVER_ERROR;
			return 'no key specified';
		}
		#$$requestObject{'stat'}=Apache2::Const::HTTP_ACCEPTED;
	}
	if($$requestObject{'method'} eq 'POST')
	{
		$$requestObject{'stat'}=Apache2::Const::HTTP_CREATED;
	}
	no strict 'refs';
	if(exists &$func)
	{
		$logger->info("found function $func");
		return &$func($requestObject);
	}
	else
	{
		$logger->error("no function found $func");
		$$requestObject{'stat'}=Apache2::Const::HTTP_INTERNAL_SERVER_ERROR;
		return 'no entity function'
	}
}

sub doColumn_lkupGET()
{
	my $requestObject=shift;
	my $entity=shift || $$requestObject{'path'}[0];
	my $col=shift || $$requestObject{'path'}[1];

	my %lkup;
	if($entity eq 'system')
	{
		$entity = 'device';
	}
	my $entity_fields=&getFieldList($entity);
$logger->info("$entity field list: " . join (',',@$entity_fields));
	foreach (@$entity_fields) { $lkup{$_}++;}
$logger->info('doing col lkup for ' . $entity . '-> ' . $col);

	my $sql;
	if($lkup{$col})
	{
		$sql="select distinct $col,? from $entity order by 1 limit 2000";
	}
	else
	{
		$sql='select distinct metadata_value from device_metadata where metadata_name=? order by 1 limit 2000';
	}
	my $res=$dbh->selectcol_arrayref($sql,{},($col));
	my @new;

	foreach(@$res){$_=~s/\"//g;push(@new,$_) if $_;}

	return \@new;
}

#audit info retreival

sub doAuditGET()
{
	my $requestObject=shift;
	my $entity=$$requestObject{'path'}[0];
	if($$valid_entities{$entity} eq 'System')
	{
		$entity='device';
	}
	my $lkup=$$requestObject{'path'}[1];
	my $sql='select * from inv_audit where entity_name=? and entity_key=? order by change_time';
	return &recordFetch($requestObject,$sql,[$entity,$lkup]);
}


#special api to check current user for write access
sub doUserGET()
{
	my $requestObject=shift;
	if($requestObject->{'user'})
	{
		return $requestObject->{'user'};	
	}
	else
	{
		return { username=> $requestObject->{'http_auth_user'}};
	}
}

# new traffic control api
sub doTrafficControlPOST()
{
	my $requestObject=shift;
	$requestObject->{'user'}=&doGenericGET({entity=>'user',path=>['trafficcontrol']});
	my $data=&eat_json($$requestObject{'body'},{allow_nonref=>1});
	my ($lkup_data,$lkup);
	$logger->debug("TC got POST from agent") if ($logger->is_debug());
	
	foreach (@{$opt->{'traffic_control_search_fields'}})	
	{
		# skip serial if not dell tag 
		next if( $_ eq 'serial_number' && length($data->{$_}) != 7 );
		$lkup= $dbh->selectall_arrayref("select * from device where $_=?", { Slice => {} },($data->{$_}));
		if(scalar(@$lkup) == 1)
		{
			$lkup_data=$$lkup[0];
			last;
		}
	}
	if(ref $lkup_data eq 'ARRAY' && scalar(@$lkup_data) == 0)
	{
		$lkup_data='';
	}
	$requestObject->{'entity'}='system';

	# loop through the entity field and assign values based on 'fact' designation of attributes
	# or default to just looking for an entry of the same name
	my $data_assembled={ 'fqdn' => $data->{'fqdn'}};
	foreach my $attr (keys(%{$tree_extended->{'entities'}->{'system'}}))
	{
		if(ref($tree_extended->{'entities'}->{'system'}->{$attr}) eq 'HASH' && $tree_extended->{'entities'}->{'system'}->{$attr}->{'fact'})
		{
			foreach my $fact_lookup (split(',',$tree_extended->{'entities'}->{'system'}->{$attr}->{'fact'}))
			{
				$logger->debug("doing fact lookup for $attr with $fact_lookup");
				if($data->{$fact_lookup})
				{
					$data_assembled->{$attr}= $data->{$fact_lookup};
					$logger->debug("found data lookup for $attr in fact $fact_lookup: $data->{$fact_lookup}");
					last;
				}
			}
		}
		else
		{
			$data_assembled->{$attr}= $data->{$attr} if($data->{$attr});
		}
	}
	$requestObject->{'body'}=make_json($data_assembled,{allow_nonref=>1});

	# if we found the entry, then setup for PUT else do POST
	if($lkup_data)
	{		
		$logger->info("TC found system " . $lkup_data->{'fqdn'} . ", doing PUT");
		$requestObject->{'path'}=[$lkup_data->{'fqdn'}];
		&doSystemPUT($requestObject);
	}
	else
	{
		$logger->info("TC doing POST for new system");
		&doSystemPOST($requestObject);
	}
	
}


sub doProvisionPcmGET()
{
	my $requestObject=shift;
	my $id = $$requestObject{'path'}[0];

	if(!$id)
	{
		$$requestObject{'stat'} = Apache2::Const::HTTP_NOT_ACCEPTABLE;
		return {'error'=> 'missing data (id)'};
	}

	my ($sql,$sth,$existing_data);
	$sql = 'select fqdn from device where serial_number=?';
	$sth=$dbh->prepare($sql);
	$sth->execute($id);
	$existing_data=$sth->fetchall_arrayref({},undef);

	if (scalar(@$existing_data)>1) 
        {
		$$requestObject{'stat'} = Apache2::Const::HTTP_INTERNAL_SERVER_ERROR;
		return {'error'=>'Multiple systems with the same ID'};
        }
        elsif(scalar(@$existing_data))
	{
		$$requestObject{'stat'} = Apache2::Const::HTTP_OK;
		return {'fqdn'=>$$existing_data[0]{'fqdn'}}
	}

	my $record={};
	$$record{'inventory_component_type'} = 'system';
	$$record{'status'} = 'idle';
        $$record{'serial_number'} = $id;

	my $name = &setNewName($record, '.' . $opt->{'prism_domain'});

	$$requestObject{'stat'} = Apache2::Const::HTTP_OK;
        return {'fqdn'=>$name};
}

# special api to fetch new hostname for provisioning
sub doProvisionGET()
{
	my $requestObject=shift;
	my ($sql,$sth,$rv);
	# this code seems pointless, why check for length 7 if we are going to remove chars?
	if($$requestObject{'query'}{'serial_number'} && length($$requestObject{'query'}{'serial_number'}) == 7 )
	{
		$$requestObject{'query'}{'serial_number'}=~s/^\s+//g;
		$$requestObject{'query'}{'serial_number'}=~s/\s+$//g;		
	}
	if($$requestObject{'query'}{'serial_number'}  && length($$requestObject{'query'}{'serial_number'}) == 7 )
	{
		$sql ='select fqdn from device where serial_number=?';
		$sth=$dbh->prepare($sql);
		$rv=$sth->execute(($$requestObject{'query'}{'serial_number'}));
	}
	elsif(!$$requestObject{'query'}{'mac_address'})
	{
		$$requestObject{'stat'}=Apache2::Const::HTTP_FAILED_DEPENDENCY;
		return 'missing data (mac_address)'
	}
	else
	{
		$sql ='select fqdn from device where mac_address=?';
		$sth=$dbh->prepare($sql);
		$rv=$sth->execute(($$requestObject{'query'}{'mac_address'}));
	}
	# unless($$requestObject{'query'}{'serial_number'})
	# {
	# 	$$requestObject{'stat'}=Apache2::Const::HTTP_FAILED_DEPENDENCY;
	# 	return 'missing data (serial_number)';
	# }
	# lkup system
	my $data=$sth->fetchall_arrayref({},undef);
	my ($hostname,$newname);
	
	# gather data sent in with the call
	my $new={};
	foreach my $f (('rack_code','rack_position','asset_tag_number','manufacturer','product_name','serial_number',$IPADDRESSFIELD,'mac_address','inventory_component_type'))
	{
		$$requestObject{'query'}{$f}=~s/^\s+//g;
		$$requestObject{'query'}{$f}=~s/\s+$//g;
		if($$requestObject{'query'}{$f})
		{
			$$new{$f}=&doFieldNormalization('system',$f,$$requestObject{'query'}{$f});
			#$$new{$f}=$$requestObject{'query'}{$f};
		}
	}
	
	# there should only be one system 
	if(scalar(@$data)>1)
	{
		$logger->warn("found too many systems in inventory: " . scalar(@$data) );
		return 'too many entries';
#TODO do something about finding more than one system 
	}
	elsif(scalar(@$data))
	{
		$logger->info("found system in inventory: " . $$data[0]{'fqdn'});
		# call setNewName which will rename if it doesn't match
		$$new{'fqdn'}=$$data[0]{'fqdn'};
		$$new{'status'}=$$data[0]{'status'};
		$newname=&setNewName($new, '.ppops.net');
		# set the IP for this system since it's coming online from provisioning vlan
		# validate that the IP is on the provisioning vlan
		if($$requestObject{'query'}{$IPADDRESSFIELD} && $$requestObject{'query'}{$IPADDRESSFIELD} =~ /10\.\d{1,3}\.25/)
		{
			$logger->info("updating IP for system entry");
			$$requestObject{'query'}{$IPADDRESSFIELD}=~s/^\s//g;
			$$requestObject{'query'}{$IPADDRESSFIELD}=~s/\s$//g;
			$sql="update device set $IPADDRESSFIELD=? where fqdn=?";
			my $sth=$dbh->prepare($sql);
			$logger->debug("executing: $sql with $$requestObject{'query'}{$IPADDRESSFIELD},$newname") if ($logger->is_debug());
			my $rv=$sth->execute(($$requestObject{'query'}{$IPADDRESSFIELD},$newname));
			$logger->error($sth->err . " : " . $sth->errstr) if ($sth->err);				
		}
	}
	# no entry found, insert system into inventory with new name
	else
	{
		unless($$requestObject{'query'}{'inventory_component_type'})
		{
			$$requestObject{'stat'}=Apache2::Const::HTTP_FAILED_DEPENDENCY;
			return 'missing data (inventory_component_type)';
		}
		$$new{'status'}='idle';
		$newname=&setNewName($new, '.ppops.net');
		if($newname=~/ERROR/)
		{
			$$requestObject{'stat'}=Apache2::Const::HTTP_FAILED_DEPENDENCY;
		}
	}
	if($$requestObject{'_format'} eq 'text')
	{
		$hostname=$newname;	
	}
	else
	{
		$hostname={fqdn=>$newname};
		
	}
	$logger->info("new name assigned : $newname");
	return $hostname;
	
}

sub setNewName()
{
	my $r=shift;
	my $suffix=shift || "";
	my ($sql,$parms,$where);
	my $newname;
	# check to see if the name is correct or if box is set to production/deployment
	if ($$r{'fqdn'}!~/m\d{7}\.ppops\.net/ && $$r{'status'} ne 'production' &&  $$r{'status'} ne 'deployment' ) {
		if (defined $$r{'mac_address'}) {
			$newname = 'temp-' . $$r{'mac_address'};
			$newname =~ s/://g;
		} elsif (defined $$r{'serial_number'}) {
			$newname = 'temp-' . $$r{'serial_number'};
		} else {
			return "ERROR: must provide serial number or MAC address";
		}
	} else {
		$newname=$$r{'fqdn'};
	}

	# fqdn passed in, so updating existing
	if ($$r{'fqdn'}) {
		$sql="update device set fqdn=?";
		push(@$parms,$newname);
	}
	# otherwise trying insert
	else {
		$sql='insert into device set fqdn=?';
		push(@$parms,$newname);
	}
	foreach my $f (keys(%$r)) {
		if ($$r{$f} && $f ne 'fqdn') {
			$sql.=", $f=? ";
			push(@$parms,$$r{$f});
		}
	}
	# doing device update so adding where clause
	if ($sql =~ /update\ device/) {
		$where= " where fqdn=?";
		push(@$parms,$$r{'fqdn'});
	}

	my $dbh=DBI->connect("DBI:mysql:database=inventory;host=$DBHOST",
			     $DBUSER,$DBPASS,{AutoCommit=>0,RaiseError=>1});
	my $sth;

	eval {
		$sth = $dbh->prepare("$sql$where");
		executeDbStatement($sth, $sql, @$parms);

		my $device_id = $sth->{mysql_insertid};

		# We need to generate a name based on the auto-incremented
		# id column if this is a new device
		if ($newname =~ /^temp-/) {
			$newname = sprintf "m%07d", $device_id;
			$newname .= $suffix;

			$sql = "update device set fqdn=? where id=?";
			$sth = $dbh->prepare($sql);
			executeDbStatement($sth, $sql, ($newname, $device_id));
		}

		$dbh->commit;
	};
	if ($@) {
		my $errstr;

		if (defined $sth && $sth->err) {
			$errstr = $sth->err . " : " . $sth->errstr;
			$logger->error($errstr);
		} else {
			$errstr = $@;
		}

		$newname = "ERROR: $errstr";
	}

	return $newname;
}

sub doSql(){
	my $sql=shift;
	my $parms=shift;
	my $dbh=DBI->connect("DBI:$DRIVER:database=$DATABASE;host=$DBHOST",$DBUSER,$DBPASS);
	
	my $sth=$dbh->prepare($sql);
	my $sql_out;
	$logger->debug("executing: $sql with " . &make_json($parms,{allow_nonref=>1}) ) if ($logger->is_debug());
	my $rv=$sth->execute(@$parms);
	$logger->error($sth->err . " : " . $sth->errstr ) if ($sth->err);
	if($sth->err)
	{
		return {err=>$sth->err , errstr=> $sth->errstr};
	}
	if($sql=~/select/)
	{
		$sql_out=$sth->fetchall_arrayref({},undef);	
	}
	return { data=>$sql_out };
}
sub recordFetch(){ 
	my $requestObject=shift;
	my $sql=shift;
	my $parms=shift;
	my $return;

	my $rtn=&doSql($sql,$parms);
	if($$rtn{'err'})
	{
		$$requestObject{'stat'}=Apache2::Const::HTTP_INTERNAL_SERVER_ERROR;
		return $$rtn{'err'} . " : " . $$rtn{'errstr'};
	}	
	my $data=$$rtn{'data'};

	# format output inside extjs compatible object if requested
	if($$requestObject{'query'}{'_extjs'})
	{
		$return={
			records=>$data,
			total=>scalar(@$data),
			metaData=>{
				root=>'records',
				totalProperty=>'total',
				id=>$tree->{entities}->{$$requestObject{'entity'}}->{key},
				fields=>&getFieldList($$requestObject{'entity'})
			}
		};
		if( !scalar(@{$$return{metaData}{fields}}) && scalar(@{$$return{records}}) )
		{
			@{$$return{metaData}{fields}}=keys(%{$$return{records}[0]})
		}
	}
	elsif($$requestObject{'path'}[0])
	{
		$return=$$data[0];
	}
	else
	{
		$return=$data
	}
	return $return;
	
}


# handle generic updates
sub doGenericPUT
{
	my ($sql);
	my $requestObject=shift;
	my $entity=$$requestObject{'entity'};
	$logger->info("processing PUT");
	my $dbs=DBI->connect("DBI:$DRIVER:database=$DATABASE;host=$DBHOST",$DBUSER,$DBPASS,{AutoCommit=>1});
	$dbs->begin_work;
	my (@sql,$parms,@errors);
	my $data=&eat_json($$requestObject{'body'},{allow_nonref=>1});	
	#audit fetch record to comparison during audit
	my $now=$dbh->selectcol_arrayref('select now()');
	my @entity_fields=@{&getFieldList($$requestObject{'entity'})};
	my $lkup_data=&doGenericGET($requestObject);
	if(scalar(keys(%$lkup_data)) == 0)
	{
		$$requestObject{'stat'}=Apache2::Const::HTTP_NOT_FOUND;
		return 'There is no resource at this location';

	}
	if($$lkup_data{'metaData'})
	{
		$lkup_data=$$lkup_data{'records'}[0]
	}
	elsif(ref $lkup_data eq 'ARRAYREF')
	{
		$lkup_data=$$lkup_data[0];
	}
	
	# strip out unchanged data and trigger mtime if needed
	my $mtime;
	foreach(@entity_fields)
	{
		$$data{$_}=&doFieldNormalization($entity,$_,$$data{$_}) if exists $$data{$_};
		$mtime= $$now[0] if(exists $$data{$_} && !$tree_extended->{entities}->{'system'}->{$_}->{meta} );
		delete $$data{$_} if(defined $$data{$_} && defined $$lkup_data{$_} && $$data{$_} eq $$lkup_data{$_});
	}
	my $blocked_changes={};
	&runACL($requestObject,$lkup_data,$entity,$data,$blocked_changes);
	# if the user is not a system user, then error out now if needed
	$logger->info("changes: " . &make_json($data));
	$logger->info("blocked changes: " . &make_json($blocked_changes) );
	if($requestObject->{'user'}->{'systemuser'} ne '1' && scalar(keys(%$blocked_changes)))
	{
		$dbs->rollback;
		$$requestObject{'stat'}=Apache2::Const::HTTP_FORBIDDEN;
		return 'ACL blocked change: ' . &make_json($blocked_changes);
	}
	if(scalar(keys(%$blocked_changes)))
	{
		my $change_item={
			change_ip=>$$requestObject{'ip_address'},
			change_user=>$requestObject->{'user'}->{'username'},
			change_time=>$$now[0],
			entity=>$$requestObject{'entity'},
			entity_key=>$$lkup_data{$tree->{'entities'}->{$$requestObject{'entity'}}->{'key'}},
			change_content=>&make_json($blocked_changes)
		};
		&doGenericPOST({
			entity=>'change_queue',
			body=>&make_json($change_item),	
		});
		$logger->info("queued change");
		return "Change queued for approval";
	}

	foreach my $f (@entity_fields)
	{
		if(exists $$data{$f})
		{
			if($$data{$f} eq '')
			{			
				push(@$parms,undef);
			}
			else
			{
				push(@$parms,$$data{$f});
			}
			
			push(@sql,"$f=?");
			#audit  check each field and record change if done
			if(!defined $$lkup_data{$f} || $$data{$f} ne $$lkup_data{$f})
			{
				$dbs->do('insert into inv_audit set 
					entity_name=?, 
					entity_key=?,
					field_name=?,
					old_value=?,
					new_value=?,
					change_time=?,
					change_user=?,
					change_ip=?',
					{},
					($entity,
					$$lkup_data{$tree->{entities}->{$$requestObject{'entity'}}->{key}},
					$f,   #field
					$$lkup_data{$f}, #old val
					$$data{$f},  # new val
					$$now[0],
					$requestObject->{'user'}->{'username'},  # user
					$$requestObject{'ip_address'}  # ip
					)
				);
			}			
		}
	}
	if(scalar(@sql) == 0)
	{
		$$requestObject{'stat'}=Apache2::Const::HTTP_NO_CONTENT;
		$dbs->commit;
		return;		
	}
	my $sql_set=join(',',@sql);
	# assemple final sql
	$sql="update $entity set $sql_set where " . $tree->{entities}->{$entity}->{key} . "=?";
	push(@$parms,$$requestObject{'path'}[0]);
	
	## do sql and record any errors
	my $sth=$dbs->prepare($sql);
	if ($sth->err)
	{
		push(@errors,$dbs->err . ": " . $dbs->errstr);
		$logger->error($sth->err . " : " . $sth->errstr);
	}
	$logger->debug("executing: $sql with " . join(',',@$parms) ) if ($logger->is_debug());
	my $rv=$sth->execute(@$parms);
	if ($sth->err)
	{
		push(@errors,$dbs->err . ": " . $dbs->errstr);
		$logger->error($sth->err . " : " . $sth->errstr );
	}

	if(scalar(@errors))
	{
		$dbs->rollback;
		$$requestObject{'stat'}=Apache2::Const::HTTP_INTERNAL_SERVER_ERROR;
		return \@errors;
	}
	else
	{
		$dbs->commit;
		return &doGenericGET($requestObject);
	}
	
}

# handle generic creations
sub doGenericPOST
{
	my ($sql);
	my $requestObject=shift;
	my $entity=$$requestObject{'entity'};
	$logger->info("processing POST");
	my (@sql,$parms);
	my $data=&eat_json($$requestObject{'body'},{allow_nonref=>1});
	my $blocked_changes={};
	&runACL($requestObject,{},$entity,$data,$blocked_changes);
	# if the user is not a system user, then error out now if needed
	$logger->info("blocked PUT fields: " . &make_json($blocked_changes) );
	my $now=$dbh->selectcol_arrayref('select now()');
	if($requestObject->{'user'}->{'systemuser'} ne '1' && scalar(keys(%$blocked_changes)))
	{
		$dbh->rollback;
		$$requestObject{'stat'}=Apache2::Const::HTTP_FORBIDDEN;
		return 'ACL blocked change: ' . &make_json($blocked_changes);
	}
	foreach my $f (@{&getFieldList($$requestObject{'entity'})})
	{
		if(exists $$data{$f})
		{
			$$data{$f}=&doFieldNormalization($entity,$f,$$data{$f});
			push(@$parms,$$data{$f});
			push(@sql,"$f=?");
		}
	}
	my $sql_set=join(',',@sql);	
	$sql="insert into $entity set $sql_set";
	my $sth=$dbh->prepare($sql);
	# set for error and return if db prepare had errors
	$logger->error($sth->err . " : " . $sth->errstr) if ($sth->err);
	$$requestObject{'stat'}=Apache2::Const::HTTP_INTERNAL_SERVER_ERROR if $sth->err;	
	return $sth->err . " : " . $sth->errstr if ($sth->err);
	#audit entry for create
	$dbh->do('insert into inv_audit set 
		entity_name=?, 
		entity_key=?,
		field_name=?,
		old_value=?,
		new_value=?,
		change_time=?,
		change_user=?,
		change_ip=?',
		{},
		($entity,
		$$data{$tree->{entities}->{$$requestObject{'entity'}}->{key}},
		'record',   #field
		'', #old val
		'CREATED',  # new val
		$$now[0],
		$requestObject->{'user'}->{'username'},  # user
		$$requestObject{'ip_address'}  # ip
		)
	);

	# run sql
	$logger->debug("executing: $sql with " . join(',',@$parms) ) if ($logger->is_debug());
	my $rv=$sth->execute(@$parms);
	#return error if db insert had errors 
	if($sth->err)
	{
		$logger->error($sth->err . " : " . $sth->errstr );
		$$requestObject{'stat'}=Apache2::Const::HTTP_INTERNAL_SERVER_ERROR;	
		return $sth->err . " : " . $sth->errstr;		
	}
	$$requestObject{'headers_out'}=['Location',"/cmdb_api/v1/" . $entity . "/" . $$data{$tree->{entities}->{$$requestObject{'entity'}}->{key}}];
	return;
}

sub doAclDELETE {
   doGenericDELETE(@_);
}

sub doAclGET {
   doGenericGET(@_);
}

sub doAclPOST {
	my ($sql);
	my $requestObject=shift;
	my $entity=$$requestObject{'entity'};
	$logger->info("processing POST");
	my (@sql,$parms);
	my $data=&eat_json($$requestObject{'body'},{allow_nonref=>1});

	if($$data{'logic'})
	{
		my $r = { };
		my $f = '';
		my $req = $requestObject;
		my $changes = {};
		eval($$data{'logic'});
		if($@)
		{
			$$requestObject{'stat'}=Apache2::Const::HTTP_INTERNAL_SERVER_ERROR;
			return "Syntax error in ACL logic: $@";
		}
	}

	foreach my $f (@{&getFieldList($$requestObject{'entity'})})
	{
		if(exists $$data{$f})
		{
			$$data{$f}=&doFieldNormalization($entity,$f,$$data{$f});
			push(@$parms,$$data{$f});
			push(@sql,"$f=?")
		}
	}
	my $sql_set=join(',',@sql);	
	$sql="insert into $entity set $sql_set";
	my $sth=$dbh->prepare($sql);
	if($sth->err)
	{
		$logger->error($sth->err . " : " . $sth->errstr);
		$$requestObject{'stat'}=Apache2::Const::HTTP_INTERNAL_SERVER_ERROR;	
		return $sth->err . " : " . $sth->errstr;
	}
	$logger->debug("executing: $sql with " . join(',',@$parms) ) if ($logger->is_debug());
	my $rv=$sth->execute(@$parms);
	if($sth->err)
	{
		$logger->error($sth->err . " : " . $sth->errstr );
		$$requestObject{'stat'}=Apache2::Const::HTTP_INTERNAL_SERVER_ERROR;	
		return $sth->err . " : " . $sth->errstr;		
	}
	$$requestObject{'headers_out'}=['Location',"/cmdb_api/v1/acl/" . $$data{'acl_id'}];
	return;


}

sub doAclPUT {
	my ($sql);
	my $requestObject=shift;
	my $entity=$$requestObject{'entity'};
	$logger->info("processing PUT");
	my $dbs=DBI->connect("DBI:$DRIVER:database=$DATABASE;host=$DBHOST",$DBUSER,$DBPASS,{AutoCommit=>1});
	$dbs->begin_work;
	my (@sql,$parms,@errors);
	my $data=&eat_json($$requestObject{'body'},{allow_nonref=>1});	
	#audit fetch record to comparison during audit
	my $now=$dbh->selectcol_arrayref('select now()');
	my @entity_fields=@{&getFieldList($$requestObject{'entity'})};
	my $lkup_data=&doGenericGET($requestObject);
	if($$lkup_data{'metaData'})
	{
		$lkup_data=$$lkup_data{'records'}[0]
	}
	elsif(ref $lkup_data eq 'ARRAYREF')
	{
		$lkup_data=$$lkup_data[0];
	}
	
	# strip out unchanged data and trigger mtime if needed
	my $mtime;
	foreach(@entity_fields)
	{
		$$data{$_}=&doFieldNormalization($entity,$_,$$data{$_}) if exists $$data{$_};
		$mtime= $$now[0] if(exists $$data{$_} && !$tree_extended->{entities}->{'system'}->{$_}->{meta} );
		delete $$data{$_} if(exists $$data{$_} && exists $$lkup_data{$_} && $$data{$_} eq $$lkup_data{$_});
	}
	my $blocked_changes={};
	&runACL($requestObject,$lkup_data,$entity,$data,$blocked_changes);

	# If the change is otherwise acceptable, and we are changing the logic,
	# verify syntax
	if($$data{'logic'})
	{
		my $r = { };
		my $f = '';
                my $req = $requestObject;
                my $changes = {};
		eval($$data{'logic'});
		if($@)
		{
			$dbs->rollback;
			$$requestObject{'stat'}=Apache2::Const::HTTP_INTERNAL_SERVER_ERROR;
			return "Syntax error in ACL logic: $@"
		}
	}

	# if the user is not a system user, then error out now if needed
	$logger->info("changes: " . &make_json($data) );
	$logger->info("blocked changes: " . &make_json($blocked_changes) );
	if($requestObject->{'user'}->{'systemuser'} ne '1' && scalar(keys(%$blocked_changes)))
	{
		$dbs->rollback;
		$$requestObject{'stat'}=Apache2::Const::HTTP_INTERNAL_SERVER_ERROR;
		return 'ACL blocked change: ' . &make_json($blocked_changes);
	}
	if(scalar(keys(%$blocked_changes)))
	{
		my $change_item={
			change_ip=>$$requestObject{'ip_address'},
			change_user=>$requestObject->{'user'}->{'username'},
			change_time=>$$now[0],
			entity=>$$requestObject{'entity'},
			entity_key=>$$lkup_data{$tree->{'entities'}->{$$requestObject{'entity'}}->{'key'}},
			change_content=>&make_json($blocked_changes)
		};
		&doGenericPOST({
			entity=>'change_queue',
			body=>&make_json($change_item),	
		});
		$logger->info("queued change");
		return "Change queued for approval";
	}

	foreach my $f (@entity_fields)
	{
		if(exists $$data{$f})
		{
			if($$data{$f} eq '')
			{			
				push(@$parms,undef);
			}
			else
			{
				push(@$parms,$$data{$f});
			}
			
			push(@sql,"$f=?");
			#audit  check each field and record change if done
			if($$data{$f} ne $$lkup_data{$f})
			{
				$dbs->do('insert into inv_audit set 
					entity_name=?, 
					entity_key=?,
					field_name=?,
					old_value=?,
					new_value=?,
					change_time=?,
					change_user=?,
					change_ip=?',
					{},
					($entity,
					$$lkup_data{$tree->{entities}->{$$requestObject{'entity'}}->{key}},
					$f,   #field
					$$lkup_data{$f}, #old val
					$$data{$f},  # new val
					$$now[0],
					$requestObject->{'user'}->{'username'},  # user
					$$requestObject{'ip_address'}  # ip
					)
				);
			}			
		}
	}
	my $sql_set=join(',',@sql);
	# assemple final sql
	$sql="update $entity set $sql_set where " . $tree->{entities}->{$entity}->{key} . "=?";
	push(@$parms,$$requestObject{'path'}[0]);
	
	## do sql and record any errors
	my $sth=$dbs->prepare($sql);
	if ($sth->err)
	{
		push(@errors,$dbs->err . ": " . $dbs->errstr);
		$logger->error($sth->err . " : " . $sth->errstr);
	}
	$logger->debug("executing: $sql with " . join(',',@$parms)) if ($logger->is_debug());
	my $rv=$sth->execute(@$parms);
	if ($sth->err)
	{
		push(@errors,$dbs->err . ": " . $dbs->errstr);
		$logger->error($sth->err . " : " . $sth->errstr);
	}

	if(scalar(@errors))
	{
		$dbs->rollback;
		$$requestObject{'stat'}=Apache2::Const::HTTP_INTERNAL_SERVER_ERROR;
		return \@errors;
	}
	else
	{
		$dbs->commit;
	}
	return;
}

sub doChangeQueuePOST()
{
	doGenericPOST(@_);
}
sub doChangeQueuePUT()
{
	doGenericPUT(@_);
}
sub doChangeQueueDELETE
{
	doGenericDELETE(@_);
}
#handles changequeue fetches
sub doChangeQueueGET()
{
	# for internal requests:
	# ro = { entity,  path[0]  query  }
	
	my ($keyval,$sql,$parms,$return);
	$logger->info("processing GET");
	my $requestObject=shift;
	# check to see if this entity requires special processing, otherwise handle with generic
	# assemble sql based on input parameters
	$sql="select * from change_queue ch left join device d on ch.entity_key=d.fqdn where ";

	# check for path key value and add if specified
	if($$requestObject{'path'}[0])
	{
		$logger->debug("found $tree->{entities}->{$$requestObject{'entity'}}->{key} : $$requestObject{'path'}[0] in url") if ($logger->is_debug());
		$sql.=" $tree->{entities}->{$$requestObject{'entity'}}->{key} like ?";
		push(@$parms,$$requestObject{'path'}[0]);
	}
	$logger->debug("getparms: $$requestObject{getparams}") if ($logger->is_debug());
	my $device_fields=&getFieldList('device',0);
	my $change_fields=&getFieldList('change_queue',0);
	if($$requestObject{getparams}) {
		my @ranges=split(/[&;]/, $$requestObject{getparams});
		foreach my $range (@ranges) {
			next unless $range =~ /(\w+)([!~>=<]+)(.+)/;
			my $key = $1;
			my $op = $2;
			my $val = $3;
            next if $key =~ /^_/;
			next unless (grep(/^$key$/,@$device_fields) || grep(/^$key$/,@$change_fields));
			$val =~ s/'/%/g;
			$op = 'LIKE' if $op eq '=';
			$op = 'NOT LIKE' if $op eq '!=';
			$op = 'RLIKE' if $op eq '~';
			$op = 'NOT RLIKE' if $op eq '!~';
			$logger->debug("Found param: $key $op $val") if ($logger->is_debug());
			$val =~ s/\*/%/g;
			$sql.=" and " if($sql!~/where\ $/);
			$sql.= grep(/^$key$/,@$device_fields) ? " d." : " ch.";
			$sql.="$key $op '$val'";
		
		}
	}
	$sql=~s/where\ // if($sql=~/where\ $/);
	my $rtn= &recordFetch($requestObject,$sql,$parms);
	
	if(ref $rtn eq 'HASH' && defined $rtn->{metaData} && defined $rtn->{metaData}->{fields})
	{
		push(@{$rtn->{metaData}->{fields}},@$device_fields);
	}
	return $rtn;
}

#handles generic fetches
sub doGenericGET()
{
	# for internal requests:
	# ro = { entity,  path[0]  query  }
	
	my ($keyval,$sql,$parms,$return);
	$logger->info("processing GET");
	my $requestObject=shift;
	# check to see if this entity requires special processing, otherwise handle with generic
	# assemble sql based on input parameters
	$sql="select * from $$requestObject{'entity'} where ";

	# check for path key value and add if specified
	if($$requestObject{'path'}[0])
	{
		$logger->debug("found $tree->{entities}->{$$requestObject{'entity'}}->{key} : $$requestObject{'path'}[0] in url") if ($logger->is_debug());
		$sql.=" $tree->{entities}->{$$requestObject{'entity'}}->{key} like ?";
		push(@$parms,$$requestObject{'path'}[0]);
	}
	elsif($$requestObject{getparams}) {
		my @ranges=split(/[&;]/, $$requestObject{getparams});
		foreach my $range (@ranges) {
			next unless $range =~ /(\w+)([!~>=<]+)(.+)/;
			my $key = $1;
			my $op = $2;
			my $val = $3;
            next if $key =~ /^_/;
			$val =~ s/'//g;
			$op = 'LIKE' if $op eq '=';
			$op = 'NOT LIKE' if $op eq '!=';
			$op = 'RLIKE' if $op eq '~';
			$op = 'NOT RLIKE' if $op eq '!~';
			$logger->debug("Found param: $key $op $val") if ($logger->is_debug());
			$val =~ s/\*/%/g;
			$sql.=" and " if($sql!~/where\ $/);
			$sql.=" $key $op '$val'";
		
		}
	}
	$sql=~s/where\ // if($sql=~/where\ $/);
	my $rec=&recordFetch($requestObject,$sql,$parms);
	if(!$rec)
	{
		$$requestObject{'stat'}=Apache2::Const::HTTP_NOT_FOUND;
		return;
	}
	else
	{
		return $rec;
	}
}

sub doGenericDELETE
{
	my $requestObject=shift;
	my $entity=$$requestObject{'entity'};
	my ($sql,$parms);
	# continue if entity key segment of the path is there
	if($requestObject->{'path'}[0])
	{
		my $lkup_data=&doGenericGET($requestObject);
		if(!defined $lkup_data)
		{
			$$requestObject{'stat'}=Apache2::Const::HTTP_NOT_FOUND;
			return;
		}
		if($$lkup_data{'metaData'})
		{
			$lkup_data=$$lkup_data{'records'}[0]
		}
		elsif(ref $lkup_data eq 'ARRAYREF')
		{
			$lkup_data=$$lkup_data[0];
		}
		my $blocked_changes={};
		&runACL($requestObject,$lkup_data,$entity,{},$blocked_changes);
		# if the user is not a system user, then error out now if needed
		$logger->info("blocked DELETE operation: " . &make_json($blocked_changes) );
		if($requestObject->{'user'}->{'systemuser'} ne '1' && scalar(keys(%$blocked_changes)))
		{
			$dbh->rollback;
			$$requestObject{'stat'}=Apache2::Const::HTTP_FORBIDDEN;
			return 'ACL blocked Delete: ' . &make_json($blocked_changes);
		}
	
		$sql="delete from $requestObject->{'entity'} where $tree_extended->{entities}->{ $requestObject->{'entity'} }->{'key'} = ?";
		$parms=[ $requestObject->{'path'}[0] ];
		$dbh->do($sql,{},@$parms); 
		if($dbh->err)
		{
			$logger->error("sql: $sql with " . join(',',@$parms) );
			$logger->error($dbh->err . " : " . $dbh->errstr ) if ($dbh->err);
			$$requestObject{'stat'}=Apache2::Const::HTTP_INTERNAL_SERVER_ERROR;
		}
		else
		{
			$dbh->do('insert into inv_audit set 
				entity_name=?, 
				entity_key=?,
				field_name=?,
				old_value=?,
				new_value=?,
				change_time=now(),
				change_user=?,
				change_ip=?',
				{},
				($requestObject->{'entity'},
				$requestObject->{'path'}[0],
				'record',   #field
				substr(make_json($lkup_data),0,100). '...', #old val
				'DELETED',  # new val
				$requestObject->{'user'}->{'username'},  # user
				$requestObject->{'ip_address'}  # ip
				)
			);
		}
		
	}
	
}

sub parseQueryParams
{
	my ($data, $getparams, $valid_fields) = @_;

        my @ranges=split(/[&;]/, $data);
        foreach my $range (@ranges) {
#			next unless $range =~ /(\w+)([!~>=<]+)(.+)/;
			next unless $range =~ /(\w+)([!~>=<]+)(.*)/;
            my $key = $1;
            my $op = $2;
            my $val = $3;
            next if $key =~ /^_/;
			next unless (grep(/^$key$/,@$valid_fields));
            $val =~ s/'//g;
			$op = 'LIKE' if $op eq '=';
			$op = 'NOT LIKE' if $op eq '!=';
			$op = 'RLIKE' if $op eq '~';
			$op = 'NOT RLIKE' if $op eq '!~';
            $logger->debug("Found param: $key $op $val") if ($logger->is_debug());
			$$getparams{$key}{op}=$op;
			$$getparams{$key}{val}=$val;
	}

	return $getparams;
}

sub doEnvironmentsServicesGET() {
	my $requestObject=shift;
	my $environment;
	my $service;
	my @parents;
	my @params;
	my %getparams;
	my %hash;
	my $environment_tag;

	$environment = $requestObject->{'path'}[0];
	$service = $requestObject->{'path'}[2];

	my $sql = "select name, environment_name from environments";

	my $rtn = &doSql($sql, undef);
	if ($$rtn{'err'}) {
		$$requestObject{'stat'}=Apache2::Const::HTTP_INTERNAL_SERVER_ERROR;
		return $$rtn{'err'} . " : " . $$rtn{'errstr'};
	}

	if ($requestObject->{'getparams'}) {
		@params = split(/[&;]/, $requestObject->{'getparams'});
		parseQueryParams($requestObject->{'getparams'}, \%getparams,
		                 [ 'type', 'name' ]);
	}

	$environment_tag = 1 if defined $requestObject->{'query'}->{'_tag_environment'};

	for my $env (@{$rtn->{'data'}}) {
		my $parent = $env->{'environment_name'};
		my $name = $env->{'name'};

		if ($parent eq $name) {
			$parent = undef;
		}

		$hash{$name} = $parent;
	}

	$parents[0] = $environment;
	while (defined $parents[-1]) {
		push @parents, $hash{$parents[-1]};
	}
	pop @parents;

	%hash = ();
	my $list = join(', ', map { "'$_'" } @parents);
	$sql = "select name, environment_name, note,  s.svc_id, type, data_key, data_value from " .
	       " (select name, environment_name, note,  svc_id, type from service_instance " .
	       "  where type != 'environment' ";

	if (defined $service) {
		$sql .= "and name like '$service' ";
	}
	
	for my $key (keys %getparams) {
		$sql .= sprintf "and %s %s '%s' ",
			$key,
			$getparams{$key}{op},
			$getparams{$key}{val};
	}

	$sql .= "and environment_name in ($list)) as s " .
	        "left join service_instance_data as d on s.svc_id = d.svc_id " .
	        "order by field(environment_name, $list)";

	$rtn = &doSql($sql, undef);
	if ($$rtn{'err'}) {
		$$requestObject{'stat'}=Apache2::Const::HTTP_INTERNAL_SERVER_ERROR;
		return $$rtn{'err'} . " : " . $$rtn{'errstr'};
	}

	for my $data (@{$rtn->{'data'}}) {
		if (not exists $hash{$data->{'name'}}) {
			$hash{$data->{'name'}} = {
						  name => $data->{'name'},
						  environment_name => $data->{'environment_name'},
						  type => $data->{'type'},
						  svc_id => $data->{'svc_id'},
						  note => $data->{'note'},
						  };
		}

		my $svc = $hash{$data->{'name'}};
		my $key = $data->{'data_key'};
		my $value = $data->{'data_value'};
	 	next if ((not defined $key) || exists $svc->{$key});

		if ($environment_tag) {
			$svc->{$key} = { value => $value,
					 environment_name =>
					$data->{'environment_name'} };
		} else {
			$svc->{$key} = $value;
		}
	}

	if (scalar(keys %hash) == 1) {
		return (values %hash)[0];
	} elsif (keys %hash) {
		return [values %hash];
	} else {
		$$requestObject{'stat'}=Apache2::Const::HTTP_NOT_FOUND;
		return;
	}
}

sub insertAuditEntry {
	my ($dbh, $requestObject, $entity, $key,
	    $name, $old, $new, $time) = @_;

	my $sql = 'insert into inv_audit set
		entity_name=?,
		entity_key=?,
		field_name=?,
		old_value=?,
		new_value=?,
		change_time=?,
		change_user=?,
		change_ip=?';

	$dbh->do($sql, {}, ($entity, $key, $name,
			    $old, $new, $time,
			    $requestObject->{user}->{username},
			    $$requestObject{ip_address}));
}

sub executeDbStatement {
	my ($sth, $sql, @parms) = @_;

	if ($logger->is_debug()) {
		my $msg;

		if (@parms) {
			$msg = "executing: $sql with " . join(',', @parms);
		} else {
			$msg = "executing: $sql"
		}

		$logger->debug($msg);
	}

	return $sth->execute(@parms);
}

sub doEnvironmentsServicesPUT(){
	my $requestObject=shift;
	$logger->info("processing PUT");
	my $dbh=DBI->connect("DBI:$DRIVER:database=$DATABASE;host=$DBHOST",
			     $DBUSER,$DBPASS,{AutoCommit=>0,RaiseError=>1});
	my $environment = $requestObject->{'path'}[0];
	my $service = $requestObject->{'path'}[2];
	my $data=&eat_json($$requestObject{'body'},{allow_nonref=>1});
	my $blocked_changes={};
	my $svc_id;
	my $sth;
	my $lkup_data;
	my @inserts;
	my @updates;
	my @deletes;
	my %service_updates;
	my %service_attributes;
	my $sql;
	my $error;
	my $old_value;
	my $new_value;
	my $did_update;

	eval {
		# Get service_instance record for the requested service
		$sql = "select svc_id,type,name,environment_name,note from service_instance where environment_name=? and name=? and type!='environment'";
		$sth = $dbh->prepare($sql);
		executeDbStatement($sth, $sql, $environment, $service);
		$lkup_data = $sth->fetchall_arrayref({}, undef);

		if ($sth->rows == 0) {
			$$requestObject{'stat'}=Apache2::Const::HTTP_NOT_FOUND;
			$dbh->rollback;
			$error = 'There is no resource at this location';
			return;
		} elsif ($sth->rows > 1) {
			$$requestObject{'stat'} = Apache2::Const::HTTP_INTERNAL_SERVER_ERROR;
			$dbh->rollback;
			$error = 'Multiple services with the same ID';
			return;
		}

		$old_value = &doEnvironmentsServicesGET($requestObject);

		&runACL($requestObject,{},'services',$data,$blocked_changes);
		# if the user is not a system user, then error out now if needed
		$logger->info("blocked PUT fields: " . &make_json($blocked_changes) );
		my $now=$dbh->selectcol_arrayref('select now()');
		if ($requestObject->{'user'}->{'systemuser'} ne '1' &&
		    scalar(keys(%$blocked_changes))) {
			$$requestObject{'stat'}=Apache2::Const::HTTP_FORBIDDEN;
			$dbh->rollback;
			$error = 'ACL blocked change: ' . &make_json($blocked_changes);
			return;
		}

		$lkup_data = $$lkup_data[0];
		$svc_id = $lkup_data->{'svc_id'};

		# Determine if we need to modify any fields of the service instance record


		my $fieldlist = &getFieldList('service_instance');
		for my $f (@{$fieldlist}) {
			my $value = $lkup_data->{$f};
			if (defined $data->{$f} && $value ne $data->{$f}) {
				$service_updates{$f} = [ $value, $data->{$f} ];
			}

			delete $data->{$f}; #ICK
		}
		delete $data->{'svc_id'}; #ICK

		# Get all service_instance_data records that belong to this instance
		# We don't care about inheritance for this
		$sql = "select data_id,data_key,data_value " .
		  "from service_instance_data where svc_id=?";
		$sth = $dbh->prepare($sql);
		executeDbStatement($sth, $sql, $svc_id);
		$lkup_data = $sth->fetchall_arrayref({}, undef);

		#populate lookup data into a structure of the service_instance for reference
		for my $row (@$lkup_data) {
			$service_attributes{$row->{'data_key'}} =
			  [ $row->{'data_value'}, $row->{'data_id'} ];
		}

		my $field_list=&getFieldList('service_instance');
		for my $key (keys %$data) {
			#skip if a native service_instance field
			if(grep(/^$key$/,@$field_list)){
				next;
			}
			if (exists $service_attributes{$key}) {
				if (not defined $data->{$key}) {
					push @deletes, $key;
				} elsif ($service_attributes{$key}[0] ne
					 $data->{$key}) {
					push @updates, $key;
				}
			} else {
				push @inserts, $key;
			}
		}


		if (keys %service_updates) {
			my $sql_set;
			my @parms;

			$sql_set = join(', ', map { "$_=?" } keys %service_updates);
			for my $key (keys %service_updates) {
				push @parms, $service_updates{$key}[1];
			}
			push @parms, $svc_id;

			$sql="update service_instance set $sql_set";
			$sql .= " where svc_id=?";

			$sth = $dbh->prepare($sql);
			executeDbStatement($sth, $sql, @parms);
			$did_update = 1;
		}

		if (@inserts) {
			# Create any new service_instance_data records
			$sql = "insert into service_instance_data " .
			  "(data_key, data_value, svc_id) values ";
			$sql .= join(',', map {sprintf("('%s','%s','%s')",
		                     $_, $data->{$_}, $svc_id)} @inserts);

			$sth = $dbh->prepare($sql);
			executeDbStatement($sth, $sql);
			$did_update = 1;
		}

		if (@updates) {
			# Modify existing service_instance_data records
			$sql = "update service_instance_data set " .
			  "data_value=? where data_key=? and svc_id=?";
			$sth = $dbh->prepare($sql);


			for my $key (@updates) {
				executeDbStatement($sth, $sql, $data->{$key}, $key, $svc_id);
			}
			$did_update = 1;
		}

		if (@deletes) {
			$sql = "delete from service_instance_data where " .
			  "svc_id=? and data_key in ";
			$sql .= '(' . join(',', map { "'$_'" } @deletes) . ')';
			$sth = $dbh->prepare($sql);

			executeDbStatement($sth, $sql, $svc_id);
			$did_update = 1;
		}

		$dbh->commit;

		$new_value = &doEnvironmentsServicesGET($requestObject);
		if ($did_update) {
			insertAuditEntry($dbh, $requestObject, 'services',
					"$environment/$service", 'record',
			                make_json($old_value),
			                make_json($new_value),
					$$now[0]);
			$dbh->commit;
		}
	};
	  if ($@) {
		  my $errstr;

		  if (defined $sth && $sth->err) {
			  $errstr = $sth->err . " : " . $sth->errstr;
			  $logger->error($errstr);
		  } else {
			  $errstr = $@;
		  }

		  $$requestObject{'stat'} =
		    Apache2::Const::HTTP_INTERNAL_SERVER_ERROR;

		  eval { $dbh->rollback; };

		  $error = $errstr;
	  }

	if (defined $error) {
		return $error;
	} else {
		return $new_value;
	}
}

sub doEnvironmentsServicesPOST(){
	my $requestObject=shift;
	$logger->info("processing POST");
	my $dbh=DBI->connect("DBI:$DRIVER:database=$DATABASE;host=$DBHOST",
			     $DBUSER,$DBPASS,{AutoCommit=>0,RaiseError=>1});
	my $environment = $requestObject->{'path'}[0];
	my $service = $requestObject->{'path'}[2];
	my $data=&eat_json($$requestObject{'body'},{allow_nonref=>1});
	my $blocked_changes={};
	my $svc_id;
	my $sth;
	my $lkup_data;
	my %service_updates;
	my %service_attributes;
	my $sql;
	my $error;

	# FIXME: should this be how we handle this?  No point in specifying either
	# of these attributes in the request.
	delete $data->{svc_id};
	$data->{name} = $service;
	$data->{'environment_name'} = $environment;

	if (not defined $service) {
		# FIXME: what's the best way to handle this? Is this the correct
		# status code
		$$requestObject{'stat'} = Apache2::Const::HTTP_NOT_ACCEPTABLE;
		return 'Service name required';
	}

	eval {
		# Get service_instance record for the requested service
		$sql = "select svc_id from service_instance where environment_name=? and name=?";
		$sth = $dbh->prepare($sql);
		executeDbStatement($sth, $sql, $environment, $service);
		$lkup_data = $sth->fetchall_arrayref({}, undef);

		if ($sth->rows) {
			# FIXME: what's the best way to handle this? should we be able to
			# turn a POST into a PUT?  Is this the correct status code to use?
			$dbh->rollback;
			$$requestObject{'stat'} = Apache2::Const::HTTP_INTERNAL_SERVER_ERROR;
			$error = 'Service already exists';
			return;
		}

		&runACL($requestObject,{},'services',$data,$blocked_changes);
		# if the user is not a system user, then error out now if needed
		$logger->info("blocked PUT fields: " . &make_json($blocked_changes) );
		my $now=$dbh->selectcol_arrayref('select now()');
		if ($requestObject->{'user'}->{'systemuser'} ne '1' &&
		    scalar(keys(%$blocked_changes))) {
			$$requestObject{'stat'}=Apache2::Const::HTTP_FORBIDDEN;
			$dbh->rollback;
			return 'ACL blocked change: ' . &make_json($blocked_changes);
		}

		my @columns;
		my @values;

		for my $field (qw/name environment_name type notes/) {
			if (defined $data->{$field}) {
				push @columns, $field;
				push @values, $data->{$field};
				delete $data->{$field};
			}
		}

		# Create service_instance record
		$sql = sprintf("insert into service_instance (%s) values (%s)",
			       join(', ', @columns), join(', ', map { "'$_'" } @values));
		$sth = $dbh->prepare($sql);
		executeDbStatement($sth, $sql);
		$svc_id = $sth->{mysql_insertid};

		# Create service_instance_data records
		$sql = "insert into service_instance_data " .
		  "(svc_id, data_key, data_value) values ";

		
		$sql .= join(',', map {sprintf("('%s','%s','%s')",
					       $svc_id, $_, $data->{$_})} keys %$data);

		$sth = $dbh->prepare($sql);
		executeDbStatement($sth, $sql);

		insertAuditEntry($dbh, $requestObject, 'services', "$environment/$service",
				 'record', '', 'CREATED', $$now[0]);
		$dbh->commit;
	};
	if ($@) {
		my $errstr;

		if ($sth->err) {
			$errstr = $sth->err . " : " . $sth->errstr;
			$logger->error($errstr);
		} else {
			$errstr = $@;
		}

		$$requestObject{'stat'} =
		  Apache2::Const::HTTP_INTERNAL_SERVER_ERROR;

		eval { $dbh->rollback; };

		return $errstr;
	}


	return $error if (defined $error);

	$$requestObject{'headers_out'}=['Location',"/cmndb_api/v1/environments/" .
					$environment . "/services/" .
					$service];
	return;
}

sub doEnvironmentsServicesDELETE(){
	my $requestObject=shift;
	$logger->info("processing DELETE");
	my $dbh=DBI->connect("DBI:$DRIVER:database=$DATABASE;host=$DBHOST",
			     $DBUSER,$DBPASS,{AutoCommit=>0,RaiseError=>1});
	my $environment = $requestObject->{'path'}[0];
	my $service = $requestObject->{'path'}[2];
	my $blocked_changes={};
	my $svc_id;
	my $sth;
	my $lkup_data;
	my %service_updates;
	my %service_attributes;
	my $sql;
	my $error;
	my $old_value;

	eval {
		# Get service_instance record for the requested service
		$sql = "select svc_id from service_instance where environment_name=? and name=?";
		$sth = $dbh->prepare($sql);
		executeDbStatement($sth, $sql, $environment, $service);
		$lkup_data = $sth->fetchall_arrayref({}, undef);


		if ($sth->rows == 0) {
			# FIXME: what's the best way to handle this? should we be able to
			# turn a POST into a PUT?  Is this the correct status code to use?
			$$requestObject{'stat'} = Apache2::Const::HTTP_NOT_FOUND;
			$dbh->rollback;
			$error = 'There is no resource at this location';
			return;
		}

		$svc_id = $$lkup_data[0]->{'svc_id'};

		&runACL($requestObject,$lkup_data,'services',{},$blocked_changes);
		# if the user is not a system user, then error out now if needed
		$logger->info("blocked DELETE operation: " . &make_json($blocked_changes) );
		if ($requestObject->{'user'}->{'systemuser'} ne '1' &&
		    scalar(keys(%$blocked_changes))) {
			$$requestObject{'stat'}=Apache2::Const::HTTP_FORBIDDEN;
			$dbh->rollback;
			$error = 'ACL blocked Delete: ' . &make_json($blocked_changes);
			return;
		}
		my $now=$dbh->selectcol_arrayref('select now()');

		$old_value = &doEnvironmentsServicesGET($requestObject);

		$sql = "delete from service_instance where svc_id=?";
		$sth = $dbh->prepare($sql);
		executeDbStatement($sth, $sql, $svc_id);

		insertAuditEntry($dbh, $requestObject, 'services',
				 "$environment/$service",
				 'record',
				 make_json($old_value),
				 'DELETED', $$now[0]);
		$dbh->commit;
	};
	if ($@) {
		my $errstr;

		if ($sth->err) {
			$errstr = $sth->err . " : " . $sth->errstr;
			$logger->error($errstr);
		} else {
			$errstr = $@;
		}

		$$requestObject{'stat'} =
		  Apache2::Const::HTTP_INTERNAL_SERVER_ERROR;

		eval { $dbh->rollback; };

		$error = $errstr;
	}

	if (defined $error) {
		return $error;
	} else {
		return;
	}
}

sub doEnvironmentsGET(){
	my $requestObject=shift;
	my @path = @{$requestObject->{'path'}};
	my @parms;
	my $environment;
	my $service;
	my $get_services = 0;

	if ($path[1] eq 'services') {
		return &doEnvironmentsServicesGET($requestObject);
	} elsif ($path[1]) {
		$$requestObject{'stat'}=Apache2::Const::HTTP_NOT_FOUND;
	} else {
		return &doGenericGET($requestObject);
	}
}

sub doEnvironmentsPUT(){
	my $requestObject=shift;
	my @path = @{$requestObject->{'path'}};
	my @parms;
	my $environment;
	my $service;
	my $get_services = 0;

	$environment = $path[0];
	$service = $path[2];

	if ($path[1] eq 'services') {
		if (defined $service) {
			return &doEnvironmentsServicesPUT($requestObject);
		} else {
			$$requestObject{'stat'}=Apache2::Const::HTTP_METHOD_NOT_ALLOWED;
		}
	} elsif ($path[1]) {
		$$requestObject{'stat'}=Apache2::Const::HTTP_NOT_FOUND;
	} else {
		return &doGenericPUT($requestObject);
	}
}

sub doEnvironmentsPOST(){
	my $requestObject=shift;
	my @path = @{$requestObject->{'path'}};
	my @parms;
	my $get_services = 0;

	my $environment = $path[0];
	my $service = $path[2];


	if ($path[1] eq 'services') {
		return &doEnvironmentsServicesPOST($requestObject);
	} elsif ($path[1]) {
		$$requestObject{'stat'}=Apache2::Const::HTTP_NOT_FOUND;
	} else {
		return &doGenericPOST($requestObject);
	}
}

sub doEnvironmentsDELETE(){
	my $requestObject=shift;
	my @path = @{$requestObject->{'path'}};
	my @parms;
	my $get_services = 0;

	my $environment = $path[0];
	my $service = $path[2];

	if ($path[1] eq 'services') {
		if (defined $service) {
			return &doEnvironmentsServicesDELETE($requestObject);
		} else {
			$$requestObject{'stat'}=Apache2::Const::HTTP_METHOD_NOT_ALLOWED;
		}
	} elsif ($path[1]) {
		$$requestObject{'stat'}=Apache2::Const::HTTP_NOT_FOUND;
	} else {
		return &doGenericDELETE($requestObject);
	}
}

# special functions to handle device and systems
sub doSystemGET(){
	my $requestObject=shift;
	my $x=0;
	my $device_fields=&getFieldList('device',1);
	my $meta_fields=&getFieldList($$requestObject{'entity'},1);
	my ($field_sql,$join_sql,$sql,$where_sql,$parms);
	if($$requestObject{'path'}[0])
	{
		$where_sql=' d.fqdn=?';
		push(@$parms,$$requestObject{'path'}[0]);
	}
	my %getparams;
	# parse custom URL query options ( for allowing ` ! etc...)
    if($$requestObject{getparams}) {
        my @ranges=split(/[&;]/, $$requestObject{getparams});
        foreach my $range (@ranges) {
#			next unless $range =~ /(\w+)([!~>=<]+)(.+)/;
			next unless $range =~ /(\w+)([!~>=<]+)(.*)/;
            my $key = $1;
            my $op = $2;
            my $val = $3;
            next if $key =~ /^_/;
			next unless (grep(/^$key$/,@$device_fields) || grep(/^$key$/,@$meta_fields));
            $val =~ s/'//g;
			$op = 'LIKE' if $op eq '=';
			$op = 'NOT LIKE' if $op eq '!=';
			$op = 'RLIKE' if $op eq '~';
			$op = 'NOT RLIKE' if $op eq '!~';
            $logger->debug("Found param: $key $op $val") if ($logger->is_debug());
			$getparams{$key}{op}=$op;
			$getparams{$key}{val}=$val;
        }
    }
	foreach(@$device_fields)
	{
		$field_sql.="," if $field_sql;
		$field_sql.="d.$_";
		#if($$requestObject{'query'}{$_})
		if(defined $getparams{$_})
		{
			my $op = $getparams{$_}{op} ? $getparams{$_}{op} : 'LIKE';
			$where_sql.=" and " if $where_sql;
			if($getparams{$_}{val} eq '')
			{
				$where_sql.=" (d.$_ $op ?";
				$where_sql.=" OR d.$_";
				$where_sql.=$getparams{$_}{op} eq 'LIKE' ? " is null)"  : " is not null)";
			}
			else
			{
				$where_sql.=" d.$_ $op ?";
			}
			# my $var=$$requestObject{'query'}{$_};
			# $var=~s/\*/%/g;
			$getparams{$_}{val} =~ s/\*/%/g;
			#push(@$parms,$var);
			push(@$parms,$getparams{$_}{val});
		}
	}
	foreach(@$meta_fields)
	{
		$field_sql.="," if $field_sql;
		if($_ eq 'guest_fqdns') {
			my $host = $getparams{fqdn} ? $getparams{fqdn}{val} : $$requestObject{'path'}[0];
			$field_sql.=" (select group_concat(fqdn) as guest_fqdns from device_metadata where metadata_value=d.fqdn and metadata_name=\"host_fqdn\" group by \"all\") as $_";
		}	
		else {
			$field_sql.="m$x.metadata_value as $_";
			$join_sql.=" left join device_metadata m$x on d.fqdn=m$x.fqdn and m$x.metadata_name='$_'";
			# if($$requestObject{'query'}{$_})
			if(defined $getparams{$_})
			{
				my $op = $getparams{$_}{op} ? $getparams{$_}{op} : 'LIKE';
				$where_sql.=" and " if $where_sql;
				if($getparams{$_}{val} eq '')
				{
					$where_sql.=" ( m$x.metadata_value $op ?";
					$where_sql.=" OR m$x.metadata_value";
					$where_sql.=$getparams{$_}{op} eq 'LIKE' ? " is null)"  : " is not null)";
				}
				else
				{
					$where_sql.=" m$x.metadata_value $op ?";
				}
				# $where_sql.=" m$x.metadata_value like ?";
				# my $var=$$requestObject{'query'}{$_};
				# $var=~s/\*/%/g;
				# push(@$parms,$var);
				$getparams{$_}{val} =~ s/\*/%/g;
				push(@$parms,$getparams{$_}{val});
			}
		}
		$x++;
	}
	$field_sql.="," if $field_sql;
	$field_sql.= " count(ch.id) as changes ";
	$join_sql.=" left join change_queue ch on d.fqdn=ch.entity_key";

	#$sql="select $field_sql from device d $join_sql where $where_sql group by d.fqdn";
	$sql="select $field_sql from device d $join_sql ";
	$sql.="where $where_sql" if $where_sql; 
	$sql.=" group by d.fqdn";


	my $rec=&recordFetch($requestObject,$sql,$parms);
	if(!$rec)
	{
		$$requestObject{'stat'}=Apache2::Const::HTTP_NOT_FOUND;
		return;
	}
	else
	{
		return $rec;
	}
	
}

sub doSystemPUT(){
	my $requestObject=shift;
	my $dbs=DBI->connect("DBI:$DRIVER:database=$DATABASE;host=$DBHOST",$DBUSER,$DBPASS,{AutoCommit=>1});
	my $x=0;
	my $fqdn=$$requestObject{'path'}[0];
	my $data=&eat_json($$requestObject{'body'},{allow_nonref=>1});
	$logger->info("processing PUT data $$requestObject{'body'}");
	my $device_fields=&getFieldList('device',1);
	my $meta_fields=&getFieldList($$requestObject{'entity'},1);
	my ($sql,$set_sql,$parms,@errors,$rv);
	my $now=$dbh->selectcol_arrayref('select now()');
	my $lkup_data=&doSystemGET($requestObject);
	# Check to make sure the date modified/versiom of the record being submitted matches the 
	# the stored record. if the stored record is newer, return error
	if( defined $$data{'date_modified'} )
	{
				my $date_modified_submitted=ParseDate($$data{'date_modified'});
				my $date_modified_stored=ParseDate($$lkup_data{'date_modified'});
				if( Date_Cmp($date_modified_submitted,$date_modified_stored) != 0)
				{
					$$requestObject{'stat'}=Apache2::Const::HTTP_CONFLICT;
					$logger->debug("Modification date of submitted record ($$data{'date_modified'}) is old: $$lkup_data{'date_modified'}"  ) if ($logger->is_debug());
					return "stored record has already been modified";
				}
	}
	if($$lkup_data{'metaData'})
	{
		$lkup_data=$$lkup_data{'records'}[0]
	}
	elsif(ref $lkup_data eq 'ARRAYREF')
	{
		$lkup_data=$$lkup_data[0];
	}
	$dbs->begin_work;

	if(exists $$data{'agent_type'})
	{
		$$data{'agent_reported'}=$$now[0];
	}
	if(
			(
				$data->{$IPADDRESSFIELD}
				&& $data->{$IPADDRESSFIELD} ne $lkup_data->{$IPADDRESSFIELD}				
			)
			||
			( 
				!exists($data->{'data_center_code'}) 
				#&& defined($lkup_data->{'data_center_code'})
				&& length($lkup_data->{'data_center_code'})==0 
			) 
		)
	{
		if($data->{$IPADDRESSFIELD})
		{
			$data->{'data_center_code'}=&lookupDC($data->{$IPADDRESSFIELD});			
		}
		else
		{
			$data->{'data_center_code'}=&lookupDC($lkup_data->{$IPADDRESSFIELD});			
		}
	}

	# strip out unchanged data and trigger mtime if needed
	my $mtime;
	foreach(@$device_fields)
	{	
		$$data{$_}=&doFieldNormalization('system',$_,$$data{$_}) if exists $$data{$_};
		$mtime= $$now[0] if(exists $$data{$_} && !$tree_extended->{'entities'}->{'system'}->{$_}->{'meta'} );
		delete $$data{$_} if(defined $$data{$_} && defined $$lkup_data{$_} && $$data{$_} eq $$lkup_data{$_});
	}
	foreach(@$meta_fields)
	{
		$$data{$_}=&doFieldNormalization('system',$_,$$data{$_}) if exists $$data{$_};
		$mtime= $$now[0] if(exists $$data{$_} && !$tree_extended->{'entities'}->{'system'}->{$_}->{'meta'} );
		delete $$data{$_} if(defined $$data{$_} && defined $$lkup_data{$_} && $$data{$_} eq $$lkup_data{$_});
	}
	my $blocked_changes={};
	&runACL($requestObject,$lkup_data,'system',$data,$blocked_changes);
	# if the user is not a system user, then error out now if needed
	$logger->info("changes: " . &make_json($data));
	$logger->info("blocked changes: " . &make_json($blocked_changes) );
	if(defined($requestObject->{'user'}->{'systemuser'}) && $requestObject->{'user'}->{'systemuser'} ne '1' && scalar(keys(%$blocked_changes)))
	{
		$dbs->rollback;
		$$requestObject{'stat'}=Apache2::Const::HTTP_FORBIDDEN;
		return 'ACL blocked change: ' . &make_json($blocked_changes);
	}
	if(scalar(keys(%$blocked_changes)))
	{
		my $change_item={
			change_ip=>$$requestObject{'ip_address'},
			change_user=>$requestObject->{'user'}->{'username'},
			change_time=>$$now[0],
			entity=>$$requestObject{'entity'},
			entity_key=>$$lkup_data{$tree->{'entities'}->{$$requestObject{'entity'}}->{'key'}},
			change_content=>&make_json($blocked_changes)
		};
		&doGenericPOST({
			entity=>'change_queue',
			body=>&make_json($change_item),	
		});
		$logger->warn("queued change for " . $$lkup_data{$tree->{'entities'}->{$$requestObject{'entity'}}->{'key'}} );
	}
	
	# construct update sql for device table
	foreach(@$device_fields)
	{
		if(exists $$data{$_})
		{
			$set_sql.="," if $set_sql;
			if( defined($$data{$_}) && length($$data{$_})==0 )
			{	
				$set_sql.=" d.$_=NULL";		
				#push(@$parms,undef);
			}
			else
			{
				$set_sql.=" d.$_=?";
				push(@$parms,$$data{$_});
			}
			#audit
			if( !$tree_extended->{entities}->{'system'}->{$_}->{meta})
			{			
				$dbs->do('insert into inv_audit set 
					entity_name=?, 
					entity_key=?,
					field_name=?,
					old_value=?,
					new_value=?,
					change_time=?,
					change_user=?,
					change_ip=?',
					{},
					('device',
					$$lkup_data{$tree->{entities}->{$$requestObject{'entity'}}->{key}},
					$_,   #field
					$$lkup_data{$_}, #old val
					$$data{$_},  # new val
					$$now[0],
					$requestObject->{'user'}->{'username'},  # user
					$$requestObject{'ip_address'}  # ip
					)
				);
			}
		}
	}
	if($mtime)
	{
		$set_sql.="," if $set_sql;
		$set_sql.=" d.date_modified=?";
		push(@$parms,$mtime);
	}
	$sql="update device d set $set_sql where fqdn=?";
	push(@$parms,$fqdn);
	$logger->debug("doing sql: $sql with " . &make_json($parms) ) if ($logger->is_debug());
	$dbs->do($sql,{},@$parms) or push(@errors,$dbs->err . ": " . $dbs->errstr);
	if($dbs->err)
	{
		$logger->error($dbs->err . " : " . $dbs->errstr ) if ($dbs->err);
		$$requestObject{'stat'}=Apache2::Const::HTTP_INTERNAL_SERVER_ERROR;
		$dbs->rollback;
		return \@errors;		
	}
	
	## check for fqdn change and adjust internal fqdn var to reflect the new name
	if(exists $$data{'fqdn'} && $$lkup_data{'fqdn'} ne $$data{'fqdn'})
	{
		$fqdn=$$data{'fqdn'};
	}
	#update or insert into ip table
	#doUpdateIps($fqdn,$data);

	
	# do update or insert into device_metadata
	foreach(@$meta_fields)
	{
		if(exists $$data{$_})
		{	
			$$data{$_}=&doFieldNormalization('system',$_,$$data{$_});
			my $lkup=$dbs->selectrow_hashref("select fqdn from device_metadata where metadata_name=? and fqdn=?",{},($_,$fqdn));
			# if exists do update
			if($$lkup{'fqdn'})
			{
				$sql="update device_metadata set metadata_value=? where metadata_name=? and fqdn=?";
			}
			# otherwise insert into device_metadata
			else
			{
				$sql="insert into device_metadata set metadata_value=?,metadata_name=?,fqdn=?,date_created=now()";
			}
			@$parms=($$data{$_},$_,$fqdn);
			$logger->debug("doing sql: $sql  with " . join(',',@$parms) ) if ($logger->is_debug());
			$rv=$dbs->do($sql,{},@$parms) or push(@errors,$dbs->err . ": " . $dbs->errstr);
			if($dbs->err)
			{
				$logger->error($dbs->err . " : " . $dbs->errstr ) if ($dbs->err);
				$$requestObject{'stat'}=Apache2::Const::HTTP_INTERNAL_SERVER_ERROR;
			}
			#audit
			if( !$tree_extended->{entities}->{'system'}->{$_}->{meta})
			{
				$dbs->do('insert into inv_audit set 
					entity_name=?, 
					entity_key=?,
					field_name=?,
					old_value=?,
					new_value=?,
					change_time=?,
					change_user=?,
					change_ip=?',
					{},
					('device',
					$$lkup_data{$tree->{entities}->{$$requestObject{'entity'}}->{key}},
					$_,   #field
					$$lkup_data{$_}, #old val
					$$data{$_},  # new val
					$$now[0],
					$requestObject->{'user'}->{'username'},  # user
					$$requestObject{'ip_address'}  # ip
					)
				);
			}			
		}
	}
	if(scalar(@errors))
	{
		$dbs->rollback;
		$logger->error("error encountered " . scalar(@errors) . ":  " . &make_json(\@errors) );
		$$requestObject{'stat'}=Apache2::Const::HTTP_INTERNAL_SERVER_ERROR;
		return \@errors;
	}
	else
	{
		# $$requestObject{'stat'}=Apache2::Const::HTTP_NO_CONTENT;
		$dbs->commit;
		return &doSystemGET($requestObject);
	}
}
sub doSystemPOST(){
	my $requestObject=shift;
	my $dbs=DBI->connect("DBI:$DRIVER:database=$DATABASE;host=$DBHOST",$DBUSER,$DBPASS,{AutoCommit=>1});
	my $x=0;
	my $data=&eat_json($$requestObject{'body'},{allow_nonref=>1});
	my $fqdn=$$data{'fqdn'};
	$logger->info("processing POST data $$requestObject{'body'}");
	my $device_fields=&getFieldList('device',1);
	my $meta_fields=&getFieldList($$requestObject{'entity'},1);
	my ($sql,$set_sql,$parms,@errors,$rv);
	$data->{'inventory_component_type'} = 'system' unless $data->{'inventory_component_type'}; 
	if($data->{$IPADDRESSFIELD} && !$data->{'data_center_code'})
	{

		$data->{'data_center_code'}=&lookupDC($data->{$IPADDRESSFIELD});
	}
	$dbs->begin_work;
	# construct insert sql for device table
	foreach(@$device_fields)
	{
		next if $_ eq 'created_by';
		if(exists $$data{$_})
		{
			$$data{$_}=&doFieldNormalization('system',$_,$$data{$_});
			$set_sql.="," if $set_sql;
			if( length($$data{$_})==0 )
			{
			       $set_sql.=" $_=NULL";
			       #push(@$parms,undef);
			}
			else
			{
			       $set_sql.=" $_=?";
			       push(@$parms,$$data{$_});
			}
		}
	}
	$sql="insert into device set created_by='', $set_sql";
	$logger->debug("doing sql: $sql with " . join(',',@$parms) ) if ($logger->is_debug());
	$dbs->do($sql,{},@$parms) or push(@errors,$dbs->err . ": " . $dbs->errstr);
	if($dbs->err)
	{
		$logger->error($dbs->err . " : " . $dbs->errstr) if ($dbs->err);
		$$requestObject{'stat'}=Apache2::Const::HTTP_INTERNAL_SERVER_ERROR;
		$dbs->rollback;
		return \@errors;
	}
	#doUpdateIps($fqdn,$data);
	
	# do update or insert into device_metadata
	foreach(@$meta_fields)
	{
		if(exists $$data{$_})
		{	
			$$data{$_}=&doFieldNormalization('system',$_,$$data{$_}) if exists $$data{$_};
			$sql="insert into device_metadata set metadata_value=?,metadata_name=?,fqdn=?,date_created=now()";
			@$parms=($$data{$_},$_,$fqdn);
			$logger->debug("doing sql: $sql with " . join(',',@$parms) ) if ($logger->is_debug());
			$rv=$dbs->do($sql,{},@$parms) or push(@errors,$dbs->err . ": " . $dbs->errstr);
			if($dbs->err)
			{
				$logger->error($dbs->err . " : " . $dbs->errstr ) if ($dbs->err);
				$$requestObject{'stat'}=Apache2::Const::HTTP_INTERNAL_SERVER_ERROR;
			}
			
		}
	}
	if(scalar(@errors))
	{
		$dbs->rollback;
		$$requestObject{'stat'}=Apache2::Const::HTTP_INTERNAL_SERVER_ERROR;
		return \@errors;
	}
	else
	{
		$dbs->commit;
		$$requestObject{'headers_out'}=['Location',"/cmdb_api/v1/system/$fqdn"];
	}
	return;
	
}

sub lookupDC()
{
	my $ip=shift;
	my $dc=$dbh->selectcol_arrayref('select data_center_code from 
		datacenter_subnet s
		where
		INET_ATON(?) BETWEEN INET_ATON(
		LEFT(s.subnet,
		INSTR(subnet, "/")-1)) AND
		INET_ATON(
		LEFT(s.subnet,
		INSTR(subnet, "/")-1))+ POW(2, 32-SUBSTRING(subnet,
		INSTR(subnet
		, "/")+1
		))-1',{},($ip));
	return $$dc[0];
}
sub doUpdateIps {
        my $fqdn = shift;
        my $data = shift;
        my $ips = getExistingIps($fqdn);
        my @interfaces;
        foreach my $slot (grep(/mac[_]{0,1}address_.*/, keys %$data)) {
                $slot =~ /mac[_]{0,1}address_(.*)/;
                push(@interfaces, $1);
        }
        #check posted/put'd interfaces against those in DB
        foreach my $interface (@interfaces) { #foreach posted interface
                $logger->info("interface: $interface");
                my $mac_post= $data->{(grep(/mac[_]{0,1}address_$interface$/, keys %$data))[0]};
                my $add_post= $data->{(grep(/ip[_]{0,1}address_$interface$/, keys %$data))[0]};

                $logger->info("\tmac_post: $mac_post");
                $logger->info("\tmac_db: $ips->{$interface}->{mac_address}");
                $logger->info("\tadd_post: $add_post");
                $logger->info("\tadd_db: $ips->{$interface}->{address}");
                doGenericPUT({entity=>'ip', body=>to_json({ fqdn=>$fqdn, address=>$add_post, interface=>$interface,mac_address=>$mac_post}),getparams=>"interface=$interface"});
                next;
                unless($mac_post eq $ips->{$interface}->{mac_address}) {
                        #update changed mac
                        my $sql = "update ip set mac_address='$mac_post' where fqdn='$fqdn';";
                        $logger->debug("$sql") if ($logger->is_debug());
                }
                unless($add_post eq $ips->{$interface}->{address}) {
                        #update changed address
                        my $sql = "update ip set address='$add_post' where fqdn='$fqdn' and interface='$interface';";
                        $logger->debug("$sql") if ($logger->is_debug());
                        my $sth=$dbh->prepare($sql);
            my $rv=$sth->execute();
            $logger->error($sth->err . " : " . $sth->errstr ) if ($sth->err);

                }

        }
}


1;



## HTTP codes for reference
#define RESPONSE_CODES 57

#define HTTP_CONTINUE                      100
#define HTTP_SWITCHING_PROTOCOLS           101
#define HTTP_PROCESSING                    102
#define HTTP_OK                            200
#define HTTP_CREATED                       201
#define HTTP_ACCEPTED                      202
#define HTTP_NON_AUTHORITATIVE             203
#define HTTP_NO_CONTENT                    204
#define HTTP_RESET_CONTENT                 205
#define HTTP_PARTIAL_CONTENT               206
#define HTTP_MULTI_STATUS                  207
#define HTTP_MULTIPLE_CHOICES              300
#define HTTP_MOVED_PERMANENTLY             301
#define HTTP_MOVED_TEMPORARILY             302
#define HTTP_SEE_OTHER                     303
#define HTTP_NOT_MODIFIED                  304
#define HTTP_USE_PROXY                     305
#define HTTP_TEMPORARY_REDIRECT            307
#define HTTP_BAD_REQUEST                   400
#define HTTP_UNAUTHORIZED                  401
#define HTTP_PAYMENT_REQUIRED              402
#define HTTP_FORBIDDEN                     403
#define HTTP_NOT_FOUND                     404
#define HTTP_METHOD_NOT_ALLOWED            405
#define HTTP_NOT_ACCEPTABLE                406
#define HTTP_PROXY_AUTHENTICATION_REQUIRED 407
#define HTTP_REQUEST_TIME_OUT              408
#define HTTP_CONFLICT                      409
#define HTTP_GONE                          410
#define HTTP_LENGTH_REQUIRED               411
#define HTTP_PRECONDITION_FAILED           412
#define HTTP_REQUEST_ENTITY_TOO_LARGE      413
#define HTTP_REQUEST_URI_TOO_LARGE         414
#define HTTP_UNSUPPORTED_MEDIA_TYPE        415
#define HTTP_RANGE_NOT_SATISFIABLE         416
#define HTTP_EXPECTATION_FAILED            417
#define HTTP_UNPROCESSABLE_ENTITY          422
#define HTTP_LOCKED                        423
#define HTTP_FAILED_DEPENDENCY             424
#define HTTP_UPGRADE_REQUIRED              426
#define HTTP_INTERNAL_SERVER_ERROR         500
#define HTTP_NOT_IMPLEMENTED               501
#define HTTP_BAD_GATEWAY                   502
#define HTTP_SERVICE_UNAVAILABLE           503
#define HTTP_GATEWAY_TIME_OUT              504
#define HTTP_VERSION_NOT_SUPPORTED         505
#define HTTP_VARIANT_ALSO_VARIES           506
#define HTTP_INSUFFICIENT_STORAGE          507
#define HTTP_NOT_EXTENDED                  510

