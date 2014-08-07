#!perl

package NOMS::JCEL;
use strict;
use Data::Dumper;
use Carp;

# TODO
# Need a way to express (field1 = 'v1' OR field2 = 'v2'). The current
# assumption is that this will be handled by the "statement" oriented
# language surrounding this expression language; for example pattern/action
# statements where two patterns lead to the same action. The problem
# with incorporating operators at the higher level is that a construct
# like { "or": [condition_list] } and { "and": [condition_list] } could
# refer to object attributes called "or" and "and"

=head1 NAME

NOMS::JCEL - JSON (or Jeremy's) Condition Expression Language

=head1 SYNOPSIS

   my $obj = from_json('{ "service": "http", "status": "up" }');
   my $jcel = NOMS::JCEL->new(from_json('{ "service": ["http", "ftp"] }'));

   print "Can use for file transfer" if $jcel->test($obj);

=head1 DESCRIPTION

This module implements an expression language you can use to implement
conditional logic expressed as a "mapping" (like that resulting from
deserializing JSON).

=head2 Methods

=over 4

=item new

   NOMS::JSON->new($expression[, $options]);

The expression is a hash reference to the JCEL expression. Options is a
hash reference containing options and values. The only supported option is
C<'debug'>.

=item test

   $jcel->test($object);

Evaluate the test(s) in the expression against the object. Returns 1 (true)
or 0 (false).

=item as_sql

   $jcel->as_sql($options);

Print a SQL condition predicate corresponding with the conditional expression.
In a scalar context, produces just the SQL text. In a list context, produces a
list, the first member of which is the SQL text and the remaining members of
which are literal values corresponding with SQL placeholders (see
B<literals>). The $options hash reference contains the following options and
values:

=back

=over 8

=item literals

If true, prints the values as quoted literals. *Note:* it is possible to cause
errors; this module's attempt to quote literals is not perfect. It's safer to
leave this value alone (false).

=back

=head2 Language

=head3 Conditions

   condition ::= { attribute: rvalue }
   condition :: = [ condition, ... ]

Each condition consists of a key, the object attribute to examine for a match,
and the rvalue, or comparison, to make against the value in the object
corresponding to the key.

And empty condition list is always true in tests, and returns an empty SQL
predicate (which if plugged into an SQL statement without examination, may
cause a syntax error).

=head3 Rvalues

   rvalue ::= literal
   rvalue ::= { operator: literal }
   rvalue ::= [ rvalue, ... ]

=head3 Operator

=over 4

=item =

General-purpose string comparison. The rvalue may contain shell-like glob
patterns (C<*>, C<?> and C<[]>). Numbers are stringified and compared as
strings.

=item !=

Negation of B<=>.

=item eq

String equality comparsion. No wildcards are allowed.

=item ne

String inequality comparison.

=item ~

Regular expression matching. The rvalue is a Perl regular expression which is
matched against the lvalue.

=item !~

Negation of regular expression matching.

=item ==

=item E<lt>

=item E<gt>

=item E<lt>E<gt>

=item E<lt>=

=item E<gt>=

Numerical comparisons.

=back

=head2 Null Values

In testing, JCEL considers two null values (as well as the case where the
object attribute does not exist) equivalent. Thus:

   my $jcel = NOMS::JCEL->new(from_json('{ "state": null }'));

This condition will evaluate to true when testing either a hash where the
B<state> key is C<undef> or where the B<state> key does not exist.

=head1 KNOWN ISSUES

The B<as_sql> method is new and experimental. There are some cases where it
will not produce syntactically correct SQL, such as for an empty condition.

=head1 AUTHOR

Jeremy Brinkley, E<lt>jbrinkley@evernote.comE<gt>

=cut

use vars qw($me $VERSION);

BEGIN {
   $me = 'NOMS::JCEL';
   $VERSION = '__VERSION__';
}

sub eql {
   my ($lvalue, $rvalue) = @_;

   my $p = glob2pat($rvalue);

   return 1 if $lvalue =~ /$p/;

   return 1 if !defined($lvalue) and !defined($rvalue);

   return 0;
}
   

# http://www.perlmonks.org/?node_id=708493
sub glob2pat {
    my $globstr = shift;
    my %patmap = (
        '*' => '.*',
        '?' => '.',
        '[' => '[',
        ']' => ']',
        '-' => '-',
        );
    
    $globstr =~ s{(?:^|(?<=[^\\]))(.)} { $patmap{$1} || "\Q$1" }ge;

    my $pattern = '^' . $globstr . '$';

    return $pattern;
}

sub isglob {
   my ($g) = @_;
   my $is = 0;

   $is = 1 if $g =~ /^[\?\*]/;
   $is = 1 if $g =~ /[^\\][\?\*]/;
 
   return $is;
}

sub glob2sql {
   my ($g) = @_;
   my %map = (
      '_' => '\_',
      '%' => '\%',
      '*' => '%',
      '?' => '_'
       );
   $g =~ s{(?:^|(?<=[^\\]))(.)} { $map{$1} || $1 }ge;
   
   return $g;
}
   

sub sqlquote {
   my ($s) = @_;

   $s =~ s/\'/\\'/g;

   return "'" . $s . "'";
}

sub new {
   my ($class, $condition, $opt) = @_;

   my $self = bless({}, $class);

   $self->{'condition'} = $condition;
   $self->dbg("init condition: " . ddump($condition));
   $self->{'options'} = $opt;
   $self->{'op'} = {
      '='   => sub { eql($_[0], $_[1]) },
      '!='  => sub { not eql($_[0], $_[1]) },
      'eq'  => sub { $_[0] eq $_[1] },
      'ne'  => sub { $_[0] ne $_[1] },
      '=='  => sub { $_[0] == $_[1] },
      '<>'  => sub { $_[0] != $_[1] },
      '~'   => sub { $_[0] =~ /$_[1]/ },
      '!~'  => sub { $_[0] !~ /$_[1]/ },
      '>'   => sub { $_[0] > $_[1] },
      '<'   => sub { $_[0] < $_[1] },
      '>='  => sub { $_[0] >= $_[1] },
      '<='  => sub { $_[0] <= $_[1] }
   };

   $self->{'sqlop'} = {
      '='   => sub { isglob($_[1]) ? ($_[0] . ' LIKE ?', glob2sql($_[1])) :
                         ($_[0] . ' = ?', $_[1]) },
      '!='  => sub { isglob($_[1]) ? ($_[0] . ' NOT LIKE ?', glob2sql($_[1])) :
                         ($_[0] . ' != ?', $_[1]) },
      'eq'  => sub { ($_[0] . ' = ?', $_[1]) },
      'ne'  => sub { ($_[0] . ' != ?', $_[1]) },
      '=='  => sub { ($_[0] . ' = ?', $_[1]) },
      '<>'  => sub { ($_[0] . ' != ?', $_[1]) },
      '>'   => sub { ($_[0] . ' > ?', $_[1]) },
      '<'   => sub { ($_[0] . ' < ?', $_[1]) },
      '>='  => sub { ($_[0] . ' >= ?', $_[1]) },
      '<='  => sub { ($_[0] . ' <= ?', $_[1]) },
      '~'   => sub { ($_[0] . ' REGEXP ?', $_[1]) },
      '!~'  => sub { ($_[0] . ' NOT REGEXP ?', $_[1]) }
   };

   $self->{'sqlop-literal'} = {
      '='   => sub { isglob($_[1]) ?
                         $_[0] . ' LIKE ' . sqlquote(glob2sql($_[1])) :
                         $_[0] . ' = ' . sqlquote($_[1]) },
      '!='  => sub { isglob($_[1]) ?
                         $_[0] . ' NOT LIKE ' . sqlquote(glob2sql($_[1])) :
                         $_[0] . ' = ' . sqlquote($_[1]) },
      'ne'  => sub { $_[0] . ' != ' . sqlquote($_[1]) },
      '=='  => sub { $_[0] . ' = ' . $_[1] },
      '<>'  => sub { $_[0] . ' != ' . $_[1] },
      '>'   => sub { $_[0] . ' > ' . $_[1] },
      '<'   => sub { $_[0] . ' < ' . $_[1] },
      '>='  => sub { $_[0] . ' >= ' . $_[1] },
      '<='  => sub { $_[0] . ' <= ' . $_[1] },
      '~'   => sub { $_[0] . ' REGEXP ' . sqlquote($_[1]) },
      '!~'  => sub { $_[0] . ' NOT REGEXP ' . sqlquote($_[1]) }
   };
                         

   return $self;
}

sub test {
   my ($self, $object) = @_;

   my $condition = $self->{'condition'};

   my $rv = 0;
   eval {
      $rv = $self->match_condition($condition, $object);
   };
   if ($@) {
      my $err = $@;
      chomp($err);
      $err =~ s/ at \S*JCEL.pm.*//;
      carp $err;
   }

   return $rv;
}

sub as_sql {
   my ($self, $sqlopt) = @_;
   my $literals = 0;

   $literals = 1 if (defined($sqlopt) and $sqlopt->{'literals'});

   my ($st, @literals) = $self->sql($self->{'condition'},
                                       { 'literals' => $literals });
   
   return (wantarray ? ($st, @literals) : $st);
}

sub sql {
   my ($self, $condition, $options, @literals) = @_;
   my $sqltext = '';

   if (ref($condition) eq 'ARRAY') {
      my @subsqltexts = ();
      for my $subcondition (@{$condition}) {
         my ($subsqltext, @sublits) = $self->sql($subcondition, $options);
         push(@subsqltexts, $subsqltext);
         push(@literals, @sublits);
      }
      $sqltext = join(' AND ', @subsqltexts);
   } else {
      my ($lvalue) = keys(%$condition);
      my $rvalue = $condition->{$lvalue};
      my $op = '=';
      my $optype = ($options->{'literals'} ? 'sqlop-literal' : 'sqlop');
      if (ref($rvalue)) {
         if (ref($rvalue) eq 'ARRAY') {
            $op = 'IN';
            my $rvaluetext = $options->{'literals'} ? 
                '(' . join(', ', map { sqlquote($_) } @$rvalue) . ')' :
                '(' . join(', ', map { '?' } @$rvalue) . ')';
            $sqltext = join(' ', $lvalue, $op, $rvaluetext);
            push(@literals, @$rvalue);
         } elsif (ref($rvalue) eq 'HASH') {
            ($op) = keys(%$rvalue);
            $rvalue = $rvalue->{$op};
            ($sqltext, $rvalue) = $self->{$optype}->{$op}->($lvalue, $rvalue);
            push(@literals, $rvalue);
         }
      } else {
         ($sqltext, $rvalue) = $self->{$optype}->{$op}->($lvalue, $rvalue);
         push(@literals, $rvalue);
      }
   }

   return ($options->{'literals'} ? ($sqltext) : ($sqltext, @literals));
}

sub match_condition {
   my ($self, $condition, $object) = @_;
   
   $self->dbg("match_condition(" . ddump($condition) . ", " . ddump($object)
              . ')');

   # and
   if (ref($condition) eq 'ARRAY') {
      for my $subcondition (@$condition) {
         return 0 unless $self->match_condition($subcondition, $object);
      }
      return 1;
   }

   if (! ref($condition) or ref($condition) ne 'HASH') {
      die "Condition must be HASH or ARRAY reference";
   }

   return 1 unless keys %$condition; # empty condition is true

   for my $attr (keys %$condition) {
      my $rvalue = $condition->{$attr};
      return 0 unless $self->match_rvalue($rvalue, $object->{$attr});
   }

   return 1;
}

sub match_rvalue {
   my ($self, $rvalue, $lvalue) = @_;

   $self->dbg("match_rvalue(" . ddump($rvalue) . ", " . ddump($lvalue) . ')');

   if (ref($rvalue)) {
      if (ref($rvalue) eq 'HASH') {
         my ($op) = keys %$rvalue;
         $self->dbg("   op is: " . ddump($op));
         my $simple_rvalue = $rvalue->{$op};
         if (ref($simple_rvalue)) {
            die "rvalue of explicit operator must be simple";
         }
         return tv($self->{'op'}->{$op}->($lvalue, $simple_rvalue));
      } elsif (ref($rvalue) eq 'ARRAY') {
         $self->dbg("   rvalue is list");
         for my $simple_rvalue (@$rvalue) {
            if (ref($simple_rvalue)) {
               die "each rvalue in rvalue list must be simple";
            }
            $self->dbg("      checking simple rvalue: "
                       . ddump($simple_rvalue));
            return 1 if $self->{'op'}->{'='}->($lvalue, $simple_rvalue);
         }
         return 0;
      }
   } else {
      $self->dbg("   rvalue is simple: $rvalue");
      return tv($self->{'op'}->{'='}->($lvalue, $rvalue));
   }
}

sub ddump {
   my $var = 'var0';
   Data::Dumper->new([@_],[map {$var++} @_])->Terse(1)->Indent(0)->Dump;
}

sub dbg {
   my ($self, @msg) = @_;
   print STDERR "DBG($me): ", join("\nDBG($me):    ", @msg), "\n"
       if $self->{'options'}->{'debug'};
}

sub tv {
   my ($val) = @_;
   return 1 if $val;
   return 0;
}

1;
