package CGI::Application::Plugin::AuthRunmode::Driver;

use strict;
use warnings;
use vars qw($VERSION);
$VERSION = '0.01';

use CGI::Application::Plugin::AuthRunmode::Status;
use Scalar::Util;

sub new {
    my $class   = shift;
    my $authrm  = shift;
    my $params  = shift || {};
    my $self = {
        'authrm'    => $authrm,
        'params'    => $params,
    };
    Scalar::Util::weaken($self->{'authrm'});
    Scalar::Util::weaken($self->{'params'});
    bless $self, $class;
    return $self;
}

sub authrm {
    my $self = shift;
    return @_ ? $self->{'authrm'} = shift : $self->{'authrm'};
}

sub params {
    my $self = shift;
    return @_ ? $self->{'params'} = shift : $self->{'params'};
}

sub authenticate {
    my $self = shift;
    die "not implemented";
}

1;
