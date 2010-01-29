package CGI::Application::Plugin::AuthRunmode::Driver;

use strict;
use warnings;
use vars qw($VERSION);
$VERSION = '0.01';

use Scalar::Util;
use base qw(Class::Data::Inheritable);

__PACKAGE__->mk_classdata('DefaultParamNames');
__PACKAGE__->DefaultParamNames({
});

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

sub get_default_param_name {
    my $self = shift;
    my $id   = shift;
    return $self->DefaultParamNames->{$id};
}

sub fields_spec {
    my $self = shift;
    return ();
}

sub get_param_name {
    my $self = shift;
    my $id   = shift;
    return $self->params->{$id} || $self->get_default_param_name($id);
}

sub get_and_clear_param {
    my $self    = shift;
    my $key     = shift;
    my $authrm  = $self->authrm;
    my $name    = $self->get_param_name($key);

    my $val = $authrm->app->query->param($name);

    $authrm->app->log->debug("delete query param [$name]");
    $authrm->app->query->delete($name);

    return $val;
}

1;
