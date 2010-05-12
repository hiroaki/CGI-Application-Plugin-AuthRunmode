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

    $authrm->log->debug("delete query param [$name]");
    $authrm->app->query->delete($name);

    return $val;
}

1;

=head1 NAME

CGI::Application::Plugin::AuthRunmode::Driver - base driver for AuthRunmode

=head1 SYNOPSIS

    package CGI::Application::Plugin::AuthRunmode::Driver::FooBar;

    use base qw(CGI::Application::Plugin::AuthRunmode::Driver);

    __PACKAGE__->DefaultParamNames({
        'param_name_userid' => 'authrm_userid_generic',
        'param_name_passwd' => 'authrm_passwd_generic',
        'param_name_submit' => 'authrm_submit_generic',
        });

    sub fields_spec {
        # implements
    }
    
    sub authenticate {
        # implements
    }

=head1 DESCRIPTION

TODO

=head1 Return Value

There are three types of return values of authenticate().

=over4

=item object - CGI::Application::Plugin::AuthRunmode

If autenticate() returns the object of CGI::Application::Plugin::AuthRunmode,
this means that a proof of success or failure.
Those differences are entrusted to the status object.

And you have to set status to 2xx number as success, or 4xx as failure.

=item undef

The undef is a sign of the failure.
However, it is especially shown that this authentic method was not used.

And you also have to set status to 401 (Authenticate required) number.

=item scalar

The scalar value is used as redirecting URL.
And you can set 3xx.

The URL will be printed with redirect header, as the result of run mode.

=back

=head1 SEE ALSO

L<CGI::Application::Plugin::AuthRunmode>
L<CGI::Application::Plugin::AuthRunmode::Status>

=head1 AUTHOR

WATANABE Hiroaki, E<lt>hwat@mac.comE<gt>

=head1 LICENSE

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut
