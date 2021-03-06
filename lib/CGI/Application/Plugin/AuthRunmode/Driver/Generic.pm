package CGI::Application::Plugin::AuthRunmode::Driver::Generic;

# $Id $

use strict;
use warnings;
use vars qw($VERSION);
$VERSION = '0.01';

use CGI::Application::Plugin::AuthRunmode::Status;
use base qw(CGI::Application::Plugin::AuthRunmode::Driver);

__PACKAGE__->DefaultParamNames({
    'param_name_userid' => 'authrm_userid_generic',
    'param_name_passwd' => 'authrm_passwd_generic',
    'param_name_submit' => 'authrm_submit_generic',
    });

sub fields_spec {
    my $self = shift;

    my @field_spec = (  # see also CGI.pm
        {
            'label' => 'user',
            'type'  => 'textfield',
            'attr'  => {
                -name => $self->get_param_name('param_name_userid'),
                },
            },
        {
            'label' => 'password',
            'type'  => 'password_field',
            'attr'  => {
                -name => $self->get_param_name('param_name_passwd'),
                },
            },
        {
            'label' => '',
            'type'  => 'submit',
            'attr'  => {
                -name => $self->get_param_name('param_name_submit'),
                -value => 'login',
                },
            },
    );
    return @field_spec;
}

sub authenticate {
    my $self    = shift;
    my $authrm  = $self->authrm;

    my $input_user = $self->get_and_clear_param('param_name_userid');
    my $input_pswd = $self->get_and_clear_param('param_name_passwd');
    my $input_sbmt = $self->get_and_clear_param('param_name_submit');

    if( ! $input_user and ! $input_pswd ){

        $authrm->status(CGI::Application::Plugin::AuthRunmode::Status->new('401'));
        return;

    }else{
        my $driver_params = $self->params;

        if( $input_user and $input_pswd 
        and $input_user eq $driver_params->{'valid_user'}
        and $input_pswd eq $driver_params->{'valid_password'}
        ){
            $authrm->log->info("login success as [$input_user]");
            $authrm->logging_in( $self, $input_user, $input_user );
            $authrm->status(CGI::Application::Plugin::AuthRunmode::Status->new('200'));
        }else{
            $authrm->log->info("login failed as [".(defined $input_user ? $input_user : 'undef')."]");
            $authrm->status(CGI::Application::Plugin::AuthRunmode::Status->new('403'));
        }

        return $authrm;
    }
}

1;

=head1 NAME

CGI::Application::Plugin::AuthRunmode::Driver::Generic - an authentication driver for AuthRunmode

=head1 SYNOPSIS

    # setup
    authrm:
      driver:
        -
          module: Generic
          params:
            valid_user: username
            valid_password: password

=head1 DESCRIPTION

This driver provides authentication for AuthRunmode.

The user\'s input strings are matched with the plain text recorded in the configuration parameter.

=head Callback Parameter

The parameter passed to callback "authrm::logging_in" called when login succeeds:

    $self->add_callback('authrm::logging_in', sub {
        my $app     = shift;    # CGI::Application
        my $driver  = shift;    # CGI::Application::Plugin::AuthRunmode::Driver
        my $user    = shift;    # input user name
        my $extra   = shift;    # same as $user

=head1 SEE ALSO

L<CGI::Application::Plugin::AuthRunmode>
L<CGI::Application::Plugin::AuthRunmode::Driver>

=head1 AUTHOR

WATANABE Hiroaki, E<lt>hwat@mac.comE<gt>

=head1 LICENSE

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut
