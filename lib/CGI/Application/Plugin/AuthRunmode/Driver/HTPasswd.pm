package CGI::Application::Plugin::AuthRunmode::Driver::HTPasswd;

# Id: #

use strict;
use warnings;
use vars qw($VERSION);
$VERSION = '0.01';

use base qw(CGI::Application::Plugin::AuthRunmode::Driver);
use CGI::Application::Plugin::AuthRunmode::Status;
use Apache::Htpasswd;

__PACKAGE__->DefaultParamNames({
    'param_name_userid' => 'authrm_userid_htpasswd',
    'param_name_passwd' => 'authrm_passwd_htpasswd',
    'param_name_submit' => 'authrm_submit_htpasswd',
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

        my $files = $driver_params->{'files'};
        if( ref $files ne 'ARRAY' ){
            $files = [$files];
        }
        die "The HTPasswd driver requires at least one htpasswd file"
            unless $files;

        for my $file ( @$files ){

            $authrm->app->log->debug("passwd file - $file");
            my $htpasswd = Apache::Htpasswd->new({
                    'passwdFile' => $file,
                    'ReadOnly'   => 1,
                    });
            if( $htpasswd->htCheckPassword( $input_user, $input_pswd ) ){
                $authrm->app->log->info("login success as [$input_user]");
                $authrm->logging_in( $self, $input_user, $htpasswd );
                $authrm->status(CGI::Application::Plugin::AuthRunmode::Status->new('200'));
                # 
                last;
            }else{
                $authrm->app->log->info("login failed as [".(defined $input_user ? $input_user : 'undef')."]");
                $authrm->status(CGI::Application::Plugin::AuthRunmode::Status->new('403'));
            }
        }

        return $authrm;
    }
}

1;

=head1 NAME

CGI::Application::Plugin::AuthRunmode::Driver::HTPasswd - an authentication driver for AuthRunmode

=head1 SYNOPSIS

    # setup
    authrm:
      driver:
        -
          module: HTPasswd
          params:
            files:
              - /path/to/etc/htpasswd
              - /home/etc/.htpasswd

=head1 DESCRIPTION

This driver provides authentication by using htpasswd files.

=head Callback Parameter

The parameter passed to callback "authrm::logging_in" called when login succeeds:

    $self->add_callback('authrm::logging_in', sub {
        my $app     = shift;    # CGI::Application
        my $driver  = shift;    # CGI::Application::Plugin::AuthRunmode::Driver
        my $user    = shift;    # verified user name (or identifier)
        my $ah      = shift;    # it has Apache::HTPasswd object

=head1 Dependency

This driver module requires external modules:

    use Apache::Htpasswd

=head1 SEE ALSO

L<Apache::Htpasswd>
L<CGI::Application::Plugin::AuthRunmode>
L<CGI::Application::Plugin::AuthRunmode::Driver>

=head1 AUTHOR

WATANABE Hiroaki, E<lt>hwat@mac.comE<gt>

=head1 LICENSE

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut
