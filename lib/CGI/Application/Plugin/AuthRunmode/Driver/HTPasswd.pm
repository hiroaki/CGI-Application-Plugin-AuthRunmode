package CGI::Application::Plugin::AuthRunmode::Driver::HTPasswd;

# Id: #

use strict;
use warnings;
use vars qw($VERSION);
$VERSION = '0.01';

use base qw(CGI::Application::Plugin::AuthRunmode::Driver);
use CGI::Application::Plugin::AuthRunmode::Status;
use Apache::Htpasswd;

sub authenticate {
    my $self            = shift;
    my $authrm          = $self->authrm;
    my $driver_params   = $self->params;

    my $param_name_user = $driver_params->{'param_name_username'} || 'authrm_username';
    my $param_name_pswd = $driver_params->{'param_name_password'} || 'authrm_password';

    my $input_user = $authrm->app->query->param($param_name_user);
    my $input_pswd = $authrm->app->query->param($param_name_pswd);

    my $cleanup = sub {
        $authrm->app->log->info("delete query params [$param_name_pswd, $param_name_user]");
        $authrm->app->query->delete($param_name_pswd, $param_name_user);
    };

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

    $cleanup->();
    return $authrm;
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

TODO

=head Callback Parameter

The parameter passed to callback "authrm::logging_in" called when log in succeeds is Apache::HTPasswd object. 

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
