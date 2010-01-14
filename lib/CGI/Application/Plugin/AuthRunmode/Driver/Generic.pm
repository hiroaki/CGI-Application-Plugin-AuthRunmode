package CGI::Application::Plugin::AuthRunmode::Driver::Generic;

# $Id $

use strict;
use warnings;
use vars qw($VERSION);
$VERSION = '0.01';

use CGI::Application::Plugin::AuthRunmode::Status;
use base qw(CGI::Application::Plugin::AuthRunmode::Driver);

sub authenticate {
    my $self = shift;
    my $authrm          = $self->authrm;
    my $driver_params   = $self->params;

    my $param_name_user = $driver_params->{'param_name_username'} || 'authrm_username';
    my $param_name_pswd = $driver_params->{'param_name_password'} || 'authrm_password';

    my $input_user = $authrm->app->query->param($param_name_user);
    my $input_pswd = $authrm->app->query->param($param_name_pswd);

    if( ( ! $authrm->app->query->param )
     or ( ! $input_user and ! $input_pswd )
    ){
        $authrm->status(CGI::Application::Plugin::AuthRunmode::Status->new('401'));
        return;
    }else{

        if( $input_user and $input_pswd 
        and $input_user eq $driver_params->{'valid_user'}
        and $input_pswd eq $driver_params->{'valid_password'}
        ){
            $authrm->app->log->info("login success as [$input_user]");
            $authrm->logging_in( $self, $input_user, $input_user );
            $authrm->status(CGI::Application::Plugin::AuthRunmode::Status->new('200'));
        }else{
            $authrm->app->log->info("login failed as [".(defined $input_user ? $input_user : 'undef')."]");
            $authrm->status(CGI::Application::Plugin::AuthRunmode::Status->new('403'));
        }

        $authrm->app->log->info("delete query params [$param_name_pswd, $param_name_user]");
        $authrm->app->query->delete($param_name_pswd, $param_name_user);
        return $authrm;
    }
}

1;
