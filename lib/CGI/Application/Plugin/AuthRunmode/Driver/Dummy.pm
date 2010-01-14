package CGI::Application::Plugin::AuthRunmode::Driver::Dummy;

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

    $authrm->app->log->info('Dummy driver always makes the authentication succeed');
    $authrm->status(CGI::Application::Plugin::AuthRunmode::Status->new('200'));
    return $self->authrm;
}

1;
