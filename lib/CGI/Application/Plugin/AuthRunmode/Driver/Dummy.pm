package CGI::Application::Plugin::AuthRunmode::Driver::Dummy;

# $Id $

use strict;
use warnings;
use vars qw($VERSION);
$VERSION = '0.01';

use CGI::Application::Plugin::AuthRunmode::Status;
use base qw(CGI::Application::Plugin::AuthRunmode::Driver);

sub authenticate {
    my $self    = shift;
    my $authrm  = $self->authrm;

    $authrm->app->log->info('Dummy driver always makes success in authentication');

    $authrm->logging_in( $self, 'Dummy', undef );
    $authrm->status(CGI::Application::Plugin::AuthRunmode::Status->new('200'));
    return $self->authrm;
}

1;

=head1 NAME

CGI::Application::Plugin::AuthRunmode::Driver::Dummy - an authentication driver for AuthRunmode

=head1 SYNOPSIS

    # setup
    authrm:
      driver:
        -
          module: Dummy

=head1 DESCRIPTION

This driver always makes success in authentication.

=head Callback Parameter

The parameter passed to callback "authrm::logging_in" called when login succeeds:

    $self->add_callback('authrm::logging_in', sub {
        my $app     = shift;    # CGI::Application
        my $driver  = shift;    # CGI::Application::Plugin::AuthRunmode::Driver
        my $user    = shift;    # always 'Dummy'
        my $extra   = shift;    # always undef

=head1 SEE ALSO

L<CGI::Application::Plugin::AuthRunmode>
L<CGI::Application::Plugin::AuthRunmode::Driver>

=head1 AUTHOR

WATANABE Hiroaki, E<lt>hwat@mac.comE<gt>

=head1 LICENSE

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut
