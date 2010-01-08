package CGI::Application::Plugin::AuthRunmode;

# Id: #

use strict;
use warnings;
use vars qw($VERSION);
$VERSION = '0.01';

use Carp qw(croak);
use CGI::Application::Plugin::AuthRunmode::Base;
use UNIVERSAL::require;
use vars qw(@ISA @EXPORT);
require Exporter;
@ISA = qw(Exporter);
@EXPORT = qw(
    &authrm
    &authrm_config
    );

sub authrm {
    my $app = shift;
    $app->{__PACKAGE__.'_instance'} || $app->authrm_config;
}

sub authrm_config {
    my $app  = shift;
    my $args = shift;

    my $drivers = $args->{'driver'} || { 'module' => 'Dummy', 'params' => {} };
    if( ref($drivers) ne 'ARRAY' ){
        $drivers = [$drivers];
    }
    for my $driver ( @$drivers ){
        my $module = $driver->{'module'};
        my $params = $driver->{'params'};

        if( $module !~ /::/ ){
            $module = "CGI::Application::Plugin::AuthRunmode::$module";
            $driver->{'module'} = $module; # restore as fullname
        }
        $module->require
            or croak("could not load module [$module]: $@");
        UNIVERSAL::can($module,'authenticate')
            or croak("cannot use incorrect implement module [$module]");
    }

    $args->{'driver'} = $drivers;
    
    # install hook
    $app->new_hook('authrm::logging_in');

    return $app->{__PACKAGE__.'_instance'} = CGI::Application::Plugin::AuthRunmode::Base->new( $app, $args );
}

1;

=head1 NAME

CGI::Application::Plugin::AuthRunmode - interrupt runmode by login transparently

=head1 SYNOPSIS

    use base qw(CGI::Application);
    use CGI::Application::Plugin::AuthRunmode;
    use CGI::Application::Plugin::Forward;
    use CGI::Application::Plugin::LogDispatch;
    use CGI::Application::Plugin::Redirect;
    use CGI::Application::Plugin::Session;
    
    sub cgiapp_init {
        my $self = shift;
        $self->authrm_config({
            'driver' => [
                {
                    'module' => 'Generic',
                    'params' => {
                        'valid_user'        => 'cgi',
                        'valid_password'    => 'application',
                        },
                   },
                ],
            'expire' => '+1h',
            });
    
        # and pass value of status to login template
        $self->add_callback('load_tmpl', sub {
            my ($self, $ht_params, $tmpl_params, $tmpl_file) = @_;
            if( $self->get_current_runmode eq $self->authrm->get_login_runmode ){
                $tmpl_params->{'login_status'} = $self->authrm->status->code;
            }
        });
    }
    
    sub setup {
        my $self = shift;
        $self->start_mode('default');
        $self->run_modes(
            'default'   => \&rm_default,
            'admin'     => \&rm_admin,
            );
        $self->authrm->add_protected_runmode(
            'admin'
            );
    }

=head1 DESCRIPTION

TODO

=head1 Appending Runmods

=over 4

=item login

=item logout

=back


=head1 Export Method

=over 4

=item authrm_config

=item authrm

=back

=head1 Driver

=over 4

=item Dummy

pass everybody.

=item Generic

using static values of user/pass in configuration.

=item Htpssword

TODO. using htpasswd file.

=item OpenID

using OpenID.

=back

=head1 Authenticate Status

See CGI::Application::Plugin::AuthRunmode::Status

=head1 Hook

=over 4

=item authrm::logging_in

=back

=head1 Dependence

Requires:

    use 5.8.1;
    use Class::Data::Inheritable;
    use CGI::Application;
    use CGI::Application::Plugin::Forward;
    use CGI::Application::Plugin::LogDispatch;
    use CGI::Application::Plugin::Redirect;
    use CGI::Application::Plugin::Session;
    use CGI::Application::Plugin::TT;
    use UNIVERSAL::require;
    
Optional, the driver CGI::Application::Plugin::AuthRunmode::OpenID using:

    use Net::OpenID::Consumer;
    use LWP::UserAgent;

=head1 SEE ALSO

CGI::Application

=head1 AUTHOR

WATANABE Hiroaki, E<lt>hwat@mac.comE<gt>

=head1 LICENSE

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut
