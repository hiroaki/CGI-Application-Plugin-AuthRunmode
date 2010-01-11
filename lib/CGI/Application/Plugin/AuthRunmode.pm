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
