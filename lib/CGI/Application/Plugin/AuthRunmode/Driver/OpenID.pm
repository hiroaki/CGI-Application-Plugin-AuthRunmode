package CGI::Application::Plugin::AuthRunmode::Driver::OpenID;

# Id: #

use strict;
use warnings;
use vars qw($VERSION);
$VERSION = '0.01';

use base qw(CGI::Application::Plugin::AuthRunmode::Driver);
use CGI::Application::Plugin::AuthRunmode::Status;
use Net::OpenID::Consumer;
use UNIVERSAL::require;

__PACKAGE__->DefaultParamNames({
    'param_name_userid' => 'authrm_userid_openid',
    'param_name_submit' => 'authrm_submit_openid',
    });

sub new {
    my $class = shift;
    my $self = $class->SUPER::new(@_);
    $self->authrm->app->new_hook('authrm::driver::openid::setup_consumer');
    return $self;
}

sub fields_spec {
    my $self = shift;

    my @field_spec = (  # see also CGI.pm
        {
            'label' => 'openid',
            'type'  => 'textfield',
            'attr'  => {
                -name => $self->get_param_name('param_name_userid'),
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
    my $self            = shift;
    my $authrm          = $self->authrm;

    my $input_user = $self->get_and_clear_param('param_name_userid');
    my $input_sbmt = $self->get_and_clear_param('param_name_submit');
    
    if( ! $input_user and ! $authrm->app->query->param('openid.mode') ){

        $authrm->status(CGI::Application::Plugin::AuthRunmode::Status->new('401'));
        return;

    }else{
        my $driver_params = $self->params;

        my $ua_module = 'LWP::UserAgent';
        my $ua_params = {};
        if( exists $driver_params->{'agent'} and exists $driver_params->{'agent'} ){
            $ua_module = $driver_params->{'agent'}->{'module'};
            $ua_params = $driver_params->{'agent'}->{'params'} || {};
        }
        my $ua = $ua_module->new( %$ua_params );
        my $csr = Net::OpenID::Consumer->new(
            'ua'                => $ua,
            'args'              => $authrm->app->query,
            'consumer_secret'   => $driver_params->{'consumer_secret'},
            'required_root'     => $driver_params->{'required_root'},
            );
        $authrm->app->call_hook('authrm::driver::openid::setup_consumer', $csr );
        $authrm->app->log->debug("Net::OpenID::Consumer has UA: ${\$csr->ua}");

        if( $input_user ){
    
            if( my $claimed_identity = $csr->claimed_identity( $input_user ) ){

                if( exists $driver_params->{'extension_args'} ){
                    $authrm->app->log->debug("set extension args: [@{ $driver_params->{'extension_args'} }]");
                    $claimed_identity->set_extension_args( @{ $driver_params->{'extension_args'} } );
                }

                my $check_url = $claimed_identity->check_url(
                                    # see Net::OpenID::ClaimedIdentity for details
                                    'delayed_return' => 1,
                                    'return_to'  => $authrm->app->query->url(-path_info=>1,-query=>1),
                                    'trust_root' => $authrm->app->query->url(-path_info=>1),
                                    );
                $authrm->app->log->notice("redirecting check_url: $check_url");

                $authrm->status(CGI::Application::Plugin::AuthRunmode::Status->new('303'));
                return $check_url;
            }else{
                $authrm->app->log->notice("it is not an OpenID provider [$input_user]");
                $authrm->app->log->notice("csr error code: ". (defined $csr->errcode ? $csr->errcode : 'undef'));
                $authrm->status(CGI::Application::Plugin::AuthRunmode::Status->new('400'));
                return $authrm;
            }
    
        }else{

            my $msg = 'csr handles server response...';
            my $r = $csr->handle_server_response(
                'not_openid' => sub {
                        $authrm->app->log->info("$msg not_openid");

                        $authrm->status(CGI::Application::Plugin::AuthRunmode::Status->new('404'));
                        return $authrm;
                    },
                'setup_required' => sub {
                        my $setup_url = shift;
                        $authrm->app->log->info("$msg setup_required");

                        $authrm->status(CGI::Application::Plugin::AuthRunmode::Status->new('305'));
                        return $setup_url;
                    },
                'cancelled' => sub {
                        $authrm->app->log->info("$msg cancelled");

                        $authrm->status(CGI::Application::Plugin::AuthRunmode::Status->new('407'));
                        return $authrm;
                    },
                'verified' => sub {
                        my $verified_identity = shift;
                        $authrm->app->log->info("$msg verified");
        
                        $authrm->logging_in( $self, $verified_identity->url, $verified_identity );

                        $authrm->status(CGI::Application::Plugin::AuthRunmode::Status->new('200'));
                        return $authrm;
                    },
                'error' => sub {
                        my $err = shift;
                        $authrm->app->log->error("$msg error: $err");

                        $authrm->status(CGI::Application::Plugin::AuthRunmode::Status->new('502'));
                        return $authrm;
                    },
                );

            $authrm->app->log->debug("return $r");
            return $r;
        }
    }
}

1;
