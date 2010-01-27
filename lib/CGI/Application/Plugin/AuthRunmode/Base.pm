package CGI::Application::Plugin::AuthRunmode::Base;

# Id: #

use strict;
use warnings;
use vars qw($VERSION);
$VERSION = '0.01';

use Carp;
use CGI::Application::Plugin::AuthRunmode::Status;
use Scalar::Util;

our %Const = (
    'default_default_runmode'   => 'default',
    'default_login_runmode'     => 'login',
    'default_logout_runmode'    => 'logout',
    'default_login_template'    => 'login.tmpl',
    'default_logout_template'   => 'logout.tmpl',
    'param_suspending_runmode'  => '_suspending_runmode',
    'param_suspending_query'    => '_suspending_query',
    'param_suspending_method'   => '_suspending_method',
    'param_auth_userid'         => 'AUTHRM_USERID',
    'param_auth_userinfo'       => 'AUTHRM_USERINFO',
    'param_auth_attempts'       => 'AUTHRM_ATTEMPTS',
    );

sub new {
    my $class   = shift;
    my $app     = shift;
    my $args    = shift || {};
    my $self    = {
        'app'       => $app,
        'args'      => $args,
        'status'    => undef, # authenticate retuns
        'drivers'   => [],
        'protected_runmodes'
                    => [],
        };
    Scalar::Util::weaken($self->{'app'});
    bless $self, $class;

    # create drivers
    my @drivers = ();
    my @auth_drivers = @{ $self->args->{'driver'} };
    unless( @auth_drivers ){
        $self->app->log->critical("no driver");
        croak "no driver";
    }
    for my $driver ( @auth_drivers ){
        my $module = $driver->{'module'};
        my $params = $driver->{'params'};
        push @drivers, $module->new($self, $params);
    }
    $self->drivers(\@drivers);

    # set default
    $self->args->{'login_template'} ||= $Const{'default_login_template'};
    $self->args->{'logout_template'}||= $Const{'default_logout_template'};

    # reservation rm
    $self->args->{'login_runmode'}  ||= $Const{'default_login_runmode'};
    $self->args->{'logout_runmode'} ||= $Const{'default_logout_runmode'};
    $self->app->run_modes(
        "@{[$self->get_login_runmode]}"   => \&rm_login,
        "@{[$self->get_logout_runmode]}"  => \&rm_logout,
        );
    # the login runmode needs protect
    $self->add_protected_runmode($self->get_login_runmode);

    # generic rm
    $self->args->{'default_runmode'}||= $Const{'default_default_runmode'};

    # hook prerun
    $self->app->add_callback('prerun', \&_handler_prerun );

    return $self;
}

sub app {
    my $self = shift;
    return @_ ? $self->{'app'} = shift : $self->{'app'};
}

sub args {
    my $self = shift;
    return @_ ? $self->{'args'} = shift : $self->{'args'};
}

sub status {
    my $self = shift;
    return @_ ? $self->{'status'} = shift : $self->{'status'};
}

sub drivers {
    my $self = shift;
    return @_ ? $self->{'drivers'} = shift : $self->{'drivers'};
}

sub protected_runmodes {
    my $self = shift;
    return @_ ? $self->{'protected_runmodes'} = shift : $self->{'protected_runmodes'};
}

sub add_protected_runmode {
    my $self = shift;
    my $pm = $self->protected_runmodes;
    for my $mode ( @_ ){
        if( ref $mode eq 'ARRAY' ){
            push @$pm, @$mode;
        }else{
            push @$pm, $mode;
        }
    }
    $self->app->log->debug("protected runmode [@$pm]");
    $self->protected_runmodes($pm);
}

sub is_protected_runmode {
    my $self = shift;
    my $rm = $self->app->get_current_runmode;
    for ( @{$self->protected_runmodes} ){
        if( ref $_ eq 'Regexp' ){
            return 1 if( $rm =~ $_ );
        }else{
            return 1 if( $rm eq $_ );
        }
    }
    return undef;
}

sub get_default_runmode {
    shift->args->{'default_runmode'};
}

sub get_login_runmode {
    shift->args->{'login_runmode'};
}

sub get_logout_runmode {
    shift->args->{'logout_runmode'};
}

sub get_login_template {
    shift->args->{'login_template'};
}

sub get_logout_template {
    shift->args->{'logout_template'};
}

sub _handler_prerun {
    my $app = shift;

    my $rm = $app->get_current_runmode;
    my $prerun_mode = $rm;
    if( ! $app->authrm->is_protected_runmode ){
        $app->authrm->_clear_suspending;
    }else{
        if( $app->authrm->is_logged_in ){
            if( $app->authrm->suspending_runmode ){
                $app->authrm->_resume_runmode;
            }
            $app->authrm->_clear_suspending;
        }else{
            $app->log->debug("in protected runmode [$rm], then it requires login");
    
            if( $app->authrm->args->{'deny_direct_login_runmode'} and $app->session->is_new ){
                $app->log->info("change rm to 'default' because 'login' does not allow to direct access, or session reaches timeout");
                $prerun_mode = $app->authrm->get_default_runmode;
            }else{
                if( $app->authrm->suspending_runmode ){
                    $app->log->debug("rm [".$app->authrm->suspending_runmode."] was suspending");
                }else{
                    $app->authrm->suspend_runmode;
                    $app->log->debug("rm [$rm] is suspended");
                }
                $prerun_mode = $app->authrm->get_login_runmode;
            }
        }
    }
    $app->prerun_mode($prerun_mode);
    return $app;
}

sub rm_login {
    my $app = shift;

    my $result = undef;
    for my $driver ( @{ $app->authrm->drivers } ){
        $result = $driver->authenticate;
        last if( $result );
    }

    unless( $result ){
        return $app->tt_process( $app->authrm->get_login_template );
    }else{
        if( Scalar::Util::blessed( $result ) and $result->isa(__PACKAGE__) ){
            if( $result->status->is_success ){
                $app->authrm->_clear_login_attempts;

                if( uc $app->authrm->suspending_method eq 'POST' ){
                     $app->redirect( $app->authrm->suspending_query->url(-path=>1) );
                }else{
                     $app->redirect( $app->authrm->suspending_query->url(-path=>1,-query=>1) );
                }
                return;
            }else{
                $app->authrm->_increment_login_attempts;
                return $app->tt_process( $app->authrm->get_login_template );
            }
        }else{
            return $app->redirect($result);
        }
    }
}

sub rm_logout {
    my $app = shift;
    $app->authrm->logging_out;
    $app->tt_process( $app->authrm->get_logout_template );
}

sub suspend_runmode {
    my $self = shift;
    $self->app->session->param($Const{'param_suspending_runmode'}, $self->app->get_current_runmode);
    $self->app->session->param($Const{'param_suspending_query'},   $self->app->query);
    $self->app->session->param($Const{'param_suspending_method'},  $self->app->query->request_method);
}

sub suspending_runmode {
    shift->app->session->param($Const{'param_suspending_runmode'});
}

sub suspending_query {
    shift->app->session->param($Const{'param_suspending_query'});
}

sub suspending_method {
    shift->app->session->param($Const{'param_suspending_method'});
}

sub _resume_runmode {
    my $self = shift;

    $self->app->log->debug("resume rm, query and REQUEST_METHOD");
    my $back_to            = $self->app->session->param($Const{'param_suspending_runmode'});
    $self->app->query(       $self->app->session->param($Const{'param_suspending_query'}  ));
    $ENV{'REQUEST_METHOD'} = $self->app->session->param($Const{'param_suspending_method'} );

    if( ! defined $back_to or $back_to eq $self->get_login_runmode ){
        $self->app->log->info("change rm from 'login' to 'default' because direct access to 'login'");
        $back_to = $self->get_default_runmode;
    }
    $self->app->log->debug("forwads to resumed run mode [$back_to]");
    return $self->app->forward( $back_to );
}

sub _clear_suspending {
    shift->app->session->clear([
        $Const{'param_suspending_runmode'},
        $Const{'param_suspending_query'},
        $Const{'param_suspending_method'}
        ]);
}

sub logging_in {
    my $self    = shift;
    my $authobj = shift;
    my $user_id = shift;
    my @extra_args = @_;

    # This can be useful to protect against some login attacks 
    # when storing authentication tokens in the session
    $self->app->session_recreate;

    $self->app->session->param($Const{'param_auth_userid'}, $user_id);
    $self->app->session->expire($Const{'param_auth_userid'}, $self->args->{'expire'});
    $self->app->session->flush;

    $self->app->call_hook('authrm::logging_in', $authobj, $user_id, @extra_args );
}

sub logging_out {
    my $self = shift;
    $self->app->log->debug("delete session");
    $self->app->session_delete;
    $self->app->session->flush;
}

sub is_logged_in {
    shift->get_login_user_id;
}

sub get_login_user_id {
    shift->app->session->param($Const{'param_auth_userid'});
}

sub get_login_user_info {
    my $self = shift;
    my $key = shift;
    my $info = $self->app->session->param($Const{'param_auth_userinfo'}) || {};
    return $info->{$key} if( defined $key );
    return $info;
}

sub set_login_user_info {
    my $self = shift;
    my $key = shift;
    my $value = shift;
    my $info = $self->get_login_user_info;
    $info->{$key} = $value;
    $self->app->session->param($Const{'param_auth_userinfo'},$info);
    $self->app->session->flush;
    return $self;
}

sub get_login_attempts {
    shift->app->session->param($Const{'param_auth_attempts'});
}

sub _increment_login_attempts {
    my $self = shift;
    my $attempts = $self->app->session->param($Const{'param_auth_attempts'}) || 0;
    $self->app->session->param($Const{'param_auth_attempts'},++$attempts);
}

sub _clear_login_attempts {
    shift->app->session->clear($Const{'param_auth_attempts'});
}

1;
