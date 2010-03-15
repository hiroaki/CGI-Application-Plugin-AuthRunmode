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
        'render_login'
                    => '_default_render_login', # method name or CODE
        'render_logout'
                    => '_default_render_logout', # method name or CODE
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

    # reservation rm
    $self->args->{'login_runmode'}  ||= $Const{'default_login_runmode'};
    $self->args->{'logout_runmode'} ||= $Const{'default_logout_runmode'};
    $self->app->run_modes(
        "@{[$self->get_login_runmode]}"   => \&rm_login,
        "@{[$self->get_logout_runmode]}"  => \&rm_logout,
        );
    # the login runmode needs protection
    $self->add_protected_runmode($self->get_login_runmode);

    # generic rm
    $self->args->{'default_runmode'}||= $Const{'default_default_runmode'};

    # hook prerun
    $self->app->add_callback('prerun', \&_handler_prerun );

    if( $self->args->{'render_login'} ){
        $self->render_login($self->args->{'render_login'});
    }

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

sub render_login {
    my $self = shift;
    return @_ ? $self->{'render_login'} = shift : $self->{'render_login'};
}

sub render_logout {
    my $self = shift;
    return @_ ? $self->{'render_logout'} = shift : $self->{'render_logout'};
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

sub _handler_prerun {
    my $app = shift;

    my $rm = $app->get_current_runmode;
    my $prerun_mode = $rm;
    if( ! $app->authrm->is_protected_runmode ){
        $app->authrm->_clear_suspending;
    }else{
        if( $app->authrm->is_logged_in ){
            if( $app->authrm->suspending_runmode ){
                $prerun_mode = $app->authrm->_resume_runmode;
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
    $app->log->debug("set prerun_mode [$prerun_mode]");
    $app->prerun_mode($prerun_mode);
    return $app;
}

sub output_login {
    my $self = shift;
    if( ref $self->render_login eq 'CODE' ){
        return $self->render_login->();
    }else{
        return $self->${\$self->render_login}();
    }
}

sub output_logout {
    my $self = shift;
    if( ref $self->render_logout eq 'CODE' ){
        return $self->render_logout->();
    }else{
        return $self->${\$self->render_logout}();
    }
}

sub _default_render_login {
    my $self = shift;

    my $html = $self->app->query->start_html(-title=>'Login');
    $html .= $self->app->query->h1("Login");
    
    for my $driver ( @{ $self->drivers } ){
        my $fname = ref $driver;
        $fname =~ s/::/_/g;
        $html .= $self->app->query->start_form(
                    -name   => $fname,
                    -method => 'POST',
                    -action => $self->app->query->url(-path=>1),
                    );
        for ( $driver->fields_spec ){
            $html .= $self->app->query->div($_->{'label'} . $self->app->query->${\$_->{'type'}}(%{$_->{'attr'}}));
        }
        $html .= $self->app->query->endform;
    }

    $html .= $self->app->query->end_html;
    return $html;
}

sub _default_render_logout {
    my $self = shift;

    my $html = $self->app->query->start_html(-title=>'Logout');
    $html .= $self->app->query->h1("Logout");
    $html .= $self->app->query->end_html;
    return $html;
}

sub rm_login {
    my $app = shift;

    my $result = undef;
    for my $driver ( @{ $app->authrm->drivers } ){
        $result = $driver->authenticate;
        $app->log->debug("trying driver [$driver], result [".(defined $result ? $result : 'undef')."]");
        last if( $result );
    }

    unless( $result ){
        return $app->authrm->output_login;
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
                return $app->authrm->output_login;
            }
        }else{
            return $app->redirect($result);
        }
    }
}

sub rm_logout {
    my $app = shift;
    $app->authrm->logging_out;
    return $app->authrm->output_logout;
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
        $self->app->log->info("change rm from '${\$self->get_login_runmode}' to '${\$self->get_default_runmode}' because direct access to 'login'");
        $back_to = $self->get_default_runmode;
    }
    $self->app->log->debug("resumed run mode [$back_to]");
    return $back_to;
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

=head1 NAME

CGI::Application::Plugin::AuthRunmode::Base - basic controller for AuthRunmode

=head1 SYNOPSIS

    CGI::Application::Plugin::AuthRunmode::Base->new( $cgi_application, {
        'driver' => {
            'module' => 'HTPasswd',
            'params' => {
                'files' => [qw(/etc/htpasswd)],
                }
            }
        });

=head1 DESCRIPTION

TODO

=head1 SEE ALSO

L<CGI::Application::Plugin::AuthRunmode>

=head1 AUTHOR

WATANABE Hiroaki, E<lt>hwat@mac.comE<gt>

=head1 LICENSE

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut
