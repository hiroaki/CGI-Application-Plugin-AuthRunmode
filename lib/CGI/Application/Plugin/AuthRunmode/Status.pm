package CGI::Application::Plugin::AuthRunmode::Status;

# $Id $

use strict;
use warnings;
use vars qw($VERSION);
$VERSION = '0.01';

use overload '""' => \&stringify;

# http://cpansearch.perl.org/src/GAAS/libwww-perl-5.834/lib/HTTP/Status.pm
our %messages = (
    100 => 'Continue',
    101 => 'Switching Protocols',
    102 => 'Processing',                      # RFC 2518 (WebDAV)
    200 => 'OK',
    201 => 'Created',
    202 => 'Accepted',
    203 => 'Non-Authoritative Information',
    204 => 'No Content',
    205 => 'Reset Content',
    206 => 'Partial Content',
    207 => 'Multi-Status',                    # RFC 2518 (WebDAV)
    300 => 'Multiple Choices',
    301 => 'Moved Permanently',
    302 => 'Found',
    303 => 'See Other',
    304 => 'Not Modified',
    305 => 'Use Proxy',
    307 => 'Temporary Redirect',
    400 => 'Bad Request',
    401 => 'Unauthorized',
    402 => 'Payment Required',
    403 => 'Forbidden',
    404 => 'Not Found',
    405 => 'Method Not Allowed',
    406 => 'Not Acceptable',
    407 => 'Proxy Authentication Required',
    408 => 'Request Timeout',
    409 => 'Conflict',
    410 => 'Gone',
    411 => 'Length Required',
    412 => 'Precondition Failed',
    413 => 'Request Entity Too Large',
    414 => 'Request-URI Too Large',
    415 => 'Unsupported Media Type',
    416 => 'Request Range Not Satisfiable',
    417 => 'Expectation Failed',
    422 => 'Unprocessable Entity',            # RFC 2518 (WebDAV)
    423 => 'Locked',                          # RFC 2518 (WebDAV)
    424 => 'Failed Dependency',               # RFC 2518 (WebDAV)
    425 => 'No code',                         # WebDAV Advanced Collections
    426 => 'Upgrade Required',                # RFC 2817
    449 => 'Retry with',                      # unofficial Microsoft
    500 => 'Internal Server Error',
    501 => 'Not Implemented',
    502 => 'Bad Gateway',
    503 => 'Service Unavailable',
    504 => 'Gateway Timeout',
    505 => 'HTTP Version Not Supported',
    506 => 'Variant Also Negotiates',         # RFC 2295
    507 => 'Insufficient Storage',            # RFC 2518 (WebDAV)
    509 => 'Bandwidth Limit Exceeded',        # unofficial
    510 => 'Not Extended',                    # RFC 2774
    );

sub new {
    my $class = shift;
    my $self = {
        'code' => shift || '500',
        };
    bless $self, $class;
    return $self;
}

sub stringify {
    $_[0]->{'code'};
}

sub code {
    my $self = shift;
    return @_ ? $self->{'code'} = shift : $self->{'code'};
}

sub status_message {
    $messages{shift->code};
}
sub is_info {
    my $code = shift->code; 100 <= $code and $code < 200;
}
sub is_success {
    my $code = shift->code; 200 <= $code and $code < 300;
}
sub is_redirect {
    my $code = shift->code; 300 <= $code and $code < 400;
}
sub is_error {
    my $code = shift->code; 400 <= $code and $code < 600;
}
sub is_client_error {
    my $code = shift->code; 400 <= $code and $code < 500;
}
sub is_server_error {
    my $code = shift->code; 500 <= $code and $code < 600;
}

1;

=head1 NAME

CGI::Application::Plugin::AuthRunmode::Status - status of result for AuthRunmode

=head1 SYNOPSIS

    $authrm->status(
        CGI::Application::Plugin::AuthRunmode::Status->new('401')
        );

=head1 DESCRIPTION

TODO

It does not relate though it refers to HTTP status codes. 

=head1 SEE ALSO

L<CGI::Application::Plugin::AuthRunmode>
L<CGI::Application::Plugin::AuthRunmode::Driver>
L<HTTP::Status>

=head1 AUTHOR

WATANABE Hiroaki, E<lt>hwat@mac.comE<gt>

=head1 LICENSE

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut
