use 5.008001;
use ExtUtils::MakeMaker;
# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.
WriteMakefile(
    NAME              => 'CGI::Application::Plugin::AuthRunmode',
    VERSION_FROM      => 'lib/CGI/Application/Plugin/AuthRunmode.pm', # finds $VERSION
    PREREQ_PM         => {
        CGI::Application => 4.31,
        CGI::Application::Plugin::Forward => 1.06,
        CGI::Application::Plugin::LogDispatch => 1.02,
        CGI::Application::Plugin::Redirect => 1.00,
        CGI::Application::Plugin::Session => 1.03,
        Class::Data::Inheritable => 0.08,
        UNIVERSAL::require => 0.13,
        }, # e.g., Module::Name => 1.1
    ($] >= 5.005 ?     ## Add these new keywords supported since 5.005
      (ABSTRACT_FROM  => 'lib/CGI/Application/Plugin/AuthRunmode.pm', # retrieve abstract from module
       AUTHOR         => 'WATANABE Hiroaki <hwat@mac.com>') : ()),
);
