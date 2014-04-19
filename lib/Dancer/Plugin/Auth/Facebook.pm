package Dancer::Plugin::Auth::Facebook;

$Dancer::Plugin::Auth::Facebook::VERSION = '0.02';

use strict;
use warnings;

use Dancer ':syntax';
use Dancer::Plugin;
use Net::Facebook::Oauth2;
use Carp 'croak';

my $_FB;
sub facebook { $_FB }
register 'facebook' => \&facebook;

my $application_id;
my $application_secret;
my $cb_url;
my $cb_success;
my $cb_fail;
my $fb_scope;
my @scope;

register 'auth_fb_init' => sub {
  my $config = plugin_setting;
  $application_id       = $config->{application_id};
  $application_secret   = $config->{application_secret};
  $cb_url               = $config->{callback_url};

  $cb_success           = $config->{callback_success} || '/';
  $cb_fail              = $config->{callback_fail} || '/fail';
  $fb_scope             = $config->{scope};

  if (defined $fb_scope) {
    foreach my $fs (split(/\s+/, $fb_scope)) {
      next unless ($fs =~  m/^[_A-Za-z0-9\.]+$/);
      push(@scope, $fs);
    }
  }
  else {
    push(@scope, 'email');
  }

  for my $param (qw/application_id application_secret callback_url/) {
    croak "'$param' is expected but not found in configuration" unless $config->{$param};
  }

  debug "new facebook with $application_id, $application_secret, $cb_url";

  $_FB = Net::Facebook::Oauth2->new(
    application_id => $application_id,  ##get this from your facebook developers platform
    application_secret => $application_secret, ##get this from your facebook developers platform
    callback => $cb_url,  ##Callback URL, facebook will redirect users after authintication
  );

};

register 'auth_fb_authenticate_url' => sub {
  if (not defined facebook ) {
    croak "auth_fb_init must be called first";
  }

  my $url = facebook->get_authorization_url(
      scope => \@scope,
      display => 'page',
  );

  session access_token  => '';
  debug "fb_auth_url: $url";

  return $url;
};

get '/auth/facebook/callback' => sub {
  debug "entering facebook callback";

  return redirect $cb_fail if (params->{'error'});

  my $access_token = session('access_token');

  if (!$access_token) {
    $access_token = facebook->get_access_token(code => params->{'code'});
    return $cb_fail if ! $access_token;
    session access_token  => $access_token;
  }

  my $fb = Net::Facebook::Oauth2->new(
       access_token => $access_token,
  );

  my $me = $fb->get(
      'https://graph.facebook.com/me',
  );

  my $fb_hash  = $me->as_hash;
  my $username = $fb_hash->{'username'};
  my $name     = $fb_hash->{'name'};
  my $mail_add =  $fb_hash->{'email'};

  session fb_username => $username;
  session fb_name     =>  $name;
  session fb_email    => $mail_add;

  redirect $cb_success;
};

register_plugin;

1;

__END__

=pod

=head1 NAME

Dancer::Plugin::Auth::Facebook - Authenticate with Facebook OAuth

=head1 VERSION

version 0.02

=head1 SYNOPSIS

package plugin::test;
use Dancer ':syntax';
use Dancer::Plugin::Auth::Facebook;

our $VERSION = '0.1';

auth_fb_init();

hook before =>  sub {
  #we don't want a redirect loop here.
  return if request->path =~ m{/auth/facebook/callback};
  if (not session('fb_username')) {
     redirect auth_fb_authenticate_url;
  }
};

get '/' => sub {
  "welcome, ".session('fb_name');
};

get '/fail' => sub { "FAIL" };

true;

...

=head1 CONCEPT

This plugin provides a simple way to authenticate your users through Facebook's
OAuth API. It provides you with a helper to build easily a redirect to the
authentication URL, defines automatically a callback route handler and saves the
authenticated user to your session when done.

=head1 PREREQUESITES

In order for this plugin to work, you need the following:

=over 4

=item * Facebook application

Anyone can register a application at L<https://developers.facebook.com/>. When
done, make sure to configure the application as a I<Web> application.

=item * Configuration

You need to configure the plugin first: copy your C<application_id> and C<application_secret>
(provided by Facebook) to your Dancer's configuration under
C<plugins/Auth::Facebook>:

# config.yml
...
plugins:
  Auth::Facebook
    application_id: "1234"
    application_secret: "abcd"
    callback_url: "http://localhost:3000/auth/facebook/callback"
    callback_success: "/"
    callback_fail: "/fail"
    scope: "email friends"

C<callback_success> , C<callback_fail> and <scope> are optional and default to
'/' , '/fail', and 'email' respectively.

Note that you also need to provide your callback url, whose route handler is automatically
created by the plugin.

=item * Session backend

For the authentication process to work, you need a session backend, in order for
the plugin to store the authenticated user's information.

Use the session backend of your choice, it doesn't make a difference, see
L<Dancer::Session> for details about supported session engines, or
L<search the CPAN for new ones|http://search.cpan.org/search?query=Dancer-Session>.

=back

=head1 EXPORT

The plugin exports the following symbols to your application's namespace:

=head2 facebook

The plugin uses a L<Net::Facebook::Oauth2> object to do its job. You can access this
object with the C<facebook> symbol, exported by the plugin.

=head2 auth_fb_init

This function should be called before your route handlers, in order to
initialize the underlying L<Net::Facebook::Oauth2> object. It will read your
configuration and create a new L<Net::Facebook::Oauth2> instance.

=head2 auth_fb_authenticate_url

this function returns an authentication URL for redirecting unauthenticated users.

hook before => sub {
   # we don't want a redirect loop here.
  return if request->path =~ m{/auth/facebook/callback};
  if (not session('fb_username')) {
    redirect auth_fb_authenticate_url();
  }
};


=head1 ROUTE HANDLERS

The plugin defines the following route handler automatically

=head2 /auth/facebook/callback

This route handler is responsible for catching back a user that has just
authenticated herself with Facebook's OAuth. The route handler saves tokens and
user information such as email,username and name in the session and then redirects the user to the URI
specified by C<callback_success>.

If the validation of the token returned by Facebook failed or was denied,
the user will be redirect to the URI specified by C<callback_fail>.

=head1 ACKNOWLEDGEMENTS

This project is a  port of L<Dancer::Plugin::Auth::Twitter> written by Alexis Sukrieh which itself is a port of
L<Catalyst::Authentication::Credential::Twitter> written by Jesse Stay.


=head1 AUTHORS

=over 4

=item *

Prajith Ndimensionz <prajith@ndimensionz>

=item *

=back

=head1 COPYRIGHT AND LICENSE

This software is copyright (c) 2014 by Prajith Ndimensionz.

This is free software; you can redistribute it and/or modify it under
the same terms as the Perl 5 programming language system itself.

=cut
