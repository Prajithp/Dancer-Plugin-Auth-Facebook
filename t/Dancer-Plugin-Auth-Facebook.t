use strict;
use warnings;

use Test::More import => ['!pass'];
plan tests => 11;

package FBMock;
use Test::More;

sub as_hash { {username => 'foo', name => 'bar', email => 'a@b.co'} }

sub get_access_token { 9876 }

sub get {
  is @_, 2, 'FBMock: passed two elements to get()';
  my ($self, $arg) = @_;

  isa_ok $self, 'Net::Facebook::Oauth2', 'FBMock: object checks ok';
  is $arg, 'https://graph.facebook.com/me', 'FBMock: arguments check on get()';

  return bless {}, 'FBMock';
}


package main;

{
    use Dancer;

    # settings must be loaded before we load the plugin
    setting(plugins => {
        'Auth::Facebook' => {
            application_id     => 1234,
            application_secret => 5678,
            callback_url       => 'http://myserver:3000/auth/facebook/callback',
            callback_success   => '/ok',
            callback_fail      => '/not-ok',
            scope              => 'basic_info  email user_birthday',
        },
    });

    eval 'use Dancer::Plugin::Auth::Facebook';
    die $@ if $@;
    ok 1, 'plugin loaded successfully';

    ok auth_fb_init(), 'able to load auth_fb_init()';

    ok my $fb = facebook(), 'facebook object is available to apps';
    isa_ok $fb, 'Net::Facebook::Oauth2';

    is auth_fb_authenticate_url(),
       'https://www.facebook.com/dialog/oauth?client_id=1234&redirect_uri=http%3A%2F%2Fmyserver%3A3000%2Fauth%2Ffacebook%2Fcallback&scope=basic_info,email,user_birthday&display=page',
       'auth_fb_authenticate_url() returns the proper facebook auth url';
}

use Dancer::Test;

route_exists [ GET => '/auth/facebook/callback' ], 'facebook auth callback route exists';

{
    no warnings 'redefine';
    *Net::Facebook::Oauth2::get = *FBMock::get;
    *Net::Facebook::Oauth2::get_access_token = *FBMock::get_access_token;
}

my $res = dancer_response( GET => '/auth/facebook/callback' );
is $res->status, 302, 'auth callback redirects user';

is_deeply session('fb_user'), {
    username => 'foo',
    name     => 'bar',
    email    => 'a@b.co',
}, 'got data from facebook mock';

