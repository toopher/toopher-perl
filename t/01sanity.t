#!/usr/bin/perl

use ToopherAPI;
use Try::Tiny;
use Test::More;

use constant TRUE => 1;
use constant FALSE => 0;

# H/T to http://perldesignpatterns.com/?InnerClasses for this "inner class" design pattern
my $ua = eval {
  package UA_Mock;
  use HTTP::Response;
  use URI;
  use URL::Encode qw ( url_params_mixed );
  sub new {
    my ($class) = @_;
    my $self = {
      '_response' => new HTTP::Response(200),
      '_last_request' => {}
    };
    return bless $self, $class;
  }
  sub request
  {
    my ($self, $request) = @_;
    if ($request) {
      $request->{'post_data'} = url_params_mixed($request->content);
      if (URI->new($request->uri)->query) {
        $request->{'query_data'} = url_params_mixed(URI->new($request->uri)->query);
      }
      $self->{'_last_request'} = $request;
      return $self->{'_response'};
    } else {
      return $self->{'_last_request'};
    }
  }
  sub response
  {
    my ($self) = @_;
    return $self->{'_response'};
  }
  __PACKAGE__;
}->new($code, $message);




my $api = new ToopherAPI(key => 'foo', secret => 'bar', ua => $ua);

subtest 'test version UA string' => sub {
  $ua->response->code(200);
  $ua->response->content('{"id":"1", "enabled":true, "user":{"id":"1","name":"some user"}}');
  $api->pair('awkward turtle', 'some user');
  is($ua->request->header('User-Agent'), "toopher-perl/" . ToopherAPI::VERSION . " (perl " . $] . " on " . $^O . ")");
};

subtest 'create pairing' => sub {
  $ua->response->code(200);
  $ua->response->content('{"id":"1", "enabled":true, "user":{"id":"1","name":"some user"}}');
  my $pairing = $api->pair('awkward turtle', 'some user');
  is($ua->request->method, 'POST');
  is($ua->request->{'post_data'}->{'pairing_phrase'}, 'awkward turtle');
  is($pairing->id, '1');
};

subtest 'create sms pairing' => sub {
  $ua->response->code(200);
  $ua->response->content('{"id":"1", "enabled":true, "user":{"id":"1","name":"some user"}}');
  my $pairing = $api->pair_sms('1234', 'some user');
  is($ua->request->method, 'POST');
  is($ua->request->{'post_data'}->{'phone_number'}, '1234');
  is($pairing->id, '1');
};

subtest 'pairing status' => sub {
  $ua->response->content('{"id":"1", "enabled":true, "user":{"id":"1","name":"some user"}}');
  my $pairing = $api->get_pairing_status('1');
  is($ua->request->method, 'GET');
  is($pairing->id, '1');
  is($pairing->user_name, 'some user');
  is($pairing->user_id, '1');
  is($pairing->enabled, TRUE);
};

subtest 'create authentication request' => sub {
  $ua->response->content('{"id":"1", "pending":false, "granted":true, "automated":false, "reason":"its a test", "terminal":{"id":"1", "name":"test terminal"}}');
  my $auth_request = $api->authenticate('1', 'test terminal');
  is($ua->request->method, 'POST');
  is($ua->request->{'post_data'}->{'pairing_id'}, '1');
  is($ua->request->{'post_data'}->{'terminal_name'}, 'test terminal');
};

subtest 'authenticate by user name' => sub {
  $ua->response->content('{"id":"1", "pending":false, "granted":true, "automated":false, "reason":"its a test", "terminal":{"id":"1", "name":"test terminal"}}');
  my $auth_request = $api->authenticate_by_user_name('some other user', 'random string', '', {'random_key' => '42'});
  is($ua->request->method, 'POST');
  is($ua->request->{'post_data'}->{'user_name'}, 'some other user');
  is($ua->request->{'post_data'}->{'terminal_name_extra'}, 'random string');
  is($ua->request->{'post_data'}->{'random_key'}, '42');
  is($ua->request->{'post_data'}->{'terminal_name'}, '');
};

subtest 'authenticate with otp' => sub {
  $ua->response->content('{"id":"1", "pending":false, "granted":true, "automated":false, "reason":"its a test", "terminal":{"id":"1", "name":"test terminal"}}');
  my $auth_request = $api->get_authentication_status_with_otp('1', '123456');
  is($ua->request->method, 'POST');
  is($ua->request->{'post_data'}->{'otp'}, '123456');
};


subtest 'authentication status' => sub {
  $ua->response->content('{"id":"1", "pending":false, "granted":true, "automated":false, "reason":"its a test", "terminal":{"id":"1", "name":"test terminal"}}');
  my $auth_request = $api->get_authentication_status('1');
  is($ua->request->method, 'GET');
  is($auth_request->id, '1');
  is($auth_request->pending, FALSE);
  is($auth_request->granted, TRUE);
  is($auth_request->reason, 'its a test');
  is($auth_request->terminal_id, '1');
  is($auth_request->terminal_name, 'test terminal');
};

subtest 'arbitrary parameters on pair' => sub {
  $ua->response->content('{"id":"1", "enabled":true, "user":{"id":"1","name":"some user"}}');
  my $pairing = $api->pair('awkward turtle', 'some user', {'test_param' => '42'});
  is($ua->request->method, 'POST');
  is($ua->request->{'post_data'}->{'pairing_phrase'}, 'awkward turtle');
  is($ua->request->{'post_data'}->{'test_param'}, '42');
};

subtest 'arbitrary parameters on authenticate' => sub {
  $ua->response->content('{"id":"1", "pending":false, "granted":true, "automated":false, "reason":"its a test", "terminal":{"id":"1", "name":"test terminal"}}');
  my $auth_request = $api->authenticate('1', 'test terminal', '', {'test_param' => '42'});
  is($ua->request->method, 'POST');
  is($ua->request->{'post_data'}->{'pairing_id'}, '1');
  is($ua->request->{'post_data'}->{'terminal_name'}, 'test terminal');
  is($ua->request->{'post_data'}->{'test_param'}, '42');
};

subtest 'access arbitrary keys in pairing status' => sub {
  $ua->response->content('{"id":"1", "enabled":true, "user":{"id":"1","name":"some user"}, "random_key":"84"}');
  my $pairing = $api->get_pairing_status('1');
  is($ua->request->method, 'GET');
  is($pairing->id, '1');
  is($pairing->user_name, 'some user');
  is($pairing->user_id, '1');
  is($pairing->enabled, TRUE);
  is($pairing->_raw->{'random_key'}, '84');
};

subtest 'access arbitrary keys in authentication status' => sub {
  $ua->response->content('{"id":"1", "pending":false, "granted":true, "automated":false, "reason":"its a test", "terminal":{"id":"1", "name":"test terminal"}, "random_key":"84"}');
  my $auth_request = $api->get_authentication_status('1');
  is($ua->request->method, 'GET');
  is($auth_request->id, '1');
  is($auth_request->pending, FALSE);
  is($auth_request->granted, TRUE);
  is($auth_request->automated, FALSE);
  is($auth_request->reason, 'its a test');
  is($auth_request->terminal_id, '1');
  is($auth_request->terminal_name, 'test terminal');
  is($auth_request->_raw->{'random_key'}, '84');
};

subtest 'disabled user raises correct error' => sub {
  $ua->response->code(409);
  $ua->response->content('{"error_code":704, "error_message":"The specified user has disabled Toopher authentication."}');
  try {
    my $auth_request = $api->authenticate_by_user_name('some disabled user', 'some random string');
    fail('Should have died before here');
  } catch {
    is($_, ToopherAPI::ERROR_USER_DISABLED);
  };
};

subtest 'unknown user raises correct error' => sub {
  $ua->response->code(409);
  $ua->response->content('{"error_code":705, "error_message":"No matching user exists."}');
  try {
    my $auth_request = $api->authenticate_by_user_name('some unknown user', 'some random string');
    fail('Should have died before here');
  } catch {
    is($_, ToopherAPI::ERROR_USER_UNKNOWN);
  };
};

subtest 'unknown terminal raises correct error' => sub {
  $ua->response->code(409);
  $ua->response->content('{"error_code":706, "error_message":"No matching terminal exists."}');
  try {
    my $auth_request = $api->authenticate_by_user_name('some unknown user', 'some random string');
    fail('Should have died before here');
  } catch {
    is($_, ToopherAPI::ERROR_TERMINAL_UNKNOWN);
  };
};

subtest 'disabled pairing raises correct error' => sub {
  $ua->response->code(403);
  $ua->response->content('{"error_code":601, "error_message":"This pairing has been deactivated."}');
  try {
    my $auth_request = $api->authenticate_by_user_name('some deactivated user', 'some random string');
    fail('Should have died before here');
  } catch {
    is($_, ToopherAPI::ERROR_PAIRING_DEACTIVATED);
  };
};

subtest 'unauthorized pairing raises correct error' => sub {
  $ua->response->code(403);
  $ua->response->content('{"error_code":601, "error_message":"This pairing has not been authorized to authenticate."}');
  try {
    my $auth_request = $api->authenticate_by_user_name('some unauthorized user', 'some random string');
    fail('Should have died before here');
  } catch {
    is($_, ToopherAPI::ERROR_PAIRING_DEACTIVATED);
  };
};

done_testing();

# vim: ts=2:sw=2:expandtab:autoindent
