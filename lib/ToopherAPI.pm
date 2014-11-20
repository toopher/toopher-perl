package ToopherAPI;
use strict;
use warnings;

use Net::OAuth::ConsumerRequest;
use HTTP::Request::Common qw{ GET POST };
use JSON qw{ decode_json };
use LWP::UserAgent;
use Class::Struct;
use URI::Escape;
use constant VERSION => "1.1.0";
use constant DEFAULT_TOOPHER_API => 'https://api.toopher.com/v1/';
use constant ERROR_CODE_USER_DISABLED => 704;
use constant ERROR_CODE_USER_UNKNOWN => 705;
use constant ERROR_CODE_TERMINAL_UNKNOWN => 706;
use constant ERROR_USER_DISABLED => "The specified user has disabled Toopher Authentication\n";
use constant ERROR_USER_UNKNOWN => "No matching user exists\n";
use constant ERROR_TERMINAL_UNKNOWN => "No matching terminal exists\n";
use constant ERROR_PAIRING_DEACTIVATED => "Pairing has been deactivated\n";

sub base_log{
  print $_[0];
}

our $_log = \&base_log;

sub new
{
  my ($class, %args) = @_;

  if(! exists $args{'key'}){
    die("Must supply consumer key\n");
  }
  if(! exists $args{'secret'}){
    die("Must supply consumer secret\n");
  }

  my $api_url = $args{'api_url'} ? $args{'api_url'} : DEFAULT_TOOPHER_API;

  my $ua = $args{'ua'} ? $args{'ua'} : LWP::UserAgent::new();
  my $self = {
    _api_url => $api_url,
    _ua => $ua,
    _key => $args{'key'},
    _secret => $args{'secret'},
  };

  bless $self, $class;
  return $self;
}

sub pair
{
  my ($self, $pairing_phrase, $user_name, $extras) = @_;
  my $params = $extras || {};
  $params->{'pairing_phrase'} = $pairing_phrase;
  $params->{'user_name'} = $user_name;
  return _pairingStatusFromJson($self->post('pairings/create', $params));
}

sub pair_sms
{
  my($self, $phone_number, $user_name, $phone_country, $extras) = @_;
  my $params = $extras || {};
  $params->{'phone_number'} = $phone_number;
  $params->{'user_name'} = $user_name;
  $params->{'phone_country'} = $phone_country if $phone_country;
  return _pairingStatusFromJson($self->post('pairings/create/sms', $params));
}

sub get_pairing_status
{
  my($self, $pairing_request_id) = @_;
  return _pairingStatusFromJson($self->get('pairings/' . $pairing_request_id));
}

sub authenticate_by_user_name
{
  my ($self, $user_name, $terminal_name_extra, $action_name, $extras) = @_;
  my $params = $extras || {};
  $params->{'user_name'} = $user_name;
  $params->{'terminal_name_extra'} = $terminal_name_extra;
  return $self->authenticate('','',$action_name, $params);
}

sub authenticate
{
  my ($self, $pairing_id, $terminal_name, $action_name, $extras) = @_;
  my $params = $extras || {};
  $params->{'pairing_id'} = $pairing_id;
  $params->{'terminal_name'} = $terminal_name;
  $params->{'action_name'} = $action_name if $action_name;
  return _authenticationStatusFromJson($self->post('authentication_requests/initiate', $params));
}

sub get_authentication_status
{
  my($self, $authentication_request_id) = @_;
  return _authenticationStatusFromJson($self->get('authentication_requests/' . $authentication_request_id));
}

sub get_authentication_status_with_otp
{
  my($self, $authentication_request_id, $otp) = @_;
  my $params = {
    'otp' => $otp,
  };
  return _authenticationStatusFromJson($self->post('authentication_requests/' . $authentication_request_id . '/otp_auth', $params));
}

sub create_user_terminal
{
  my ($self, $user_name, $terminal_name, $terminal_name_extra) = @_;
  my $params = {
    'user_name' => $user_name,
    'name' => $terminal_name,
    'name_extra' => $terminal_name_extra,
  };
  return $self->post('user_terminals/create', $params);
}

sub set_toopher_enabled_for_user
{
  my ($self, $user_name, $enabled) = @_;
  my $params = {
    'name' => $user_name,
  };

  my @users = @{$self->get('users', $params)};
  if (scalar @users > 1) {
    die "Multiple users with name = $user_name";
  }
  if (scalar @users == 0) {
    die "No users with name = $user_name";
  }

  my $user_id = $users[0]->{'id'};

  $params = {
    'disable_toopher_auth' => $enabled ? 'false' : 'true',
  };
  return $self->post('users/' . $user_id, $params);
}

struct(
  PairingStatus => [
    id => '$',
    pending => '$',
    enabled => '$',
    user_id => '$',
    user_name => '$',
    _raw => '$',
  ]
);
struct(
  AuthenticationStatus => [
    id => '$',
    pending => '$',
    granted => '$',
    automated => '$',
    reason => '$',
    terminal_id => '$',
    terminal_name => '$',
    _raw => '$',
  ]
);

sub _pairingStatusFromJson
{
  my ($obj) = @_;
  PairingStatus->new(
    id => $obj->{'id'},
    pending => $obj->{'pending'},
    enabled => $obj->{'enabled'},
    user_id => $obj->{'user'}{'id'},
    user_name => $obj->{'user'}{'name'},
    _raw => $obj,
  );
}
sub _authenticationStatusFromJson
{
  my ($obj) = @_;
  return AuthenticationStatus->new(
    id => $obj->{'id'},
    pending => $obj->{'pending'},
    granted => $obj->{'granted'},
    automated => $obj->{'automated'},
    reason => $obj->{'reason'},
    terminal_id => $obj->{'terminal'}{'id'},
    terminal_name => $obj->{'terminal'}{'name'},
    _raw => $obj,
  );
}

sub get
{
  my ($self, $endpoint, $params) = @_;
  if ($params) {
    $endpoint .= '?';
    my $separator = '';
    foreach my $key (keys %{$params}){
      $endpoint = $endpoint . $key . '=' . uri_escape(${$params}{$key}) . $separator;
      $separator = '&';
    }
  }
  my $url = $self->{'_api_url'} . $endpoint;
  my $req = GET $url;
  return $self->request($req, {});
}
sub post
{
  my ($self, $endpoint, $params) = @_;
  my $url = $self->{'_api_url'} . $endpoint;
  my $req = POST $url, [%$params];
  return $self->request($req, $params);
}

sub request
{
  my ($self, $req,  $params) = @_;
  my $oaRequest = Net::OAuth::ConsumerRequest->new(
    consumer_key => $self->{_key},
    consumer_secret => $self->{_secret},
    request_url => $req->uri,
    request_method => $req->method,
    timestamp => time,
    nonce => substr ((rand() . ""), 2),
    signature_method => 'HMAC-SHA1',
    extra_params => $params,
  );
  $oaRequest->sign;

  $req->header('Authorization' => $oaRequest->to_authorization_header);
  $req->header('User-Agent' => "toopher-perl/" . VERSION . " (perl " . $] . " on " . $^O . ")");
  my $response = $self->{_ua}->request($req);

  if ($response->code >= 300) {
    _parse_request_error($response);
  }

  my $jsonObj;
  eval {
    $jsonObj = decode_json($response->content);
  } or die "Error decoding JSON response: " . $@;

  return $jsonObj;
}

sub _parse_request_error
{
  my ($response) = @_;
  if ($response->content) {
    my $errObj = 0;
    eval {
      $errObj = decode_json($response->content);
    };
    if ($errObj) {
      if($errObj->{'error_code'} == ERROR_CODE_USER_DISABLED) {
        die ERROR_USER_DISABLED;
      } elsif ($errObj->{'error_code'} == ERROR_CODE_USER_UNKNOWN) {
        die ERROR_USER_UNKNOWN;
      } elsif ($errObj->{'error_code'} == ERROR_CODE_TERMINAL_UNKNOWN) {
        die ERROR_TERMINAL_UNKNOWN;
      } else {
        if (($errObj->{'error_message'} =~ /pairing has been deactivated/i)
            || ($errObj->{'error_message'} =~ /pairing has not been authorized/i)) {
          die ERROR_PAIRING_DEACTIVATED;
        }
      }
    } else {
      die $response->status_line . ' ' . $response->content;
    }
  } else {
    die $response->status_line;
  }
}
1;
