#ToopherPerl

#### Introduction
ToopherPerl is a Toopher API library that simplifies the task of interfacing with the Toopher API from Perl code.  This project wrangles all the required OAuth and JSON functionality so you can focus on just using the API.

#### Learn the Toopher API
Make sure you visit (http://dev.toopher.com) to get acquainted with the Toopher API fundamentals.  The documentation there will tell you the details about the operations this API wrapper library provides.

#### OAuth Authentication
First off, to access the Toopher API you'll need to sign up for an account at the developers portal (http://dev.toopher.com) and create a "requester". When that process is complete, your requester is issued OAuth 1.0a credentials in the form of a consumer key and secret. Your key is used to identify your requester when Toopher interacts with your customers, and the secret is used to sign each request so that we know it is generated by you.  This library properly formats each request with your credentials automatically.

#### The Toopher Two-Step
At minimum, interacting with the Toopher web service involves two steps: pairing, and authenticating.

##### Pair
Before you can enhance your website's actions with Toopher, your customers will need to pair their phone's Toopher app with your website.  To do this, they generate a unique, nonsensical "pairing phrase" from within the app on their phone.  You will need to prompt them for a pairing phrase as part of the Toopher enrollment process.  Once you have a pairing phrase, just send it to the Toopher web service and we'll return a pairing ID that you can use whenever you want to authenticate an action for that user.

##### Authenticate
You have complete control over what actions you want to authenticate using Toopher (for example: logging in, changing account information, making a purchase, etc.).  Just send us the user's pairing ID, a name for the terminal they're using, and a description of the action they're trying to perform and we'll make sure they actually want it to happen.

#### Librarified
This library makes it super simple to do the Toopher two-step.  Check it out:

```perl
use ToopherAPI

# Create an API object using your credentials
my $api = new ToopherApi("<your consumer key>", "<your consumer secret>");

# Step 1 - Pair with their phone's Toopher app
my $pairing_status = $api->pair("pairing phrase", "username@yourservice.com");

# Step 2 - Authenticate a log in
my $auth = $api->authenticate($pairing_status->id, "my computer")

# Once they've responded you can then check the status
my $auth_status = $api->get_authentication_status($auth->id)
if (!($auth_status->pending) && $auth_status->granted){
        # Success!
}
```

#### Handling Errors
If any request runs into an error a `ToopherApiError` will be thrown with more details on what went wrong.

#### Zero-Storage usage option
Requesters can choose to integrate the Toopher API in a way does not require storing any per-user data such as Pairing ID and Terminal ID - all of the storage
is handled by the Toopher API Web Service, allowing your local database to remain unchanged.  If the Toopher API needs more data, it will `die()` with a specific
error string that allows your code to respond appropriately.

```perl
use Try::Tiny;
my $auth;
try {
  # optimistically try to authenticate against Toopher API with username and a Terminal Identifier
  # Terminal Identifer is typically a randomly generated secure browser cookie.  It does not
  # need to be human-readable
  $auth = $api->authenticate_by_user_name("username@yourservice.com", "<terminal identifier>");
  
  # if you got here, everything is good!  poll the auth request status as described above
} catch {
  # there are four distinct errors ToopherAPI can return if it needs more data
  if ($_ == ToopherAPI::ERROR_USER_DISABLED) {
    # you have marked this user as disabled in the Toopher API.
  } elsif ($_ == ToopherAPI::ERROR_UNKNOWN_USER) {
    # This user has not yet paired a mobile device with their account.  Pair them
    # using $api->pair() as described above, then re-try authentication
  } elsif ($_ == ToopherAPI::ERROR_UNKNOWN_TERMINAL) {
    # This user has not assigned a "Friendly Name" to this terminal identifier.
    # Prompt them to enter a terminal name, then submit that "friendly name" to
    # the Toopher API:
    #   $api->assign_user_friendly_name_to_terminal($user_name, $terminal_friendly_name, $terminal_identifier);
    # Afterwards, re-try authentication
  } elsif ($_ == ToopherAPI::ERROR_PAIRING_DEACTIVATED) {
    # this user does not have an active pairing,
    # typically because they deleted the pairing.  You can prompt
    # the user to re-pair with a new mobile device.
  }
};

```

#### Dependencies
To install dependencies necessary to use this module:

```shell
cpan install HTTP::Request::Common JSON LWP::UserAgent LWP::Protocol::https Net::OAuth::ConsumerRequest Class::Struct URI::Escape
```

#### Tests
Install the test dependencies:

```shell
$ cpan install Try::Tiny HTTP::Response Test::More URI URL::Encode
```

To execute the tests:

```shell
$ perl -Ilib t/01sanity.t
```

#### Try it out
demo script coming soon!
