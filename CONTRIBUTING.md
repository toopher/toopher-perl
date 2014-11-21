# ToopherAPI Perl Client

#### Perl Version
>= 5.0.0

#### Installing Dependencies
Toopher uses [CPAN](http://www.cpan.org/).

To ensure all dependencies are up-to-date run:
```shell
$ cpan install HTTP::Request::Common JSON LWP::UserAgent LWP::Protocol::https Net::OAuth::ConsumerRequest Class::Struct URI::Escape
```

To ensure test dependencies are installed enter:
```shell
$ cpan install Try::Tiny HTTP::Response Test::More URI URL::Encode
```

Note: You may need to use `sudo` for OSX.

#### Tests
To run the tests enter:
```shell
$ perl -Ilib t/01sanity.t
```
