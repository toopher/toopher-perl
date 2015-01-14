use strict;
use warnings;
use Module::Build;

my $builder = Module::Build->new(
    module_name         => 'ToopherAPI',
    license             => 'perl',
    dist_abstract       => 'ToopherAPI - Toopher API wrapper in Perl',
    dist_author         => 'Toopher <dev@toopher.com>',
    dist_version        => '1.0.0',
    build_requires => {
        'Test::More' => 0,
        'Test::Exception' => 0,
        'Devel::Cover::Report::Coveralls' => 0,
        'HTTP::Request::Common' => 0,
        'JSON' => 0,
        'LWP::UserAgent' => 0,
        'LWP::Protocol::https' => 0,
        'Net::OAuth::ConsumerRequest' => 0,
        'Class::Struct' => 0,
        'URI::Escape' => 0,
        'Try::Tiny' => 0,
        'HTTP::Response' => 0,
        'URI' => 0,
        'URL::Encode' => 0
    },
);

$builder->create_build_script();
