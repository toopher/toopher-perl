use strict;
use warnings;
use Module::Build;

my $builder = Module::Build->new(
    module_name         => 'ToopherAPI',
    license             => 'perl',
    dist_abstract       => 'ToopherAPI - Toopher API wrapper in Perl',
    dist_author         => 'Toopher <dev@toopher.com>',
);

$builder->create_build_script();
