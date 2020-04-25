#include <stdio.h>
#include "Configure.h"

struct ccl_t  configure()
{
    struct ccl_t                  config;
    const struct ccl_pair_t       *iter;

    config.comment_char = '#';
    config.sep_char = '=';
    config.str_char = '"';

    ccl_parse(&config, "/home/logan/CLionProjects/Capture/mytest.conf");

    while((iter = ccl_iterate(&config)) != 0) {
        printf("%s: %s\n", iter->key, iter->value);
    }
    struct ccl_t config_rel = config;

    ccl_release(&config);

    return config_rel;
}