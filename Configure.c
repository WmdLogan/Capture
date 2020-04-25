#include <stdio.h>
#include "Configure.h"

struct ccl_t configure()
{
    struct ccl_t config;
    config.comment_char = '#';
    config.sep_char = '=';
    config.str_char = '"';

    ccl_parse(&config, "/home/logan/CLionProjects/Capture/mytest.conf");
    return config;
}
/*int main(){
    struct ccl_t re = configure();
    const struct ccl_pair_t *iter;
    while((iter = ccl_iterate(&re)) != 0) {
        printf("%s: %s\n", iter->key, iter->value);
    }
    ccl_release(&re);
    return 0;
}*/
