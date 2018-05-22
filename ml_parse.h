#ifndef __ML_PARSE_H
#define __ML_PARSE_H

struct global_config {
    char name[64];
    char value[64];
};

typedef struct free_app_info_s {
    char name[64];
    char ip[17];
    char port[7];
} free_app_info_t;

struct app_list {
    char name[64];
    char value[64];
};

extern int parse_conf(FILE *f);


#endif
