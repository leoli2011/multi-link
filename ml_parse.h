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

typedef struct wan_if_s  {
    char ifname[20];
    char table[20];
    char weight[20];
    char src[32];
    char dst[32];
    char nexthop[32];
    char gateway[32];
    char active;
    char found;
} wan_if_t;

#endif
