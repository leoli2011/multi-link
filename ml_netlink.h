#ifndef __RULE_H_
#define __RULE_H_
#include "ml_parse.h"

extern struct nl_sock* netlink_init(void);
extern int netlink_fini(struct nl_sock *sk);
extern int add_srcrule(struct nl_sock *sk, wan_if_t *wif);
extern int add_network_route(struct nl_sock *sk, wan_if_t *wif);
extern int del_network_route(struct nl_sock *sk, wan_if_t *wif);
extern int del_srcrule(struct nl_sock *sk, wan_if_t *wif);
extern int add_multipath_route(struct nl_sock *sk, wan_if_t *wif);
extern int del_multipath_route(struct nl_sock *sk);
extern int del_default_route(struct nl_sock *sk, wan_if_t *wif);
extern int add_default_route(struct nl_sock *sk, wan_if_t *wif);
extern int get_modem_if(wan_if_t *wif);

#endif
