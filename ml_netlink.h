#ifndef __RULE_H_
#define __RULE_H_

extern struct nl_sock* netlink_init(void);
extern int netlink_fini(struct nl_sock *sk);
extern int add_srcrule(struct nl_sock *sk, unsigned short tid, struct sockaddr *host);
extern int add_route(struct nl_sock *sk, char *saddr, char *daddr, char* nexthop, char* tid);
extern int del_route(struct nl_sock *sk, char *saddr, char *daddr, char* nexthop, char* tid);
extern int del_srcrule(struct nl_sock *sk, unsigned short tid, struct sockaddr *host);
extern int add_multipath_route(struct nl_sock *sk);

#endif
