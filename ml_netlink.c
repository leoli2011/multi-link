#include <stdio.h>
#include <syslog.h>
#include <linux/fib_rules.h>
#include <linux/netlink.h>
#include <netlink/route/rule.h>
#include <netlink/cli/utils.h>
#include <netlink/cli/route.h>
#include <netlink/cli/link.h>
#include "multilink.h"

static struct nl_cache *link_cache, *route_cache;
static int add_nexthop(gateway_info *gatei, struct rtnl_route *mproute, struct nl_sock *sk);

#define GET_RULE_PRIORITY2(a, b) a##b;
#define GET_RULE_PRIORITY(a, b) GET_RULE_PRIORITY2(a, b)
#define RULE_PRIORITY_PRIFIX  30000

int add_srcrule(struct nl_sock *sk, unsigned short tid, struct sockaddr *host)
{
    struct rtnl_rule *rule = rtnl_rule_alloc();
    if (!rule) {
        syslog(LOG_NOTICE, "Failed to alloc rule");
        rtnl_rule_put(rule);
        return -1;
    }

    struct sockaddr_in *src = (struct sockaddr_in *)host;
    rtnl_rule_set_family(rule, src->sin_family);
    rtnl_rule_set_table(rule, tid);
    rtnl_rule_set_action(rule, FR_ACT_TO_TBL);

    tid += RULE_PRIORITY_PRIFIX;
    syslog(LOG_NOTICE, "add rule table tid=%d", tid);
    rtnl_rule_set_prio(rule, tid);

    struct nl_addr *sourceaddr = nl_addr_build(src->sin_family, &src->sin_addr, sizeof(struct in_addr));
    if (!sourceaddr) {
        rtnl_rule_put(rule);
        nl_addr_put(sourceaddr);
        syslog(LOG_ERR, "Failed to build source addr");
        return -1;
    }

    nl_addr_set_prefixlen(sourceaddr, 32);
    int error = rtnl_rule_set_src(rule, sourceaddr);
    syslog(LOG_NOTICE, "error = %d, build source addr", error);

    error = rtnl_rule_add(sk, rule, NLM_F_REPLACE);

    syslog(LOG_ERR, "add rule for address %x to lookup table 0x%x",
                    *(unsigned int*)&src->sin_addr, tid);

    return 0;
}

int del_srcrule(struct nl_sock *sk, unsigned short tid, struct sockaddr *host)
{
    struct rtnl_rule *rule = rtnl_rule_alloc();
    if (!rule) {
        syslog(LOG_NOTICE, "Failed to alloc rule");
        rtnl_rule_put(rule);
        return -1;
    }

    struct sockaddr_in *src = (struct sockaddr_in *)host;
    rtnl_rule_set_family(rule, src->sin_family);
    rtnl_rule_set_table(rule, tid);
    rtnl_rule_set_action(rule, FR_ACT_TO_TBL);

    tid += RULE_PRIORITY_PRIFIX;
    syslog(LOG_NOTICE, "delete rule table tid=%d", tid);
    rtnl_rule_set_prio(rule, tid);

    struct nl_addr *sourceaddr = nl_addr_build(src->sin_family, &src->sin_addr, sizeof(struct in_addr));
    if (!sourceaddr) {
        rtnl_rule_put(rule);
        nl_addr_put(sourceaddr);
        syslog(LOG_ERR, "Failed to build source addr");
        return -1;
    }

    nl_addr_set_prefixlen(sourceaddr, 32);
    int error = rtnl_rule_set_src(rule, sourceaddr);
    syslog(LOG_NOTICE, "error = %d, build source addr", error);

    error = rtnl_rule_delete(sk, rule, NLM_F_REPLACE);

    syslog(LOG_ERR, "delete rule for address %x to lookup table %d", 
                    *(unsigned int*)&src->sin_addr, tid);

    return 0;
}


int add_route(struct nl_sock *sk, char *saddr, char *daddr, char* nexthop, char* tid)
{

    int err = 1;
    struct rtnl_route *route;
    struct nl_dump_params dp = {
        .dp_type = NL_DUMP_LINE,
        .dp_fd = stdout,
    };

    link_cache = nl_cli_link_alloc_cache(sk);
    route_cache = nl_cli_route_alloc_cache(sk, 0);
    route = nl_cli_route_alloc();

    if (saddr) {
        //nl_cli_route_parse_src(route, saddr);
        nl_cli_route_parse_pref_src(route, saddr);
    }

    nl_cli_route_parse_dst(route, daddr);
    nl_cli_route_parse_nexthop(route, nexthop, link_cache);
    nl_cli_route_parse_table(route, tid);

    if ((err = rtnl_route_add(sk, route, NLM_F_EXCL)) < 0) {
        syslog(LOG_ERR, "Unable to add route: %s", nl_geterror(err));
        goto OUT;
    }

    syslog(LOG_NOTICE, "Added ");
    nl_object_dump(OBJ_CAST(route), &dp);

    syslog(LOG_NOTICE, "route for src address %s, dst %s, nexthop %s, table %s ", 
                    saddr, daddr, nexthop, tid);

    err = 0;
OUT:
    nl_cache_free(link_cache);
    nl_cache_free(route_cache);
    rtnl_route_put(route);

    return err;
}

int del_route(struct nl_sock *sk, char *saddr, char *daddr, char* nexthop, char* tid)
{

    int err = 1;
    struct rtnl_route *route;
    struct nl_dump_params dp = {
        .dp_type = NL_DUMP_LINE,
        .dp_fd = stdout,
    };

    link_cache = nl_cli_link_alloc_cache(sk);
    route_cache = nl_cli_route_alloc_cache(sk, 0);
    route = nl_cli_route_alloc();

    if (saddr) {
        nl_cli_route_parse_pref_src(route, saddr);
    }

    nl_cli_route_parse_dst(route, daddr);
    nl_cli_route_parse_nexthop(route, nexthop, link_cache);
    nl_cli_route_parse_table(route, tid);

    if ((err = rtnl_route_delete(sk, route, 0)) < 0) {
        syslog(LOG_ERR, "Unable to delete route: %s", nl_geterror(err));
        goto OUT;
    }

    syslog(LOG_NOTICE, "Deleted");
    nl_object_dump(OBJ_CAST(route), &dp);

    syslog(LOG_NOTICE, "delete route for src address %s, dst %s, nexthop %s, table %s ", 
                    saddr, daddr, nexthop, tid);

    err = 0;
OUT:

    nl_cache_free(link_cache);
    nl_cache_free(route_cache);
    rtnl_route_put(route);

    return err;
}

struct nl_sock* netlink_init(void)
{
    int err;
    struct nl_sock *sk;

    sk = nl_socket_alloc();
    if ((err = nl_connect(sk, NETLINK_ROUTE)) < 0) {
        nl_perror(err, "Unable to connect socket");
        return NULL;
    }

    return sk;
}

int netlink_fini(struct nl_sock *sk)
{
    if (sk) {
        nl_socket_free(sk);
    }

    return 0;
}

/*
int add_multipath_route(struct nl_sock *sk)
{

    int err = 1;
    struct rtnl_route *route;
    struct nl_dump_params dp = {
        .dp_type = NL_DUMP_LINE,
        .dp_fd = stdout,
    };

    link_cache = nl_cli_link_alloc_cache(sk);
    route_cache = nl_cli_route_alloc_cache(sk, 0);
    route = nl_cli_route_alloc();


    int i = 0;
    modem_if_info *mif;
    nl_cli_route_parse_dst(route, "default");
    for(i = 0; i < get_hosts_len(); i++) {
        mif = &hosts[i];
        if (mif->active == 1) {
            nl_cli_route_parse_nexthop(route, mif->nexthop, link_cache);
        }
    }

    nl_cli_route_parse_dst(route, "default");
    nl_cli_route_parse_scope(route, "global");

            //nl_cli_route_parse_nexthop(route, "via=192.168.1.1,dev=wlp4s0,weight=1", link_cache);
            nl_cli_route_parse_nexthop(route, "via=10.75.36.1", link_cache);

    nl_cli_route_parse_table(route, "main");

    if ((err = rtnl_route_add(sk, route, NLM_F_EXCL)) < 0) {
        syslog(LOG_ERR, "Unable to add multipath default route: %s", nl_geterror(err));
        goto OUT;
    }

    syslog(LOG_NOTICE, "Added ");
    nl_object_dump(OBJ_CAST(route), &dp);

    syslog(LOG_NOTICE, "add route for multipath default successfully!");


    err = 0;
OUT:
    nl_cache_free(link_cache);
    nl_cache_free(route_cache);
    rtnl_route_put(route);
    return 0;
}
*/

int add_multipath_route(struct nl_sock *sk)
{
    int ret = -1;
    struct nl_addr *addr;

    struct rtnl_route* mproute = rtnl_route_alloc();
    if (!mproute) {
        syslog(LOG_ERR, "Failed to alloc memory for route");
        return ret;
    }

    rtnl_route_set_scope(mproute, RT_SCOPE_UNIVERSE);
    rtnl_route_set_table(mproute, RT_TABLE_MAIN);
    rtnl_route_set_protocol(mproute, RTPROT_STATIC);

    ret = nl_addr_parse("default", AF_INET, &addr);
    if (ret != 0) {
        syslog(LOG_NOTICE, "Unable to parse dst IP address");
        goto OUT;
    }

    ret = rtnl_route_set_dst(mproute, addr);
    if (ret != 0) {
        syslog(LOG_NOTICE, "Error in setting destination route");
        goto OUT;
    }

    int i = 0;
    gateway_info *gatei;
    for(i = 0; i < get_gates_len(); i++) {
        gatei = &gates[i];
        if (gatei->used == 0) {
            ret = add_nexthop(gatei, mproute, sk);
            if  (ret == 0) {
                gatei->used = 1;
            }
        }
    }

    ret = rtnl_route_add(sk, mproute, 0);
    if (ret != 0) {
        syslog(LOG_ERR, "Kernel response : %s", nl_geterror(ret) );
    }

    ret = 0;
OUT:

    if (ret == 0) {
        syslog(LOG_ERR, "Added route successfully!");
    }

    /*
    if  (mproute)
        rtnl_route_put(mproute);
    */

    return ret;
}

static int add_nexthop(gateway_info *gatei, struct rtnl_route *mproute, struct nl_sock *sk)
{
    int ret = -1;
    struct rtnl_nexthop* nh = NULL;
    struct nl_addr *gatewayaddr;

    syslog(LOG_NOTICE,"Add next ifname=%s, gate_addr=%s, weight=%d", 
           gatei->ifname, gatei->gate_addr, gatei->weight);
    link_cache = nl_cli_link_alloc_cache(sk);
    nh = rtnl_route_nh_alloc();
    if (!nh) {
        syslog(LOG_ERR, "Failed to alloc memory for nexthop!");
        goto OUT;
    }

    ret = rtnl_link_name2i(link_cache, gatei->ifname);
    if (!ret) {
        syslog(LOG_ERR,"Link \"%s\" does not exist", gatei->ifname);
        ret = -1;
        goto OUT;
    }
    rtnl_route_nh_set_ifindex(nh, ret);

    ret = nl_addr_parse(gatei->gate_addr, AF_INET, &gatewayaddr);
    if (ret < 0) {
        syslog(LOG_ERR,"Unable to parse IP address");
        goto OUT;
    }
    rtnl_route_nh_set_gateway(nh, gatewayaddr);
    nl_addr_put(gatewayaddr);

    rtnl_route_nh_set_weight(nh,gatei->weight);

    rtnl_route_add_nexthop(mproute, nh);

    ret = 0;
OUT:

    nl_cache_free(link_cache);
    /*  delete later
    if (nh)
        rtnl_route_nh_free(nh);
    */

    if (ret == 0) {
        syslog(LOG_NOTICE,"Add nexthop for ifname=%s, successfully", gatei->ifname);
    } else {
        syslog(LOG_NOTICE,"Failed to add nexthop for ifname=%s", gatei->ifname);
    }

    return ret;
}
