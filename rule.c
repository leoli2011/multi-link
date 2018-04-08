#include <stdio.h>
#include <syslog.h>
#include <linux/fib_rules.h>
#include <linux/netlink.h>
#include <netlink/route/rule.h>
#include <netlink/cli/utils.h>
#include <netlink/cli/route.h>
#include <netlink/cli/link.h>

static struct nl_cache *link_cache, *route_cache;

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
    
    struct nl_addr *sourceaddr = nl_addr_build(src->sin_family, &src->sin_addr, sizeof(struct in_addr));
    if (!sourceaddr) {
        rtnl_rule_put(rule);
        nl_addr_put(sourceaddr);
        syslog(LOG_ERR, "Failed to build source addr");
        return -1;
    }

    nl_addr_set_prefixlen(sourceaddr, 32);
    int error = rtnl_rule_set_src(rule, sourceaddr);
    syslog(LOG_ERR, "error = %d, build source addr", error);

    error = rtnl_rule_add(sk, rule, NLM_F_REPLACE);
              
    syslog(LOG_ERR, "add rule for address %d to lookup table %x for interface", 
                    *(unsigned int*)&src->sin_addr, tid);

    return 0;
}

int add_route(struct nl_sock *sk, char *saddr, char *daddr, char* nexthop, char *tid)
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
        nl_cli_route_parse_src(route, saddr);
    }

    nl_cli_route_parse_dst(route, daddr);
    nl_cli_route_parse_nexthop(route, nexthop, link_cache);
    nl_cli_route_parse_table(route, tid);

    if ((err = rtnl_route_add(sk, route, NLM_F_EXCL)) < 0)
        nl_cli_fatal(err, "Unable to add route: %s", nl_geterror(err));

    printf("Added ");
    nl_object_dump(OBJ_CAST(route), &dp);
                                
    syslog(LOG_NOTICE, "add route for src address %s, dst %s, nexthop %s, table %s ", 
                    saddr, daddr, nexthop, tid);

    return 0;
}


struct nl_sock* netlink_init()
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
	nl_close(sk);
    return 0;
}
