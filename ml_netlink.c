#include <stdio.h>
#include <syslog.h>
#include <ifaddrs.h>
#include <linux/fib_rules.h>
#include <arpa/inet.h>
#include <netlink/route/rule.h>
#include <netlink/cli/utils.h>
#include <netlink/cli/route.h>
#include <netlink/cli/link.h>
#include <netlink/cli/addr.h>
#include <linux/netlink.h>
#include <netinet/in.h>
#include "ml_parse.h"
#include "multilink.h"

static struct nl_cache *link_cache, *route_cache;
static int add_nexthop(wan_if_t *wif, struct rtnl_route *mproute, struct nl_sock *sk);
static int read_dhcp_info(wan_if_t *wif);

#define GET_RULE_PRIORITY2(a, b) a##b;
#define GET_RULE_PRIORITY(a, b) GET_RULE_PRIORITY2(a, b)
#define RULE_PRIORITY_PRIFIX  30000
#define MODEM_DHCP_CONFIG          "/data/local/tmp/dhcp_config"

static int get_modem_addr(const char *ifname, struct sockaddr *addr)
{
    struct ifaddrs *ip, *ifa;
    int s;
    char host[NI_MAXHOST];
    char found = 0;

    if (getifaddrs(&ip) == -1) {
        syslog(LOG_NOTICE, "getifaddrs");
        return -1;
    }

    for (ifa = ip; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL) {
            continue;
        }

        if (ifa->ifa_addr->sa_family != AF_INET) {
            continue;
        }

        s = getnameinfo(ifa->ifa_addr, sizeof(struct sockaddr_in), host, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
        if (s != 0) {
            syslog(LOG_ERR, "ifa_name=%s family=%s getnameinfo() failed: %s\n",
                    ifa->ifa_name,
                    (ifa->ifa_addr->sa_family == AF_PACKET) ? "AF_PACKET" :
                    (ifa->ifa_addr->sa_family == AF_INET) ? "AF_INET" :
                    (ifa->ifa_addr->sa_family == AF_INET6) ? "AF_INET6" : "???",
                    gai_strerror(s)
                  );
            continue;
        }

        if ((strncmp(ifa->ifa_name, ifname, strlen(ifname))==0)&&(ifa->ifa_addr->sa_family==AF_INET)) {
            syslog(LOG_NOTICE, "ifname=%s family=%s IP=%s\n",
                    ifa->ifa_name,
                    (ifa->ifa_addr->sa_family == AF_PACKET) ? "AF_PACKET" :
                    (ifa->ifa_addr->sa_family == AF_INET) ? "AF_INET" : "???",
                    host);

            memcpy(addr, ifa->ifa_addr, sizeof(struct sockaddr));
            found = 1;
            break;
        }
    }

    freeifaddrs(ip);
    return found;
}

int add_srcrule(struct nl_sock *sk, wan_if_t *mif)
{
    struct rtnl_rule *rule = rtnl_rule_alloc();
    if (!rule) {
        syslog(LOG_NOTICE, "Failed to alloc rule");
        rtnl_rule_put(rule);
        return -1;
    }

    struct sockaddr host_addr;
    get_modem_addr(mif->ifname, &host_addr);
    struct sockaddr_in *src = (struct sockaddr_in *)&host_addr;
    rtnl_rule_set_family(rule, src->sin_family);

    unsigned int tid = atoi(mif->table);
    rtnl_rule_set_table(rule, tid);
    rtnl_rule_set_action(rule, FR_ACT_TO_TBL);

    tid += RULE_PRIORITY_PRIFIX;
    rtnl_rule_set_prio(rule, tid);
    tid -= RULE_PRIORITY_PRIFIX;

    struct nl_addr *sourceaddr = nl_addr_build(src->sin_family, &src->sin_addr, sizeof(struct in_addr));
    if (!sourceaddr) {
        rtnl_rule_put(rule);
        nl_addr_put(sourceaddr);
        syslog(LOG_ERR, "Failed to build source addr");
        return -1;
    }

    nl_addr_set_prefixlen(sourceaddr, 32);
    int error = rtnl_rule_set_src(rule, sourceaddr);

    error = rtnl_rule_add(sk, rule, NLM_F_REPLACE);

    syslog(LOG_ERR, "Added: rule for address %s to lookup table %s, error=%d",
                    mif->src, mif->table, error);

    return error;
}

int del_srcrule(struct nl_sock *sk, wan_if_t *mif)
{
    struct rtnl_rule *rule = rtnl_rule_alloc();
    if (!rule) {
        syslog(LOG_NOTICE, "Failed to alloc rule");
        rtnl_rule_put(rule);
        return -1;
    }

    struct sockaddr host_addr;
    get_modem_addr(mif->ifname, &host_addr);
    struct sockaddr_in *src = (struct sockaddr_in *)&host_addr;
    rtnl_rule_set_family(rule, src->sin_family);

    unsigned int tid = atoi(mif->table);
    rtnl_rule_set_table(rule, tid);
    rtnl_rule_set_action(rule, FR_ACT_TO_TBL);

    tid += RULE_PRIORITY_PRIFIX;
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

    error = rtnl_rule_delete(sk, rule, NLM_F_REPLACE);

    syslog(LOG_ERR, "Delete rule for src address %s to lookup table %s, error=%d",
                    mif->src, mif->table, error);

    return error;
}

int add_network_route(struct nl_sock *sk, wan_if_t *wif)
{
    int err = -1;
    char buf[32] = {0};
    struct nl_dump_params dp = {
        .dp_type = NL_DUMP_LINE,
        .dp_fd = stdout,
    };

    int if_index = 0;
    int table;
    char *endptr = NULL;
    struct nl_cache *link_cache = NULL;
    struct nl_cache *route_cache = NULL;
    struct rtnl_route *route = NULL;
    struct nl_addr *src = NULL;
    struct nl_addr *dst = NULL;
    struct rtnl_nexthop *nh = NULL;

    if (sk == NULL || wif == NULL) {
        syslog(LOG_ERR, "the parameters of input is NULL.");
        goto OUT;
    }

    err = rtnl_link_alloc_cache(sk, AF_INET, &link_cache);
    if (err < 0) {
        syslog(LOG_ERR, "Failed to alloc link cache: %s", nl_geterror(err));
        goto OUT;
    }

    err = rtnl_route_alloc_cache(sk, AF_INET, 0, &route_cache);
    if (err < 0) {
        syslog(LOG_ERR, "Failed to alloc route cache: %s", nl_geterror(err));
        goto OUT;
    }

    route = rtnl_route_alloc();
    if (!route) {
        syslog(LOG_ERR, "Failed to alloc route entry: %s", nl_geterror(err));
        goto OUT;
    }

    err = nl_addr_parse(wif->src, AF_INET, &src);
    if (err < 0) {
        syslog(LOG_ERR, "Failed to parsing src address: %s", nl_geterror(err));
        goto OUT;
    }

    err = rtnl_route_set_pref_src(route, src);
    if (err < 0) {
        syslog(LOG_ERR, "Failed to set preferred src address: %s", nl_geterror(err));
        goto OUT;
    }

    err = nl_addr_parse(wif->dst, AF_INET, &dst);
    if (err < 0) {
        syslog(LOG_ERR, "Failed to parsing dst address: %s", nl_geterror(err));
        goto OUT;
    }

    err = rtnl_route_set_dst(route, dst);
    if (err < 0) {
        syslog(LOG_ERR, "Failed to set destination address: %s", nl_geterror(err));
        goto OUT;
    }

    nh = rtnl_route_nh_alloc();
    if (nh == NULL) {
        syslog(LOG_ERR, "Failed to alloc nexthop entry: %s", nl_geterror(err));
        goto OUT;
    }

    if_index = rtnl_link_name2i(link_cache, wif->nexthop);
    if (if_index == 0) {
        syslog(LOG_ERR, "Failed to get %s's interface index", wif->nexthop);
        goto OUT;
    }

    rtnl_route_nh_set_ifindex(nh, if_index);
    rtnl_route_add_nexthop(route, nh);

    table = strtoul(wif->table, &endptr, 0);
    if ((errno == ERANGE && (table == LONG_MAX || table == LONG_MIN))
            || (errno != 0 && table == 0)) {
        syslog(LOG_ERR, "Failed to do strtol conversion");
        goto OUT;
    }

    rtnl_route_set_table(route, table);
    if ((err = rtnl_route_add(sk, route, NLM_F_EXCL)) < 0) {
        syslog(LOG_ERR, "Unable to add route: %s", nl_geterror(err));
        goto OUT;
    }

    nl_object_dump(OBJ_CAST(route), &dp);

    syslog(LOG_NOTICE, "Added route for src address %s, dst %s, nexthop %s, table %s ",
                       wif->src, wif->dst, wif->nexthop, wif->table);

    err = 0;
OUT:
    if (link_cache) {
        nl_cache_free(link_cache);
        link_cache = NULL;
    }
    if (route_cache) {
        nl_cache_free(route_cache);
        route_cache = NULL;
    }
    if (route) {
        rtnl_route_put(route);
        route = NULL;
    }
    if (src) {
        nl_addr_put(src);
        src = NULL;
    }
    if (dst) {
        nl_addr_put(dst);
        dst = NULL;
    }
    if (nh) {
        rtnl_route_nh_free(nh);
        nh = NULL;
    }

    return err;
}

int add_default_route(struct nl_sock *sk, wan_if_t *wif)
{
    int err = 1;
    char buf[32] = {0};
    struct rtnl_route *route;
    struct nl_dump_params dp = {
        .dp_type = NL_DUMP_LINE,
        .dp_fd = stdout,
    };

    link_cache = nl_cli_link_alloc_cache(sk);
    route_cache = nl_cli_route_alloc_cache(sk, 0);
    route = nl_cli_route_alloc();

    nl_cli_route_parse_dst(route, "default");
    snprintf(buf, sizeof(wif->gateway), "via=%s", wif->gateway);
    nl_cli_route_parse_nexthop(route, buf, link_cache);
    nl_cli_route_parse_table(route, wif->table);

    if ((err = rtnl_route_add(sk, route, NLM_F_EXCL)) < 0) {
        syslog(LOG_ERR, "Unable to add route: %s", nl_geterror(err));
        goto OUT;
    }

    nl_object_dump(OBJ_CAST(route), &dp);

    syslog(LOG_NOTICE, "Added default route for table %s, src %s nexthop %s",
                        wif->table, wif->src, wif->gateway);

    err = 0;
OUT:
    nl_cache_free(link_cache);
    nl_cache_free(route_cache);
    rtnl_route_put(route);

    return err;
}

int del_network_route(struct nl_sock *sk, wan_if_t *wif)
{
    int err = 1;
    char buf[32] = {0};
    struct rtnl_route *route;
    struct nl_dump_params dp = {
        .dp_type = NL_DUMP_LINE,
        .dp_fd = stdout,
    };

    link_cache = nl_cli_link_alloc_cache(sk);
    route_cache = nl_cli_route_alloc_cache(sk, 0);
    route = nl_cli_route_alloc();

    nl_cli_route_parse_pref_src(route, wif->src);
    nl_cli_route_parse_dst(route, wif->dst);
    snprintf(buf, sizeof(wif->nexthop), "dev=%s", wif->nexthop);
    nl_cli_route_parse_nexthop(route, buf, link_cache);
    nl_cli_route_parse_table(route, wif->table);

    if ((err = rtnl_route_delete(sk, route, 0)) < 0) {
        syslog(LOG_ERR, "Unable to delete route: %s", nl_geterror(err));
        goto OUT;
    }

    nl_object_dump(OBJ_CAST(route), &dp);

    syslog(LOG_NOTICE, "Delete: route for src address %s, dst %s, nexthop %s, table %s ",
                       wif->src, wif->dst, wif->nexthop, wif->table);

    err = 0;
OUT:

    nl_cache_free(link_cache);
    nl_cache_free(route_cache);
    rtnl_route_put(route);

    return err;
}

int del_default_route(struct nl_sock *sk, wan_if_t *wif)
{

    int err = 1;
    char buf[32] = {0};
    struct rtnl_route *route;
    struct nl_dump_params dp = {
        .dp_type = NL_DUMP_LINE,
        .dp_fd = stdout,
    };

    link_cache = nl_cli_link_alloc_cache(sk);
    route_cache = nl_cli_route_alloc_cache(sk, 0);
    route = nl_cli_route_alloc();

    nl_cli_route_parse_dst(route, "default");
    snprintf(buf, sizeof(wif->gateway), "via=%s", wif->gateway);
    nl_cli_route_parse_nexthop(route, buf, link_cache);
    nl_cli_route_parse_table(route, wif->table);

    if ((err = rtnl_route_delete(sk, route, 0)) < 0) {
        syslog(LOG_ERR, "Unable to delete route: %s", nl_geterror(err));
        goto OUT;
    }

    nl_object_dump(OBJ_CAST(route), &dp);

    syslog(LOG_NOTICE, "Delete: route for src: %s, dst: default, gateway: %s, table %s ",
                       wif->src, wif->gateway, wif->table);

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

int add_multipath_route(struct nl_sock *sk, wan_if_t *wif)
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
    rtnl_route_set_priority(mproute, 5);

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

    for(int i = 0; i < get_wan_cnt(); i++) {
        if (wif->active == 1) {
            add_nexthop(wif, mproute, sk);
        }
        wif++;
    }

    ret = rtnl_route_add(sk, mproute, 0);
    if (ret != 0) {
        syslog(LOG_ERR, "Failed to add multi route, Kernel response : %s", nl_geterror(ret) );
        goto OUT;
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

int del_multipath_route(struct nl_sock *sk)
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
    rtnl_route_set_priority(mproute, 5);

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

    ret = rtnl_route_delete(sk, mproute, 0);
    if (ret != 0) {
        syslog(LOG_ERR, "Kernel response : %s", nl_geterror(ret) );
    }

    ret = 0;
OUT:

    if (ret == 0) {
        syslog(LOG_ERR, "delete multipath route successfully!");
    }

    /*
    if  (mproute)
        rtnl_route_put(mproute);
    */

    return ret;
}

static int add_nexthop(wan_if_t *wif, struct rtnl_route *mproute, struct nl_sock *sk)
{
    int ret = -1;
    struct rtnl_nexthop* nh = NULL;
    struct nl_addr *gatewayaddr;

    syslog(LOG_NOTICE,"Add next ifname=%s, gate_addr=%s, weight=%s",
                      wif->ifname, wif->gateway, wif->weight);
    link_cache = nl_cli_link_alloc_cache(sk);
    nh = rtnl_route_nh_alloc();
    if (!nh) {
        syslog(LOG_ERR, "Failed to alloc memory for nexthop!");
        goto OUT;
    }

    ret = rtnl_link_name2i(link_cache, wif->ifname);
    if (!ret) {
        syslog(LOG_ERR,"Link \"%s\" does not exist", wif->ifname);
        ret = -1;
        goto OUT;
    }
    rtnl_route_nh_set_ifindex(nh, ret);

    ret = nl_addr_parse(wif->gateway, AF_INET, &gatewayaddr);
    if (ret < 0) {
        syslog(LOG_ERR,"Unable to parse IP address");
        goto OUT;
    }
    rtnl_route_nh_set_gateway(nh, gatewayaddr);
    nl_addr_put(gatewayaddr);

    unsigned int weight = atoi(wif->weight);
    rtnl_route_nh_set_weight(nh, weight);

    rtnl_route_add_nexthop(mproute, nh);

    ret = 0;
OUT:

    nl_cache_free(link_cache);
    /*  delete later
    if (nh)
        rtnl_route_nh_free(nh);
    */

    if (ret == 0) {
        syslog(LOG_NOTICE,"Add nexthop for ifname=%s, successfully", wif->ifname);
    } else {
        syslog(LOG_NOTICE,"Failed to add nexthop for ifname=%s", wif->ifname);
    }

    return ret;
}

static void feed_modem_if(struct nl_object *obj, void *arg)
{
    wan_if_t *wif = (wan_if_t *)arg;
    struct rtnl_addr *addr = (struct rtnl_addr *)obj;
    char buf[128];
    char *tmp = NULL;
    char prefix_len = 0;
    uint32_t netmask = 0;
    uint32_t src_addr = 0;
    int rc = -1;

    if (wif == NULL || addr == NULL) {
        return;
    }

    nl_addr2str(rtnl_addr_get_local(addr), buf, sizeof(buf));
    tmp = strchr(buf, '/');
    if (tmp) {
        *tmp++ = '\0';
        snprintf(wif->src, sizeof(wif->src), "%s", buf);
    }

    prefix_len = atoi(tmp);
    netmask = ~((1 << (32 - prefix_len)) - 1);

    inet_pton(AF_INET, buf, &src_addr);
    src_addr = htonl((ntohl(src_addr) & netmask));
    inet_ntop(AF_INET, &src_addr, buf, sizeof(buf));

    snprintf(wif->dst, sizeof(wif->dst), "%s/%d", buf, prefix_len);
    snprintf(wif->nexthop, sizeof(wif->nexthop), "%s", wif->ifname);

    if (strcmp(wif->ifname, "usb10") == 0) {
        snprintf(wif->gateway, sizeof(wif->gateway), "%s", "192.168.1.1");

    } else if (strcmp(wif->ifname, "usb20") == 0) {
        snprintf(wif->gateway, sizeof(wif->gateway), "%s", "192.168.2.1");

    } else if (strcmp(wif->ifname, "usb30") == 0) {
        snprintf(wif->gateway, sizeof(wif->gateway), "%s", "192.168.3.1");

    } else if (strcmp(wif->ifname, "usb40") == 0) {
        syslog(LOG_ERR, "modem name:%s US modem, got ip from dhcp client!", wif->ifname);
        rc = read_dhcp_info(wif);
        if (rc) {
            syslog(LOG_ERR, "modem name:%s Failed to got the IP address", wif->ifname);
            return;
        }
    } else {
        syslog(LOG_ERR, "modem name:%s Can not got the IP address", wif->ifname);
        return;
    }

    wif->found = 1;
    syslog(LOG_ERR, "modem name:%s src=%s dst=%s, nexthop=%s, gateway=%s",
                    wif->ifname, wif->src, wif->dst, wif->nexthop, wif->gateway);
    return;
}

int get_modem_if(wan_if_t *wif)
{
    struct nl_sock *sock;
    struct rtnl_addr *addr;
    struct nl_cache *link_cache, *addr_cache;
    int ifindex;

    sock = nl_cli_alloc_socket();
    nl_cli_connect(sock, NETLINK_ROUTE);
    link_cache = nl_cli_link_alloc_cache(sock);
    addr_cache = nl_cli_addr_alloc_cache(sock);
    addr = nl_cli_addr_alloc();

    ifindex = rtnl_link_name2i(link_cache, wif->ifname);
    if (!ifindex) {
        syslog(LOG_ERR, "modem name:%s does not exist.", wif->ifname);
        return -1;
    }
    rtnl_addr_set_ifindex(addr, ifindex);
    rtnl_addr_set_family(addr, AF_INET);

    nl_cache_foreach_filter(addr_cache, OBJ_CAST(addr), feed_modem_if, wif);
    return 0;
}

static int read_dhcp_info(wan_if_t *wif)
{
    FILE *fp;
    int rc = -1;
    char buf[128] = {0};

    fp = fopen(MODEM_DHCP_CONFIG, "r");
    if (!fp) {
        syslog(LOG_ERR, "Unable to open file %s for read", MODEM_DHCP_CONFIG);
        return rc;
    }

    while(fgets(buf, sizeof(buf), fp)) {
        if (strstr(buf, "ADDR=")) {
            syslog(LOG_NOTICE, "got the addr=%s", buf+strlen("ADDR="));

        } else if (strstr(buf, "GATEWAY=")) {
            buf[strlen(buf) - 1 ] = '\0';
            snprintf(wif->gateway, sizeof(wif->gateway), "%s", buf+strlen("GATEWAY="));
            syslog(LOG_NOTICE, "got the gateway=%s", wif->gateway);
        } else if (strstr(buf, "PREFIXLEN=")) {
            syslog(LOG_NOTICE, "got the prefixlen=%s", buf+strlen("PREFIXLEN="));

        } else {
            syslog(LOG_NOTICE, "got the content %s", buf);
        }
    }

    rc = 0;

    if (fp) {
        fclose(fp);
    }

    return rc;
}
