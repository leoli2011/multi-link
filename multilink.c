#include <stdio.h>
#include <netdb.h>
#include <stdlib.h>
#include <ifaddrs.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <assert.h>
#include <syslog.h>
#include <getopt.h>
#include "multilink.h"
#include "ml_netlink.h"

static const char *confname = "/etc/multilink.conf";
//static const char *confname = "/tmp/multilink.conf";
static const char *pidfile = "/tmp/multilink.pid";
static const char* version = "0.1";

#define log_error  syslog

static int get_modem_if(char *ifname, struct sockaddr *addr);
static void sig_handler(int sig);
static struct nl_sock *sk;
static int signal_init();
//static void become_daemon();
static int clean_routing_rule(char active);
int clean_environment();
static int died = 0;


modem_if_info hosts[] =
{
#ifdef MODEM_ENVIRONMENT
    {"usb10", 100, "192.168.1.10", "192.168.1.0/24", "dev=usb10", "via=192.168.1.1"},
    {"usb20", 200, "192.168.2.10", "192.168.2.0/24", "dev=usb20", "via=192.168.2.1"},
    {"usb30", 300, "192.168.3.10", "192.168.3.0/24", "dev=usb30", "via=192.168.3.1"}

#elif  TEST_ENVIRONMENT
    {"enp1s0f1", 100, "1.1.1.10", "1.1.1.0/24", "dev=enp1s0f1", "via=1.1.1.1"},
    {"enp1s0f2", 200, "1.1.2.10", "1.1.2.0/24", "dev=enp1s0f2", "via=1.1.2.1"},
    {"enp1s0f3", 300, "1.1.3.10", "1.1.3.0/24", "dev=enp1s0f3", "via=1.1.3.1"}
#else
    {"wlp4s0", 100, "192.168.1.10", "192.168.1.0/24", "dev=wlp4s0", "via=192.168.1.1"},
    {"enp2s0", 200, "10.75.36.251", "10.75.36.0/23", "dev=enp2s0", "via=10.75.36.1"}
    //{"usb1", 200, "192.168.2.10", "192.168.2.0/24", "dev=usb1" },
    //{"usb2", 300, "192.168.3.10", "192.168.3.0/24", "dev=usb2" },
#endif
};

gateway_info gates[] =
{
#ifdef MODEM_ENVIRONMENT
    {"usb10", "192.168.1.1", 0},
    {"usb20", "192.168.2.1", 0},
    {"usb30", "192.168.3.1", 0}

#elif TEST_ENVIRONMENT
    {"enp1s0f1", "1.1.1.1", 0},
    {"enp1s0f2", "1.1.2.1", 0},
    {"enp1s0f3", "1.1.3.1", 0}
#else
    {"wlp4s0", "192.168.1.1", 0, },
    {"enp2s0", "10.75.36.1", 0, }
#endif
};

enum {
    USB10 = 100,
    USB20 = 200,
    USB30 = 300
};

char* const tid_string[] = {
    [USB10] = "100",
    [USB20] = "200",
    [USB30] = "300",
    NULL
};


//TODO: for main
//1, add configuration parser
//2, add the multi-thread function
int main(int argc, char **argv)
{
    int rc = -1;
    unsigned short  conftest = 0;
    int opt;
    int i;
    int default_added = 0;
    int active_cnt = 0;

    while ((opt = getopt(argc, argv, "h?vtc:p:")) != -1) {
        switch (opt) {
            case 't':
                conftest = 1;
                break;
            case 'c':
                confname = optarg;
                break;
            case 'p':
                pidfile = optarg;
                break;
            case 'v':
                puts(version);
                return EXIT_SUCCESS;
            default:
                printf(
                        "Usage: %s [-?hvt] [-c config] [-p pidfile]\n"
                        "  -h, -?       this message\n"
                        "  -v           print version\n"
                        "  -t           test config syntax\n"
                        "  -p           write pid to pidfile\n",
                        argv[0]);
                return (opt == '?' || opt == 'h') ? EXIT_SUCCESS : EXIT_FAILURE;
        }
    }

    //clean_environment();
    //become_daemon();

    log_error(LOG_NOTICE, "conftest = %d\n", conftest);
    FILE *f = fopen(confname, "r");
    if (!f) {
        log_error(LOG_ERR, "Unable to open config file");
        return EXIT_FAILURE;
    }

    if (pidfile) {
        f = fopen(pidfile, "w");
        if (!f) {
            log_error(LOG_ERR, "Unable to open pidfile for write");
            return EXIT_FAILURE;
        }
        fprintf(f, "%d\n", getpid());
        fclose(f);
    }

    log_error(LOG_NOTICE, "multi-link started");
    signal_init();

    sk = netlink_init();
    if (!sk)  {
        log_error(LOG_ERR, "Failed to request the netlink socket");
        return -1;
    }

    while(1) {

        if (died)
            break;

        struct sockaddr host_addr;
        modem_if_info *mif;
        for (i = 0; i < (int)SIZEOF_ARRAY(hosts); i++) {
            mif = &hosts[i];
            if (mif->active == 1) {
                continue;
            }

            rc = get_modem_if(mif->ifname, &host_addr);
            if (rc == 1) {
                rc = add_srcrule(sk, mif->tid, &host_addr);
                if (rc != 0) {
                    syslog(LOG_ERR, "Failed to add routing rule!");
                }

                syslog(LOG_ERR, "add routing rule successfully!");
                add_route(sk, mif->src, mif->dst, mif->nexthop, tid_string[mif->tid]);
                add_route(sk, NULL, "default", mif->rulegate, tid_string[mif->tid]);
                mif->active = 1;
                active_cnt++;
            }
        }

        if (!default_added && active_cnt > 2) {
            add_multipath_route(sk);
            gateway_info *gatei;
            for(i = 0; i < get_gates_len(); i++) {
                gatei = &gates[i];
                if (gatei->used == 0) {
                    break;
                }
            }

            if (i == get_gates_len()) {
                log_error(LOG_NOTICE, "Add the multipath route successfully!");
                default_added = 1;
            } else {
                log_error(LOG_NOTICE, "Failed to add the multipath route!, try again!");
            }
        } else if (active_cnt == 1) {
            for (i = 0; i < (int)SIZEOF_ARRAY(hosts); i++) {
                mif = &hosts[i];
                if (mif->active == 1) {
                    add_route(sk, NULL, "default", mif->rulegate, "main");
                }
            }
        }

        sleep(3);
    }

    log_error(LOG_NOTICE, "multilink goes down!");

    clean_routing_rule(0);

    if (pidfile) {
        remove(pidfile);
        log_error(LOG_DEBUG, "remove pidfile %s", pidfile);
    }

    if (sk) {
        netlink_fini(sk);
    }

    return rc;
}

int get_modem_if(char *ifname, struct sockaddr *addr)
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

static int signal_init(void)
{
    struct sigaction sigact;
    sigact.sa_handler = sig_handler;
    sigact.sa_flags = 0;
    sigemptyset(&sigact.sa_mask);
    sigaction(SIGUSR1, &sigact, NULL);
    sigaction(SIGUSR2, &sigact, NULL);
    sigaction(SIGTERM, &sigact, NULL);
    sigaction(SIGALRM, &sigact, NULL);
    sigaction(SIGCHLD, &sigact, NULL);
    sigaction(SIGINT, &sigact, NULL);

    sigact.sa_handler = SIG_IGN;
    sigaction(SIGHUP, &sigact, NULL);
    sigaction(SIGPIPE, &sigact, NULL);
    return 0;
}

static void sig_handler(int sig)
{
    syslog(LOG_NOTICE, "got the signal %d", sig);

    if (sig == SIGCHLD) {
        syslog(LOG_NOTICE, "got the signal SIGCHLD, do something");
    }
    else if (sig == SIGALRM) {
        syslog(LOG_NOTICE, "got the signal SIGALRM, do something");
    }
    else if (sig == SIGTERM) {
        syslog(LOG_NOTICE, "got the signal SIGTERM, exit");
        exit(EXIT_SUCCESS);
    }
    else if (sig == SIGUSR1) {
        syslog(LOG_NOTICE, "got the signal SIGUSR1, delete the rule and the table!");
        clean_routing_rule(1);
    }
    else if (sig == SIGUSR2) {
        syslog(LOG_NOTICE, "got the signal SIGUSR2, do clean action!");
        died = 1;
    }
    else if (sig == SIGINT) {
        syslog(LOG_NOTICE, "got the signal SIGINT, exit");
        exit(EXIT_SUCCESS);
    }

    fflush(NULL);
    return;
}


/*
static void become_daemon()
{
    int rc;
    pid_t pid;

    pid = fork();
    if (pid < 0) {
        syslog(LOG_ERR, "fork failed!");
        exit(EXIT_FAILURE);
    }

    if (pid > 0)
        exit(EXIT_SUCCESS);

    if (setsid() < 0)
        exit(EXIT_FAILURE);

    pid = fork();

    if (pid < 0)
        exit(EXIT_FAILURE);

    if (pid > 0)
        exit(EXIT_SUCCESS);

    umask(0);

    rc = chdir("/");
    if (rc != 0) {
        log_error(LOG_ERR, "Failed to change working directory!");
    }

    int x;
    for (x = sysconf(_SC_OPEN_MAX); x>=0; x--)
    {
        close (x);
    }

    openlog("multilink", LOG_PID, LOG_DAEMON);
    fflush(NULL);
}
*/

int clean_routing_rule(char active)
{
    int rc;
    modem_if_info *mif;
    struct sockaddr host_addr;
    int i = 0;

    for(i = 0; i <  (int)SIZEOF_ARRAY(hosts); i++) {
        mif = &hosts[i];
        if (mif->active == 1) {
            del_route(sk, NULL, mif->dst, mif->nexthop, tid_string[mif->tid]);
            del_route(sk, NULL, "default", mif->rulegate, tid_string[mif->tid]);
            rc = get_modem_if(mif->ifname, &host_addr);
            if (rc == 1) {
                rc = del_srcrule(sk, mif->tid, &host_addr);
                if (rc != 0) {
                    syslog(LOG_ERR, "Failed to delete routing rule!");
                }

                syslog(LOG_ERR, "delete routing rule successfully!");
                syslog(LOG_ERR, "active = %d", active);
                mif->active = active;
            }
        }
    }

    return 0;
}

int get_hosts_len()
{
    return SIZEOF_ARRAY(hosts);
}

int get_gates_len()
{
    return SIZEOF_ARRAY(gates);
}

int clean_environment()
{
    int rc;
    modem_if_info *mif;
    struct sockaddr host_addr;
    int i = 0;

    for(i = 0; i <  (int)SIZEOF_ARRAY(hosts); i++) {
        mif = &hosts[i];
        del_route(sk, NULL, mif->dst, mif->nexthop, tid_string[mif->tid]);
        del_route(sk, NULL, "default", mif->rulegate, tid_string[mif->tid]);
        rc = get_modem_if(mif->ifname, &host_addr);
        if (rc == 1) {
            rc = del_srcrule(sk, mif->tid, &host_addr);
            if (rc != 0) {
                syslog(LOG_ERR, "Failed to delete routing rule!");
            }

            syslog(LOG_ERR, "delete routing rule successfully!");
            mif->active = 0;
        }
    }

    return 0;
}

