#include <stdio.h>
#include <netdb.h>
#include <stdlib.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <assert.h>
#include <syslog.h>
#include <getopt.h>
#include <pthread.h>
#include "multilink.h"
#include "ml_netlink.h"
#include "ml_parse.h"

static const char *confname = "/vendor/etc/multilink.conf";
static const char *pidfile = "/data/multilink.pid";
static const char *socket_path = "/data/socket.server";
static const char *version = "0.2";
static int mmu_board_version = 0;

#define MMU_BOARD_VERSION_FILE  "/data/mmu_version"
#define  MMU_ZONE_CN   (1)
#define  MMU_ZONE_US   (2)


#define log_error  syslog

static void sig_handler(int sig);
static struct nl_sock *sk;
static int signal_init();
//static void become_daemon();
static int delete_policy_route(void);
static int clean_environment(void);
static void get_mmu_version(const char *fname);
static int add_policy_route(void);
extern wan_if_t wan_if_list[10];
static int get_died();
static int set_died(int value);
static int get_mpath_added();
static int set_mpath_added(int value);
static int get_active_cnt();
static int set_active_cnt(int value);
int get_wan_cnt();
static int set_wan_cnt(int value);

static ml_status_t ml_status = {0, 0, 0, 0};

static pthread_t monitor_tid = -1;
pthread_mutex_t mutex_mlstatus;
static void *monitor_fun(void *arg);
static int handle_if_msg(const char *buf);


//TODO: for main
//1, add the multi-thread function
int main(int argc, char **argv)
{
    int rc = -1;
    unsigned short  conftest = 0;
    int opt;
    int i;
    pthread_attr_t attr;

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

    clean_environment();
    //become_daemon();

    pthread_mutex_init(&mutex_mlstatus, NULL);
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

    get_mmu_version(MMU_BOARD_VERSION_FILE);
    log_error(LOG_NOTICE, "conftest = %d\n", conftest);
    if (mmu_board_version == MMU_ZONE_US) {
        confname = "/vendor/etc/multilink_us.conf";
    }

    FILE *f = fopen(confname, "r");
    if (!f) {
        log_error(LOG_ERR, "Unable to open config file:%s", confname);
        return EXIT_FAILURE;
    }

    rc = parse_conf(f);
    if (rc) {
        log_error(LOG_ERR, "Failed to parse config file:%s", confname);
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

    rc = pthread_create(&monitor_tid, &attr, monitor_fun, NULL);
    if (rc) {
        log_error(LOG_ERR, "pthread_create failed form passive monitor");
        return -1;
    }

    while(1) {

        if (get_died())
            break;

        rc = add_policy_route();
        if (rc) {
            log_error(LOG_NOTICE, "Failed to add policy route.");
        }

        if (!get_mpath_added() && get_active_cnt() >= 2) {
            del_multipath_route(sk);
            rc = add_multipath_route(sk, wan_if_list);
            if (rc != 0) {
                syslog(LOG_ERR, "Failed to add multipath route!");
            }

            if (rc == 0 && get_active_cnt() == get_wan_cnt()) {
                log_error(LOG_NOTICE, "Add the multipath route successfully!");
                set_mpath_added(1);
            } else if (rc == 0 && get_active_cnt() < get_wan_cnt()){
                log_error(LOG_NOTICE, "Need further detective, active_cnt=%d, wan_if_cnt=%d!", get_active_cnt(), get_wan_cnt());
                set_mpath_added(1);

            } else {
                log_error(LOG_NOTICE, "Failed to add the multipath route!, try again!");
                del_multipath_route(sk);
                set_mpath_added(0);
            }
        }

        sleep(3);
    }

    log_error(LOG_NOTICE, "multilink goes down!");

    delete_policy_route();
    del_multipath_route(sk);
    pthread_attr_destroy(&attr);
    pthread_mutex_destroy(&mutex_mlstatus);

    if (pidfile) {
        remove(pidfile);
        log_error(LOG_DEBUG, "remove pidfile %s", pidfile);
    }

    if (sk) {
        netlink_fini(sk);
    }

    return rc;
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
        syslog(LOG_NOTICE, "got the signal SIGUSR1, reload configuration and the policy routing rule!");
        delete_policy_route();
        if (sk) {
            del_multipath_route(sk);
            set_active_cnt(0);
            set_mpath_added(0);
        }
    }
    else if (sig == SIGUSR2) {
        syslog(LOG_NOTICE, "got the signal SIGUSR2, do clean action!");
        set_died(1);
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

int delete_policy_route()
{
    int rc;
    wan_if_t *mif;
    struct sockaddr host_addr;
    int i = 0;

    for(i = 0; i < get_wan_cnt(); i++) {
        mif = &wan_if_list[i];
        syslog(LOG_ERR, "modem name:%s src=%s dst=%s, nexthop=%s, gateway=%s active=%d",
                        mif->ifname, mif->src, mif->dst, mif->nexthop, mif->gateway, mif->active);
        if (mif->active == 1) {
            del_network_route(sk, mif);
            del_default_route(sk, mif);
            rc = del_srcrule(sk, mif);
            if (rc != 0) {
                syslog(LOG_ERR, "Failed to delete routing rule!");
            }

            syslog(LOG_ERR, "delete routing rule successfully!");
            mif->active = 0;
        }
    }

    return 0;
}

int clean_environment()
{
    int rc = 0;

    delete_policy_route();
    //del_multipath_route();

    return rc;
}

void get_mmu_version(const char *fname)
{
    FILE *fp = NULL;
    char buf[100] = {0};
    int done = 0;

    if (fname == NULL) {
        return;
    }

    do {
        fp = fopen(fname, "r");
        if (fp != NULL) {
            fscanf(fp, "%s\n", buf);
            done = 1;
            break;
        } else {
            syslog(LOG_ERR, "Unable to open file %s for read, waiting", fname);
        }

        sleep(1);
    } while (!done);

    if (strstr(buf, "CN")) {
       mmu_board_version = MMU_ZONE_CN;
       set_wan_cnt(3);
    } else if (strstr(buf, "US")) {
       mmu_board_version = MMU_ZONE_US;
       set_wan_cnt(2);
    }

    syslog(LOG_NOTICE, "Got the mmu version is %s, wan cnt=%d", mmu_board_version == 2 ? "US" : "CN", get_wan_cnt());

    if (fp) {
        fclose(fp);
    }

    return;
}

int add_policy_route()
{
    int rc = -1;
    wan_if_t *mif;

    for (int i = 0; i < get_wan_cnt(); i++) {
        mif = &wan_if_list[i];
        if (mif->active == 1) {
            continue;
        }

        get_modem_if(mif);
        if (mif->found) {
            int count;
            rc = add_srcrule(sk, mif);
            if (rc != 0) {
                syslog(LOG_ERR, "Failed to add routing rule!");
                continue;
            }

            syslog(LOG_ERR, "add routing rule successfully!");
            add_network_route(sk, mif);
            add_default_route(sk, mif);
            mif->active = 1;
            count = get_active_cnt();
            count += 1;
            set_active_cnt(count);
            set_mpath_added(0);
        }
    }

    rc = 0;
    return rc;
}

static void* monitor_fun(void *arg)
{
    int rc = -1;
    int len;
    int client_sock;
    int server_sock;
    char buf[256];
    int backlog = 10;
    struct sockaddr_un server_addr;
    struct sockaddr_un client_addr;

    log_error(LOG_DEBUG, "monitor link thread enter");
    pthread_detach(pthread_self());

    server_sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (server_sock == -1) {
        log_error(LOG_ERR, "socket create error:%s", strerror(errno));
        return NULL;
    }

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sun_family = AF_UNIX;
    strncpy(server_addr.sun_path, socket_path, sizeof(server_addr.sun_path)-1);
    len = sizeof(server_addr);

    unlink(socket_path);
    rc = bind(server_sock, (struct sockaddr*)&server_addr, len);
    if (rc == -1) {
        log_error(LOG_ERR, "socket bind error:%s", strerror(errno));
        close(server_sock);
        return NULL;
    }

    rc = listen(server_sock, backlog);
    if (rc == -1) {
        log_error(LOG_ERR, "socket listen error:%s", strerror(errno));
        close(server_sock);
        return NULL;
    }

    log_error(LOG_DEBUG, "server socket listening");
    while (1) {
        client_sock = accept(server_sock, (struct sockaddr *)&client_addr, &len);
        if (client_sock == -1) {
            log_error(LOG_ERR, "socket accept error:%s", strerror(errno));
            close(client_sock);
            continue;
        }

        len = sizeof(client_addr);
        rc = getpeername(client_sock, (struct sockaddr *)&client_addr, &len);
        if (rc == -1){
            log_error(LOG_ERR, "Failed to get peer name:%s", strerror(errno));
            close(client_sock);
            continue;
        }

        log_error(LOG_DEBUG, "Client socket filepath: %s\n", client_addr.sun_path);
        rc = recv(client_sock, buf, sizeof(buf), 0);
        if (rc == -1) {
            log_error(LOG_ERR, "socket read error:%s", strerror(errno));
            close(client_sock);
            continue;
        } else {
            char tmp[64];
            log_error(LOG_DEBUG, "got %d bytes from mini-nm: %s\n", rc, buf);
            memset(tmp, 0, sizeof(tmp));
            snprintf(tmp, sizeof(tmp), "multilink got %d bytes.", rc);
            rc = send(client_sock, tmp, strlen(tmp), 0);
            if (rc == -1) {
                log_error(LOG_ERR, "Failed to send info to client");
                close(client_sock);
            }

            handle_if_msg(buf);
        }
    }

    close(server_sock);
    close(client_sock);

    return NULL;
}

static int handle_if_msg(const char *buf)
{
    int rc = -1;
    char ifname[20];
    int link_status = -1;
    wan_if_t *mif;
    int count;

    if (buf == NULL) {
        return rc;
    }

    if (get_mpath_added() == 0) {
        syslog(LOG_ERR, "The default route did not add, no need update route entry!");
        return rc;
    }

    rc = sscanf(buf, "%s %d", ifname, &link_status);
    if (rc != 2 ) {
        log_error(LOG_ERR, "Failed to parse the msg: %s \n", buf);
        return rc;
    }

    log_error(LOG_DEBUG, "Got the ifname:%s link_status=%d \n", ifname, link_status);
    for (int i = 0; i < get_wan_cnt(); i++) {
        mif = &wan_if_list[i];
        if (strcmp(mif->ifname, ifname) != 0) {
            continue;
        }

        if (mif->active == 0) {
            syslog(LOG_ERR, "The modem:%s is not active, no need update route entry!", ifname);
            return rc;
        }

        rc = del_srcrule(sk, mif);
        if (rc != 0) {
            syslog(LOG_ERR, "Failed to delete routing rule!");
        }

        syslog(LOG_ERR, "delete routing rule successfully!");
        mif->found = 0;
        mif->active = 0;
    }

    count = get_active_cnt();
    count -= 1;
    set_active_cnt(count);
    set_mpath_added(0);
    syslog(LOG_ERR, "Update the route entry for modem:%s successfully!", ifname);

    return 0;
}

static int get_died()
{
    return ml_status.died;
}

static int set_died(int value)
{
    if (value != 0 && value !=1) {
        log_error(LOG_ERR, "Unable to set value %d", value);
        return -1;
    }

    ml_status.died = value;
    return 0;
}

static int get_mpath_added()
{
    return ml_status.mpath_route_added;
}

static int set_mpath_added(int value)
{
    if (value != 0 && value !=1) {
        log_error(LOG_ERR, "Unable to set value %d", value);
        return -1;
    }

    pthread_mutex_lock(&mutex_mlstatus);
    ml_status.mpath_route_added = value;
    pthread_mutex_unlock(&mutex_mlstatus);

    return 0;
}

static int get_active_cnt()
{
    return ml_status.active_if_cnt;
}

static int set_active_cnt(int value)
{
    if (value < 0) {
        log_error(LOG_ERR, "Unable to set value %d", value);
        return -1;
    }

    pthread_mutex_lock(&mutex_mlstatus);
    ml_status.active_if_cnt = value;
    pthread_mutex_unlock(&mutex_mlstatus);

    return 0;
}

int get_wan_cnt()
{
    return ml_status.wan_if_cnt;
}

static int set_wan_cnt(int value)
{
    if (value < 0) {
        log_error(LOG_ERR, "Unable to set value %d", value);
        return -1;
    }

    ml_status.wan_if_cnt = value;

    return 0;
}
