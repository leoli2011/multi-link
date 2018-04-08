#include <stdio.h>
#include <netdb.h>
#include <stdlib.h>
#include <ifaddrs.h>
#include <sys/time.h>
#include <sys/types.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <assert.h>
#include <syslog.h>
#include "rule.h"
#include "multilink.h"

//static const char *confname = "/etc/multilink.conf";
static const char *confname = "/tmp/multilink.conf";
static const char *pidfile = "/tmp/multilink.pid";
static const char* version = "0.1";

#define log_error  syslog

static struct nl_sock *sk;
int get_modem_if(char *ifname, struct sockaddr *addr)
{
    struct ifaddrs *ip, *ifa;
    int s;
    char host[NI_MAXHOST];

    if (getifaddrs(&ip) == -1) {
        syslog(LOG_NOTICE, "getifaddrs");
        return -1;
    }

    for (ifa = ip; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL) {
            continue;
        }

        s = getnameinfo(ifa->ifa_addr, sizeof(struct sockaddr_in), host, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
        if (s != 0) {
            printf("getnameinfo() failed: %s\n", gai_strerror(s));
            freeifaddrs(ip);
            return -1;
        }

        if ((strncmp(ifa->ifa_name,ifname, strlen(ifname))==0)&&(ifa->ifa_addr->sa_family==AF_INET)) {
            syslog(LOG_NOTICE, "ifname=%s family=%s IP=%s\n", 
                   ifa->ifa_name, 
                   (ifa->ifa_addr->sa_family == AF_PACKET) ? "AF_PACKET" :
                   (ifa->ifa_addr->sa_family == AF_INET) ? "AF_INET" : "???", 
                   host);

            memcpy(addr, ifa->ifa_addr, sizeof(struct sockaddr));
            break;
        }
    }

    freeifaddrs(ip);
    return 0;
}

//TODO: for main 
//1, add signal handler 
//2, add configuration parser

int main(int argc, char **argv)
{
	int rc;
//	int exit_signals[2] = {SIGTERM, SIGINT};
	unsigned short  conftest = 0;
	int opt;
//	int i;
//	struct event_base *ev_base = NULL;

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


	FILE *f = fopen(confname, "r");
	if (!f) {
		perror("Unable to open config file");
		return EXIT_FAILURE;
	}



	if (pidfile) {
		f = fopen(pidfile, "w");
		if (!f) {
			perror("Unable to open pidfile for write");
			return EXIT_FAILURE;
		}
		fprintf(f, "%d\n", getpid());
		fclose(f);
	}

	log_error(LOG_NOTICE, "multi-link started");

    sk =  netlink_init();
    if (!sk)  {
	    log_error(LOG_ERR, "Failed to request the netlink socket");
        return -1;
    }

    while(1) {

        struct sockaddr host_addr; 
        
        rc = get_modem_if("usb0", &host_addr);
        if (rc == 0) {
            rc = add_srcrule(sk, 0x100, &host_addr);
            if (rc != 0) {
                syslog(LOG_ERR, "Failed to add routing rule!");
            }

            add_route(sk, "192.168.1.10", "192.168.1.0/24", "dev usb0", 0x100);
            add_route(sk, NULL, "default", "via 192.168.1.1", 0x100);
        }

        rc = get_modem_if("usb1", &host_addr);
        if (rc == 0) {
            add_srcrule(sk, 0x200, &host_addr);
        }

        rc = get_modem_if("usb2", &host_addr);
        if (rc == 0) {
            add_srcrule(sk, 0x300, &host_addr);
        }

        sleep(1);
    }

	log_error(LOG_NOTICE, "redsocks goes down");

//shutdown:

	if (pidfile) {
		remove(pidfile);
		log_error(LOG_DEBUG, "remove pidfile %s", pidfile);
	}

	return rc;
}
