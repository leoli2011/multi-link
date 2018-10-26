#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <asm/types.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <netinet/in.h>
#include <linux/tcp.h>
#include <linux/sock_diag.h>
#include <linux/inet_diag.h>
#include <arpa/inet.h>
#include <pwd.h>

//Kernel TCP states. /include/net/tcp_states.h
enum{
    TCP_ESTABLISHED = 1,
    TCP_SYN_SENT,
    TCP_SYN_RECV,
    TCP_FIN_WAIT1,
    TCP_FIN_WAIT2,
    TCP_TIME_WAIT,
    TCP_CLOSE,
    TCP_CLOSE_WAIT,
    TCP_LAST_ACK,
    TCP_LISTEN,
    TCP_CLOSING
};

static const char* tcp_states_map[]={
    [TCP_ESTABLISHED] = "ESTABLISHED",
    [TCP_SYN_SENT] = "SYN-SENT",
    [TCP_SYN_RECV] = "SYN-RECV",
    [TCP_FIN_WAIT1] = "FIN-WAIT-1",
    [TCP_FIN_WAIT2] = "FIN-WAIT-2",
    [TCP_TIME_WAIT] = "TIME-WAIT",
    [TCP_CLOSE] = "CLOSE",
    [TCP_CLOSE_WAIT] = "CLOSE-WAIT",
    [TCP_LAST_ACK] = "LAST-ACK",
    [TCP_LISTEN] = "LISTEN",
    [TCP_CLOSING] = "CLOSING"
};

static int cnt1 = 0;
static int cnt2 = 0;
static int cnt3 = 0;
static int cnt4 = 0;

static int read_dhcp_address(char *addr);
#define TCPF_ALL 0xFFF

#define SOCKET_BUFFER_SIZE (getpagesize() < 8192L ? getpagesize() : 8192L)

//Example of diag_filtering, checks if destination port is <= 1000
unsigned char create_filter(void **filter_mem)
{
    struct inet_diag_bc_op *bc_op = NULL;
    unsigned char filter_len = sizeof(struct inet_diag_bc_op)*2;
    if((*filter_mem = calloc(filter_len, 1)) == NULL)
        return 0;

    bc_op = (struct inet_diag_bc_op*) *filter_mem;
    bc_op->code = INET_DIAG_BC_D_LE;
    bc_op->yes = sizeof(struct inet_diag_bc_op)*2;
    bc_op->no = 12;

    bc_op = bc_op + 1;
    bc_op->no = 1000;

    return filter_len;
}

int send_diag_msg(int sockfd)
{
    struct msghdr msg;
    struct nlmsghdr nlh;
    struct inet_diag_req_v2 conn_req;
    struct sockaddr_nl sa;
    struct iovec iov[4];
    int rc = 0;

    struct rtattr rta;
    void *filter_mem = NULL;
    int filter_len = 0;

    memset(&msg, 0, sizeof(msg));
    memset(&sa, 0, sizeof(sa));
    memset(&nlh, 0, sizeof(nlh));
    memset(&conn_req, 0, sizeof(conn_req));

    sa.nl_family = AF_NETLINK;
    sa.nl_pid = 0;

    conn_req.sdiag_family = AF_INET;
    conn_req.sdiag_protocol = IPPROTO_TCP;

    //conn_req.idiag_states = TCPF_ALL &
    //   ~((1<<TCP_SYN_RECV) | (1<<TCP_TIME_WAIT) | (1<<TCP_CLOSE));
    conn_req.idiag_states = TCPF_ALL;
    conn_req.idiag_ext |= (1 << (INET_DIAG_INFO - 1));

    nlh.nlmsg_len = NLMSG_LENGTH(sizeof(conn_req));
    nlh.nlmsg_flags = NLM_F_DUMP | NLM_F_REQUEST;

    //conn_req.id.idiag_dport=htons(443);

    nlh.nlmsg_type = SOCK_DIAG_BY_FAMILY;
    iov[0].iov_base = (void*) &nlh;
    iov[0].iov_len = sizeof(nlh);
    iov[1].iov_base = (void*) &conn_req;
    iov[1].iov_len = sizeof(conn_req);

#if 0
    filter_len = create_filter(&filter_mem);
    if (filter_len > 0) {
        memset(&rta, 0, sizeof(rta));
        rta.rta_type = INET_DIAG_REQ_BYTECODE;
        rta.rta_len = RTA_LENGTH(filter_len);
        iov[2] = (struct iovec){&rta, sizeof(rta)};
        iov[3] = (struct iovec){filter_mem, filter_len};
        nlh.nlmsg_len += rta.rta_len;
    }
#endif

    msg.msg_name = (void*) &sa;
    msg.msg_namelen = sizeof(sa);
    msg.msg_iov = iov;
    if(filter_mem == NULL)
        msg.msg_iovlen = 2;
    else
        msg.msg_iovlen = 4;

    rc = sendmsg(sockfd, &msg, 0);

    if (filter_mem != NULL) {
        free(filter_mem);
    }

    return rc;
}

void parse_diag_msg(struct inet_diag_msg *diag_msg, int rtalen)
{
    struct rtattr *attr;
    struct tcp_info *tcpi;
    char local_addr_buf[INET6_ADDRSTRLEN];
    char remote_addr_buf[INET6_ADDRSTRLEN];
    struct passwd *uid_info = NULL;

    memset(local_addr_buf, 0, sizeof(local_addr_buf));
    memset(remote_addr_buf, 0, sizeof(remote_addr_buf));

    uid_info = getpwuid(diag_msg->idiag_uid);

    if (diag_msg->idiag_family == AF_INET) {
        inet_ntop(AF_INET, (struct in_addr*) &(diag_msg->id.idiag_src),
            local_addr_buf, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, (struct in_addr*) &(diag_msg->id.idiag_dst),
            remote_addr_buf, INET_ADDRSTRLEN);
    } else if (diag_msg->idiag_family == AF_INET6) {
        inet_ntop(AF_INET6, (struct in_addr6*) &(diag_msg->id.idiag_src),
                local_addr_buf, INET6_ADDRSTRLEN);
        inet_ntop(AF_INET6, (struct in_addr6*) &(diag_msg->id.idiag_dst),
                remote_addr_buf, INET6_ADDRSTRLEN);
    } else {
        fprintf(stderr, "Unknown family\n");
        return;
    }

    if (local_addr_buf[0] == 0 || remote_addr_buf[0] == 0) {
        fprintf(stderr, "Could not get required connection information\n");
        return;
    } else {
        //fprintf(stdout, "User: %s (UID: %u) Src: %s:%d Dst: %s:%d\n", 
        //        uid_info == NULL ? "Not found" : uid_info->pw_name,
        //        diag_msg->idiag_uid,
        //        local_addr_buf, ntohs(diag_msg->id.idiag_sport),
        //        remote_addr_buf, ntohs(diag_msg->id.idiag_dport));
        //fprintf(stdout, "Src: %s, len=%d\n", local_addr_buf, strlen(local_addr_buf)); 
        if (strcmp(local_addr_buf, "192.168.1.10") == 0) {
            cnt1++;
        } else if(strcmp(local_addr_buf, "192.168.2.10") == 0) {
            cnt2++;
        } else if(strcmp(local_addr_buf, "192.168.3.10") == 0) {
            cnt3++;
        } else if(strcmp(local_addr_buf, "0.0.0.0") == 0) {
            return;
        } else if(strcmp(local_addr_buf, "127.0.0.1") == 0) {
            return;
        } else if(strcmp(local_addr_buf, "172.26.200.1") == 0) {
            return;
        } else {
            char addr[32] = {0};
            int rc = read_dhcp_address(addr);
            if (rc == 0 && strcmp(local_addr_buf, addr) == 0) {
               cnt4++;
            }
        }
    }

    if (rtalen > 0) {
        attr = (struct rtattr*)(diag_msg+1);
        while (RTA_OK(attr, rtalen)) {
            if (attr->rta_type == INET_DIAG_INFO) {
                tcpi = (struct tcp_info*) RTA_DATA(attr);

                /*
                fprintf(stdout, "\tState: %s RTT: %gms (var. %gms) "
                        "Recv. RTT: %gms Snd_cwnd: %u/%u\n",
                        tcp_states_map[tcpi->tcpi_state],
                        (double) tcpi->tcpi_rtt/1000,
                        (double) tcpi->tcpi_rttvar/1000,
                        (double) tcpi->tcpi_rcv_rtt/1000,
                        tcpi->tcpi_unacked,
                        tcpi->tcpi_snd_cwnd);
                */
            }
            attr = RTA_NEXT(attr, rtalen);
        }
    }
}

int main(int argc, char *argv[])
{
    int nl_sock = 0;
    int numbytes = 0;
    int rtalen = 0;
    int rc = -1;
    struct nlmsghdr *nlh;
    uint8_t recv_buf[SOCKET_BUFFER_SIZE];
    struct inet_diag_msg *diag_msg;

    nl_sock = socket(AF_NETLINK, SOCK_DGRAM, NETLINK_INET_DIAG);
    if (nl_sock == -1) {
        perror("socket: ");
        return EXIT_FAILURE;
    }

    rc = send_diag_msg(nl_sock);
    if (rc < 0) {
        perror("sendmsg to kernel: ");
        return EXIT_FAILURE;
    }

    while (1) {
        numbytes = recv(nl_sock, recv_buf, sizeof(recv_buf), 0);
        nlh = (struct nlmsghdr*)recv_buf;

        while (NLMSG_OK(nlh, (unsigned int)numbytes)) {
            if (nlh->nlmsg_type == NLMSG_DONE)
                goto out;

            if (nlh->nlmsg_type == NLMSG_ERROR) {
                fprintf(stderr, "Error in netlink message\n");
                goto out;
            }

            diag_msg = (struct inet_diag_msg*)NLMSG_DATA(nlh);
            rtalen = nlh->nlmsg_len - NLMSG_LENGTH(sizeof(*diag_msg));
            parse_diag_msg(diag_msg, rtalen);

            nlh = NLMSG_NEXT(nlh, numbytes);
        }
    }

out:
    fprintf(stdout, "Modem1=%d, Modem2=%d, Modem3=%d\n", cnt1, cnt2, cnt3 ? cnt3 : cnt4);

    return EXIT_SUCCESS;
}


#define MODEM_DHCP_CONFIG          "/data/local/tmp/dhcp_config"
static int read_dhcp_address(char *addr)
{
    FILE *fp;
    int rc = -1;
    char buf[128] = {0};

    fp = fopen(MODEM_DHCP_CONFIG, "r");
    if (!fp) {
        fprintf(stdout, "Unable to open file %s for read\n", MODEM_DHCP_CONFIG);
        return rc;
    }

    while (fgets(buf, sizeof(buf), fp)) {
        if (strstr(buf, "ADDR=")) {
            buf[strlen(buf) - 1 ] = '\0';
            //fprintf(stdout, "got the IP addr=%s\n", buf+strlen("ADDR="));
            snprintf(addr, strlen(buf), "%s", buf+strlen("ADDR="));
            break;
        } else {
            fprintf(stdout, "got the content %s", buf);
        }
    }

    if (fp) {
        fclose(fp);
    }

    rc = 0;
    return rc;
}
