#ifndef __MULTILINK_H__
#define __MULTILINK_H__

#include <libio.h>
#include <linux/if.h>

#define SIZEOF_ARRAY(arr)        (sizeof(arr) / sizeof(arr[0]))
#define FOREACH(ptr, array)      for (ptr = array; ptr < array + SIZEOF_ARRAY(array); ptr++)

//#define log_errno(prio, msg...) syslog(__FILE__, __LINE__, __func__, 1, prio, ## msg)
//#define log_error(prio, msg...) syslog(__FILE__, __LINE__, __func__, 0, prio, ## msg)		//syslog_msg

typedef struct modem_if_info_t {
    char ifname[IFNAMSIZ];
    unsigned short tid;
    //unsigned int addr;
    char src[32];
    char dst[32];
    char nexthop[32];
    char rulegate[32];
    char active;
} modem_if_info;


typedef struct gateway_info_t {
    char ifname[IFNAMSIZ];
    char gate_addr[32];
    char weight;
    char used;
} gateway_info;

extern modem_if_info hosts[];
extern gateway_info gates[];
extern char* const tid_string[];
extern int get_hosts_len(void);
extern int get_gates_len(void);

#endif

