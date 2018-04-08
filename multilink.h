#ifndef __MULTILINK_H__
#define __MULTILINK_H__

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
} modem_if_info;


modem_if_info hosts[] = 
{
    {"usb0", 0x100, "192.168.1.10", "192.168.1.0/24", "dev usb0" },
    {"usb1", 0x200, "192.168.2.10", "192.168.2.0/24", "dev usb1" },
    {"usb2", 0x300, "192.168.3.10", "192.168.3.0/24", "dev usb2" },
};


#endif 
