#ifndef __MULTILINK_H__
#define __MULTILINK_H__

//#include <libio.h>
#include <linux/if.h>

#define SIZEOF_ARRAY(arr)        (sizeof(arr) / sizeof(arr[0]))
#define FOREACH(ptr, array)      for (ptr = array; ptr < array + SIZEOF_ARRAY(array); ptr++)

//#define log_errno(prio, msg...) syslog(__FILE__, __LINE__, __func__, 1, prio, ## msg)
//#define log_error(prio, msg...) syslog(__FILE__, __LINE__, __func__, 0, prio, ## msg)		//syslog_msg

typedef struct ml_status_s {
    int died;
    int mpath_route_added;
    int active_if_cnt;
    int wan_if_cnt;
} ml_status_t;

extern int get_wan_cnt();

#endif

