#ifndef SR_ENDHOSTD_H
#define SR_ENDHOSTD_H

#include <linux/seg6.h>

#define _unused __attribute__((unused))

struct connection {
	struct in6_addr src;
	struct in6_addr dst;
	__u16 src_port;
	__u16 dst_port;
};

int monitor_init();
int monitor(struct connection *conn, struct ipv6_sr_hdr **srh,
	    size_t *srh_len);
int monitor_free();

#endif /* SR_ENDHOSTD_H */

