#ifndef SR_REROUTED_H
#define SR_REROUTED_H

#include <linux/seg6.h>

#define _unused __attribute__((unused))

struct connection {
	struct in6_addr src;
	struct in6_addr dst;
	__u16 src_port;
	__u16 dst_port;
};

int notifier_init();
size_t notification_alloc_size();
int notify_endhost(struct connection *conn, struct ipv6_sr_hdr *srh,
		   size_t srh_len);
int notifier_free();

int nf_queue_init();
int nf_queue_recv(struct connection *conn);
int nf_queue_free();

#endif /* SR_RETOURED_H */

