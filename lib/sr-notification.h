#ifndef SR_NOTIFICATION_H
#define SR_NOTIFICATION_H

#include <linux/seg6.h>

struct conn_tlv {
	__u8	type;
	__u8	length; // Number of bytes
	__u8	res;
	__u8	flags;
	struct in6_addr src;
	struct in6_addr dst;
	__u16	src_port;
	__u16	dst_port;
} __attribute__((__packed__));

#define SRH_MAX_SIZE sizeof(struct ipv6_sr_hdr) + 2 * sizeof(struct in6_addr)
#define CONN_TUPLE_SIZE sizeof(struct conn_tlv)
#define CONN_TLV_TYPE 7


const int SR_ENDHOSTD_PORT = 5000; // XXX Might change

#endif /* SR_NOTIFICATION_H */

