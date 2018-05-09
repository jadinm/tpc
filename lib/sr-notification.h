#ifndef SR_NOTIFICATION_H
#define SR_NOTIFICATION_H

#include <linux/icmpv6.h>
#include <linux/ipv6.h>
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
#define PACKET_CONTEXT sizeof(struct ipv6hdr) + 8
#define ICMPv6_MIN_SIZE sizeof(struct icmp6hdr) + PACKET_CONTEXT


const int SR_ENDHOSTD_PORT = 5000; // XXX Might change

#endif /* SR_NOTIFICATION_H */

