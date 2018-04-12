#ifndef SR_REROUTED_H
#define SR_REROUTED_H

#define _unused __attribute__((unused))

struct sr_conn_tlv {
	__u8	type;
	__u8	length;
	__u8	res;
	__u8	flags;
	struct in6_addr src;
	struct in6_addr dst;
	__u16	src_port;
	__u16	dst_port;
};

struct ipv6_sr_hdr {
	__u8	nexthdr;
	__u8	hdrlen;
	__u8	type;
	__u8	segments_left;
	__u8	first_segment;
	__u8	flag_1;
	__u8	flag_2;
	__u8	reserved;
	struct in6_addr segments[0];
};

struct connection {
	struct in6_addr src;
	struct in6_addr dst;
	__u16 src_port;
	__u16 dst_port;
};

int notifier_init();
int notify_endhost(struct connection *conn, struct ipv6_sr_hdr *srh,
		   size_t srh_len);
int notifier_free();

int nf_queue_init();
int nf_queue_recv(struct connection *conn);
int nf_queue_free();

#endif /* SR_RETOURED_H */

