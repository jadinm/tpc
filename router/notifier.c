#include <arpa/inet.h>
#include <errno.h>
#include <linux/icmpv6.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <zlog.h>


#include "sr-notification.h"
#include "sr-rerouted.h"


#define SIZEOF_ERR_BUF 255

#define ICMPV6_CHANGE_PATH 5
#define ICMPV6_SRH_OFFER 0

static int sfd = -1;
static zlog_category_t *zc;
static char err_buf[SIZEOF_ERR_BUF];

extern void *icmp;


int notifier_init()
{
	zc = zlog_get_category("notifier");
	if (!zc) {
		fprintf(stderr, "Initiating logs for the notifier failed\n");
		return -1;
	}

	if ((sfd = socket(AF_INET6, SOCK_RAW | SOCK_CLOEXEC, IPPROTO_ICMPV6)) < 0) {
		strerror_r(errno, err_buf, SIZEOF_ERR_BUF);
		zlog_error(zc, "Cannot create notifier socket %s", err_buf);
		return -1;
	}

	zlog_info(zc, "The notifier is initialized");
	return 0;
}

size_t notification_alloc_size()
{
	return ICMPv6_MIN_SIZE + 2 * SRH_MAX_SIZE;
}

void *create_icmp(void *packet, size_t *icmp_len, struct connection *conn)
{
	struct icmp6hdr *icmp_hdr = icmp;
	*icmp_len = notification_alloc_size();
	memset(icmp_hdr, 0, *icmp_len);

	/* ICMP header */
	icmp_hdr->icmp6_type = ICMPV6_CHANGE_PATH;
	icmp_hdr->icmp6_code = ICMPV6_SRH_OFFER;
	void *ptr = ((char *) icmp) + 4;

	/* Packet causing the ICMP - TODO Asuming no IPv6 Extension Header for the moment */
	memcpy(ptr, packet, PACKET_CONTEXT);
	printf("First byte of packet %x\n", ((uint32_t *) packet)[0]);
	printf("First word of copied packet in icmp %x\n", ((uint32_t *) icmp_hdr)[0]);
	printf("Second word of copied packet in icmp %x\n", ((uint32_t *) icmp_hdr)[1]);
	printf("Third word of copied packet in icmp %x\n", ((uint32_t *) icmp_hdr)[2]);

	/* SRH */
	struct ipv6_sr_hdr *srh = (struct ipv6_sr_hdr *) (((char *) ptr) + PACKET_CONTEXT);
	zlog_debug(zc, "pointer %p - after increment %p - size %zd\n", // TODO Remove
		   ptr, srh, PACKET_CONTEXT);  // TODO remove
	int err = build_srh(conn, srh);
	if (err < 0) {
		zlog_warn(zc, "Cannot produce an SRH for a connection");
	}
	*icmp_len = 4 + PACKET_CONTEXT + err;

	return icmp;
}

int notify_endhost(struct connection *conn, void *icmp, size_t icmp_len)
{
	struct sockaddr_in6 sin6;
	memset(&sin6, 0, sizeof(sin6));
	sin6.sin6_family = AF_INET6;
	sin6.sin6_addr = conn->src;

	ssize_t err;
	err = sendto(sfd, icmp, icmp_len, 0, (struct sockaddr *) &sin6,
		     sizeof(struct sockaddr_in6));
	if (err < 0) {
		strerror_r(errno, err_buf, SIZEOF_ERR_BUF);
		zlog_warn(zc, "Could not send the notification %s", err_buf);
		return -1;
	} else if (err < (ssize_t) icmp_len) {
		zlog_warn(zc, "Could not send the complete packet");
		return -1;
	}

	char src_str[INET6_ADDRSTRLEN];
	char dst_str[INET6_ADDRSTRLEN];
	inet_ntop(AF_INET6, &conn->src, src_str, sizeof(conn->src));
	inet_ntop(AF_INET6, &conn->dst, dst_str, sizeof(conn->dst));
	zlog_debug(zc, "Connection src=%s dst=%s src_port=%u dst_port=%u",
		   src_str, dst_str, ntohs(conn->src_port),
		   ntohs(conn->dst_port));
	return 0;
}

int notifier_free()
{
	return close(sfd);
}

