#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <zlog.h>

#include "sr-endhostd.h"
#include "sr-notification.h"


#define SIZEOF_ERR_BUF 255

static int sfd = -1;
static zlog_category_t *zc;
static char err_buf[SIZEOF_ERR_BUF];

static char buf[SRH_MAX_SIZE + ICMPv6_MIN_SIZE];


int monitor_init()
{
	zc = zlog_get_category("monitor");
	if (!zc) {
		fprintf(stderr, "Initiating logs for the monitor failed\n");
		return -1;
	}

	sfd = socket(AF_INET6, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (sfd < 0) {
		strerror_r(errno, err_buf, SIZEOF_ERR_BUF);
		zlog_error(zc, "Could not create monitor socket %s", err_buf);
		return -1;
	}

	struct sockaddr_in6 sin6;
	memset(&sin6, 0, sizeof(sin6));
	sin6.sin6_family = AF_INET6;
	sin6.sin6_port = htons(SR_ENDHOSTD_PORT);
	if (bind(sfd, (struct sockaddr *) &sin6, sizeof(sin6)) < 0) {
		strerror_r(errno, err_buf, SIZEOF_ERR_BUF);
		zlog_error(zc, "Could not bind monitor socket %s", err_buf);
		return -1;
	}

	zlog_info(zc, "The monitor is initialized");
	return 0;
}

int monitor(struct connection *conn, struct ipv6_sr_hdr **srh, size_t *srh_len)
{
	ssize_t err = recvfrom(sfd, buf, SRH_MAX_SIZE + ICMPv6_MIN_SIZE,
			       0, NULL, NULL);
	if (err < 0) {
		zlog_warn(zc, "Could not receive the notification");
		return -1;
	}

	*srh = (struct ipv6_sr_hdr *) buf;
	*srh_len = sizeof(**srh) + ((*srh)->hdrlen) * 8;
	printf("Test %zd\n", *srh_len); // TODO
	// TODO Might want to check the SRH format

	if (err < (ssize_t) *srh_len) {
		zlog_warn(zc, "Could not receive a complete notification");
		return -1;
	}

	struct conn_tlv *tlv = (struct conn_tlv *) (buf + *srh_len);
	if (tlv->length != sizeof(*tlv)) {
		zlog_warn(zc, "Malformed notification");
		return -1;
	}
	memcpy(&conn->src, &tlv->src, sizeof(tlv->src));
	memcpy(&conn->dst, &tlv->dst, sizeof(tlv->dst));
	tlv->src_port = conn->src_port;
	tlv->dst_port = conn->dst_port;

	char src_str[INET6_ADDRSTRLEN];
	char dst_str[INET6_ADDRSTRLEN];
	inet_ntop(AF_INET6, &conn->src, src_str, sizeof(conn->src));
	inet_ntop(AF_INET6, &conn->dst, dst_str, sizeof(conn->dst));
	zlog_debug(zc, "Connection src=%s dst=%s src_port=%u dst_port=%u",
		   src_str, dst_str, ntohs(conn->src_port),
		   ntohs(conn->dst_port));

	return 0;
}

int monitor_free()
{
	return close(sfd);
}

