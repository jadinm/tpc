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

static char buf[SRH_MAX_SIZE + CONN_TUPLE_SIZE];


int monitor_init()
{
	struct addrinfo hints;
	struct addrinfo *result, *rp;

	int status = 0;

	zc = zlog_get_category("monitor");
	if (!zc) {
		fprintf(stderr, "Initiating logs for the monitor failed\n");
		return -1;
	}

	/* Init server socket */
	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = AF_INET6;	/* Allow IPv4 or IPv6 */
	hints.ai_socktype = SOCK_DGRAM; /* Datagram socket */
	hints.ai_flags = AI_PASSIVE;	/* For wildcard IP address */
	hints.ai_protocol = 0;		/* Any protocol */
	hints.ai_canonname = NULL;
	hints.ai_addr = NULL;
	hints.ai_next = NULL;

	status = getaddrinfo(NULL, SR_ENDHOSTD_PORT, &hints, &result);
	if (status != 0) {
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(status));
		return -1;
	}

	for (rp = result; rp != NULL; rp = rp->ai_next) {
		sfd = socket(rp->ai_family, rp->ai_socktype | SOCK_CLOEXEC,
			     rp->ai_protocol);
		if (sfd == -1)
			continue;
		if (bind(sfd, rp->ai_addr, rp->ai_addrlen) == 0)
			break;
		close(sfd);
	}

	freeaddrinfo(result);

	if (rp == NULL) {
		strerror_r(errno, err_buf, SIZEOF_ERR_BUF);
		zlog_error(zc, "Could not bind monitor socket %s", err_buf);
		return -1;
	}

	zlog_info(zc, "The monitor is initialized");
	return 0;
}

int monitor(struct connection *conn _unused, struct ipv6_sr_hdr **srh _unused,
	    size_t *srh_len _unused)
{
	ssize_t err = recvfrom(sfd, buf, SRH_MAX_SIZE + CONN_TUPLE_SIZE,
			       0, NULL, NULL);
	if (err < 0) {
		zlog_warn(zc, "Could not receive the notification");
		return -1;
	}

	*srh = (struct ipv6_sr_hdr *) buf;
	*srh_len = ((*srh)->hdrlen + 1) * 8;

	if (err < (ssize_t) *srh_len) {
		zlog_warn(zc, "Could not receive a complete notification");
		return -1;
	}

	struct conn_tlv *tlv = (struct conn_tlv *) (buf + *srh_len);
	if (tlv->length != 38) {
		zlog_warn(zc, "Malformed notification");
		return -1;
	}
	memcpy(&conn->src, &tlv->src, sizeof(tlv->src));
	memcpy(&conn->dst, &tlv->dst, sizeof(tlv->dst));
	tlv->src_port = conn->src_port;
	tlv->dst_port = conn->dst_port;

	return 0;
}

int monitor_free()
{
	return close(sfd);
}

