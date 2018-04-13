#include <errno.h>
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

static int sfd = -1;
static zlog_category_t *zc;
static char err_buf[SIZEOF_ERR_BUF];


int notifier_init()
{
	zc = zlog_get_category("notifier");
	if (!zc) {
		fprintf(stderr, "Initiating logs for the notifier failed\n");
		return -1;
	}

	if (socket(AF_INET6, SOCK_DGRAM | SOCK_CLOEXEC, 0)) {
		strerror_r(errno, err_buf, SIZEOF_ERR_BUF);
		zlog_error(zc, "Cannot create notifier socket %s", err_buf);
		return -1;
	}

	zlog_info(zc, "The notifier is initialized");
	return 0;
}

size_t notification_alloc_size()
{
	return SRH_MAX_SIZE + CONN_TUPLE_SIZE;
}

int notify_endhost(struct connection *conn, struct ipv6_sr_hdr *srh,
		   size_t srh_len)
{
	struct conn_tlv *tlv = (struct conn_tlv *)
		(((char *) srh) + (srh_len + 1) * 4);
	memset(tlv, 0, sizeof(*tlv));
	memcpy(&tlv->src, &conn->src, sizeof(conn->src));
	memcpy(&tlv->dst, &conn->dst, sizeof(conn->dst));
	tlv->src_port = conn->src_port;
	tlv->dst_port = conn->dst_port;
	tlv->type = 7;
	tlv->length = 38;

	struct sockaddr_in6 sin6;
	sin6.sin6_family = AF_INET6;
	sin6.sin6_port = htons(SR_ENDHOSTD_PORT);
	sin6.sin6_flowinfo = 0;
	sin6.sin6_addr = conn->src;
	sin6.sin6_flowinfo = 0;

	ssize_t err;
	size_t buf_len = srh_len + sizeof(*tlv);
	err = sendto(sfd, srh, buf_len, 0, (struct sockaddr *) &sin6,
		     sizeof(struct sockaddr_in6));
	if (err < 0) {
		zlog_warn(zc, "Could not send the notification");
		return -1;
	} else if (err < (ssize_t) buf_len) {
		zlog_warn(zc, "Could not send the complete packet");
		return -1;
	}
	return 0;
}

int notifier_free()
{
	return close(sfd);
}

