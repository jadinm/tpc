#include <stdio.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <zlog.h>

#include "sr-rerouted.h"


static int sfd = -1;
static zlog_category_t *zc;
static char err_buf[SIZEOF_ERR_BUF];


int notifier_init()
{
	zc = zlog_get_category("notifier");
	if (!zc) {
		fprintf(stderr, "Initiating logs for the notifier failed\n");
		ret = -1;
		goto out;
	}

	
	if (socket(AF_INET6, SOCK_DGRAM | SOCK_CLOEXEC, 0)) {
		strerror_r(errno, err_buf, SIZEOF_ERR_BUF);
		zlog_error(zc, "Cannot create notifier socket %s", err_buf);
		return -1;
	}

	zlog_info(zc, "The notifier is initialized");
	return 0;
}

int notify_endhost(struct connection *conn, struct ipv6_sr_hdr *srh,
		   size_t srh_len)
{
	struct sr_conn_tlv *tlv = (struct sr_conn_tlv *)
		(((char *) srh) + srh_len);
	memset(tlv, 0, sizeof(*tlv));
	memcpy(&tlv->src, conn->src, sizeof(conn->src));
	memcpy(&tlv->dst, conn->dst, sizeof(conn->dst));
	tlv->src_port = conn->src_port;
	tlv->dst_port = conn->dst_port;
	tlv->type = 7;
	tlv->length = 38;

	srh->hdrlen += 5;

	err = sendto(sfd, srh, srh_length, 0, (struct sockaddr *) &conn->src,
		     conn->src_len + sizeof(*tlv));
}

int notifier_free()
{
	return close(sfd);
}

