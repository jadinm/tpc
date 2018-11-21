#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <zlog.h>

#include <libmnl/libmnl.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nfnetlink_queue.h>
#include <libnetfilter_queue/libnetfilter_queue.h>

#include "sr-rerouted.h"


#define SIZEOF_BUF IP_MAXPACKET + MNL_SOCKET_BUFFER_SIZE/2 // Max packet size with netlink metadata
#define SIZEOF_ERR_BUF 256
#define DEFAULT_QUEUE 0
#define MAX_PATH 255
#define NEXTHDR_ROUTING 43

static struct mnl_socket *nl;
static zlog_category_t *zc;
static char err_buf[SIZEOF_ERR_BUF];
static uint32_t portid;


/* This function is inspired from https://www.netfilter.org/projects/libnetfilter_queue/doxygen/nf-queue_8c_source.html */
static struct nlmsghdr *nfq_hdr_put(char *buf, int type, uint32_t queue_num)
{
	struct nlmsghdr *nlh = mnl_nlmsg_put_header(buf);
	nlh->nlmsg_type = (NFNL_SUBSYS_QUEUE << 8) | type;
	nlh->nlmsg_flags = NLM_F_REQUEST;

	struct nfgenmsg *nfg = mnl_nlmsg_put_extra_header(nlh, sizeof(*nfg));
	nfg->nfgen_family = AF_UNSPEC;
	nfg->version = NFNETLINK_V0;
	nfg->res_id = htons(queue_num);

	return nlh;
}

/* This function is inspired from https://www.netfilter.org/projects/libnetfilter_queue/doxygen/nf-queue_8c_source.html */
static void nfq_send_verdict(int queue_num, uint32_t id)
{
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct nlmsghdr *nlh;

	nlh = nfq_hdr_put(buf, NFQNL_MSG_VERDICT, queue_num);
	nfq_nlmsg_verdict_put(nlh, id, NF_DROP);

	if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0) {
		strerror_r(errno, err_buf, SIZEOF_ERR_BUF);
		zlog_error(zc, "mnl_socket_send NFQNL_MSG_VERDICT %s", err_buf);
	}
}

/* This function is inspired from https://www.netfilter.org/projects/libnetfilter_queue/doxygen/nf-queue_8c_source.html */
static int nf_queue_callback(const struct nlmsghdr *nlh, void *data)
{
	struct nlattr *attr[NFQA_MAX+1] = {};
	uint32_t id = 0;
	struct nfgenmsg *nfg;
	
	zlog_debug(zc, "Starting callback function"); // TODO

	if (nfq_nlmsg_parse(nlh, attr) < 0) {
		strerror_r(errno, err_buf, SIZEOF_ERR_BUF);
		zlog_error(zc, "nfq_nlmsg_parse - Cannot parse %s", err_buf);
		return MNL_CB_ERROR;
	}

	nfg = mnl_nlmsg_get_payload(nlh);

	if (attr[NFQA_PACKET_HDR] == NULL) {
		zlog_error(zc, "Metaheader not set !");
		return MNL_CB_ERROR;
	}

	uint16_t attr_len = mnl_attr_get_payload_len(attr[NFQA_PAYLOAD]);
	if (attr_len <= 0) {
		zlog_error(zc, "Empty payload");
		return MNL_CB_ERROR;
	}
	void *payload = mnl_attr_get_payload(attr[NFQA_PAYLOAD]);
	struct connection *conn = (struct connection *) data;
	memset(conn, 0, sizeof(*conn));

	/* XXX We assume that only IPv6 packets with TCP or UDP payload are received here */
	struct ip6_hdr *iphdr = payload;
	char *ptr = ((char *) payload) + sizeof(*iphdr);
	uint8_t next_header = iphdr->ip6_nxt;
	uint16_t nextheader_len = 0;
	if (next_header == NEXTHDR_ROUTING) {
		/* Already an SRH -> extract the final destination */
		struct ipv6_sr_hdr *srh = (struct ipv6_sr_hdr *) ptr;
		conn->srh = srh;
		struct in6_addr *final_dst = (struct in6_addr *)
			(ptr + sizeof(struct ipv6_sr_hdr));
		conn->dst = *final_dst;
		uint16_t srh_len = (1 + srh->hdrlen)*8;
		nextheader_len += srh_len;
		ptr = ptr + srh_len;
		next_header = srh->nexthdr;

		/* We set the destination of the IPv6 packet to the final
		 * destination so that the endhost can find which connection
		 * the ICMP targets.
		 */
		iphdr->ip6_dst = conn->dst;

		zlog_debug(zc, "Packets with a SRH is being rerouted");
		// TODO At the moment we don't consider the case of multiple
		// extension headers or stacked SRHs
	} else {
		conn->dst = iphdr->ip6_dst;
		conn->srh = NULL;
	}
	conn->src = iphdr->ip6_src;
	struct tcphdr *tcphdr;
	struct udphdr *udphdr;
	switch (next_header) {
	case IPPROTO_TCP:
		tcphdr = (struct tcphdr *) ptr;
		conn->src_port = tcphdr->source;
		conn->dst_port = tcphdr->dest;
		break;
	case IPPROTO_UDP:
		udphdr = (struct udphdr *) ptr;
		conn->src_port = udphdr->source;
		conn->dst_port = udphdr->dest;
		break;
	default:
		zlog_error(zc, "Cannot identify the Next Header field !");
		return MNL_CB_ERROR;
	}

	/* Produce the ICMP */
	size_t icmp_len = 0;
	void *icmp = create_icmp(payload, nextheader_len, &icmp_len, conn);
	if (!icmp) {
		zlog_warn(zc, "Cannot produce an ICMP for a connection");
		return MNL_CB_ERROR;
	}

	/* Send it to the host */
	if (notify_endhost(conn, icmp, icmp_len)) {
		zlog_warn(zc, "Cannot notify the endhost");
		return MNL_CB_ERROR;
	}

	nfq_send_verdict(ntohs(nfg->res_id), id);
	return MNL_CB_OK;
}

int nf_queue_init()
{
	struct nlmsghdr *nlh;
	int ret = 0;
	int err = 0;
	uint32_t queue_num = DEFAULT_QUEUE;
	char buf[SIZEOF_BUF];
	memset(buf, 0, SIZEOF_BUF);

	zc = zlog_get_category("nf_queue");
	if (!zc) {
		fprintf(stderr, "Initiating logs for the nf_queue failed\n");
		ret = -1;
		goto out;
	}

	zlog_info(zc, "Netfilter initialization");

	/* Netlink setup - This code is inspired from https://www.netfilter.org/projects/libnetfilter_queue/doxygen/nf-queue_8c_source.html */
	nl = mnl_socket_open(NETLINK_NETFILTER);
	if (nl == NULL) {
		strerror_r(errno, err_buf, SIZEOF_ERR_BUF);
		zlog_error(zc, "mnl_socket_open %s", err_buf);
		ret = -1;
		goto out;
	}

	if (mnl_socket_bind(nl, 0, MNL_SOCKET_AUTOPID) < 0) {
		strerror_r(errno, err_buf, SIZEOF_ERR_BUF);
		zlog_error(zc, "mnl_socket_bind %s", err_buf);
		goto err_netlink;
	}
	portid = mnl_socket_get_portid(nl);

	nlh = nfq_hdr_put(buf, NFQNL_MSG_CONFIG, queue_num);
	nfq_nlmsg_cfg_put_cmd(nlh, AF_INET6, NFQNL_CFG_CMD_BIND);
	if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0) {
		strerror_r(errno, err_buf, SIZEOF_ERR_BUF);
		zlog_error(zc, "mnl_socket_send NFQNL_CFG_CMD_BIND %s",
			   err_buf);
		goto err_netlink;
	}

	nlh = nfq_hdr_put(buf, NFQNL_MSG_CONFIG, queue_num);
	nfq_nlmsg_cfg_put_params(nlh, NFQNL_COPY_PACKET, 0xffff);

	mnl_attr_put_u32(nlh, NFQA_CFG_FLAGS, htonl(NFQA_CFG_F_GSO));
	mnl_attr_put_u32(nlh, NFQA_CFG_MASK, htonl(NFQA_CFG_F_GSO));
	if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0) {
		strerror_r(errno, err_buf, SIZEOF_ERR_BUF);
		zlog_error(zc, "mnl_socket_send NFQA_CFG_F_GSO "
			       "and NFQNL_COPY_PACKET %s", err_buf);
		goto err_netlink;
	}

	/* ENOBUFS is signalled to userspace when packets were lost
	 * on kernel side.  In most cases, userspace isn't interested
	 * in this information, so turn it off.
	 */
	err = 1;
	mnl_socket_setsockopt(nl, NETLINK_NO_ENOBUFS, &err, sizeof(int));

	zlog_info(zc, "nf_queue started");

	
out:
	return ret;
err_netlink:
	ret = -1;
	mnl_socket_close(nl);
	goto out;
}

int nf_queue_recv(struct connection *conn)
{
	int err = 0;
	int ret = 0;
	fd_set read_fds;
	char buf[SIZEOF_BUF];

	FD_ZERO(&read_fds);
	FD_SET(mnl_socket_get_fd(nl), &read_fds);
	err = select(mnl_socket_get_fd(nl) + 1, &read_fds, NULL, NULL, NULL);
	if (err < 0) {
		if (errno != EINTR) {
			strerror_r(errno, err_buf, SIZEOF_ERR_BUF);
			zlog_error(zc, "Select failed %s", err_buf);
			ret = -1;
		} else {
			ret = 0;
			zlog_warn(zc, "Program interrupted");
		}
		return ret;
	}

	if (FD_ISSET(mnl_socket_get_fd(nl), &read_fds)) {
		err = mnl_socket_recvfrom(nl, buf, SIZEOF_BUF);
		if (err == -1) {
			strerror_r(errno, err_buf, SIZEOF_ERR_BUF);
			zlog_error(zc, "mnl_socket_recvfrom %s", err_buf);
			return -1;
		}
		err = mnl_cb_run(buf, err, 0, portid, nf_queue_callback, conn);
		if (err == MNL_CB_ERROR) {
			return -1;
		} // TODO MNL_CB_STOP Not interpreted
		return 1;
	}
	return 0;
}

int nf_queue_free()
{
	if (mnl_socket_close(nl)) {
		strerror_r(errno, err_buf, SIZEOF_ERR_BUF);
		zlog_error(zc, "Error while closing netlink %s", err_buf);
		return -1;
	}
	return 0;
}

