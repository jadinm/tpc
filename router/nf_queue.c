#include <arpa/inet.h>
#include <errno.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>

#include <zlog.h>

#include <libmnl/libmnl.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nfnetlink_queue.h>
#include <libnetfilter_queue/libnetfilter_queue.h>

#include "nf_queue.h"


#define SIZEOF_BUF 0xffff + MNL_SOCKET_BUFFER_SIZE
#define SIZEOF_ERR_BUF 256
#define DEFAULT_QUEUE 0
#define MAX_PATH 255
#define TIMEOUT_LOOP 1

static struct mnl_socket *nl;
static zlog_category_t *zc;

static char err_buf[SIZEOF_ERR_BUF];
volatile int stop;


void sig_handler(int signal_number _unused)
{
	stop = 1;
}

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
static int nf_queue_callback(const struct nlmsghdr *nlh, void *data _unused)
{
	struct nfqnl_msg_packet_hdr *ph = NULL;
	struct nlattr *attr[NFQA_MAX+1] = {};
	uint32_t id = 0;
	uint32_t skbinfo;
	struct nfgenmsg *nfg;
	uint16_t plen;

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

	ph = mnl_attr_get_payload(attr[NFQA_PACKET_HDR]);
	plen = mnl_attr_get_payload_len(attr[NFQA_PAYLOAD]);
	skbinfo = attr[NFQA_SKB_INFO]
		? ntohl(mnl_attr_get_u32(attr[NFQA_SKB_INFO]))
		: 0;
	/* void *payload = mnl_attr_get_payload(attr[NFQA_PAYLOAD]); */

	if (attr[NFQA_CAP_LEN]) {
		uint32_t orig_len = ntohl(mnl_attr_get_u32(attr[NFQA_CAP_LEN]));
		if (orig_len != plen)
			zlog_debug(zc, "Packet trucated");
	}

	if (skbinfo & NFQA_SKB_GSO)
		zlog_debug(zc, "GSO is used");

	id = ntohl(ph->packet_id);
	zlog_debug(zc, "packet received id=%u hw=0x%04x hook=%u payload len %u",
		   id, ntohs(ph->hw_protocol), ph->hook, plen);

	/*
	 * ip/tcp checksums are not yet valid, e.g. due to GRO/GSO.
	 * The application should behave as if the checksums are correct.
	 *
	 * If these packets are later forwarded/sent out, the checksums will
	 * be corrected by kernel/hardware.
	 */
	if (skbinfo & NFQA_SKB_CSUMNOTREADY)
		zlog_debug(zc, "The checksum is not ready");

	nfq_send_verdict(ntohs(nfg->res_id), id);
	return MNL_CB_OK;
}

int main(int argc _unused, char *argv[] _unused)
{
	struct nlmsghdr *nlh;
	int ret = 0;
	int err = 0;
	uint32_t portid;
	uint32_t queue_num = DEFAULT_QUEUE;
	char buf[SIZEOF_BUF];
	memset(buf, 0, SIZEOF_BUF);

	/* Logs setup */
	char *path = getcwd(NULL, MAX_PATH);
	if (!path) {
		perror("Cannot get current working directory");
		ret = -1;
		goto out;
	}
	int len = strlen(path);
	snprintf(path + len, MAX_PATH - len, "/%s", "zlog.conf");
	int rc = zlog_init(path);
	if (rc) {
		fprintf(stderr, "Initiating logs failed\n");
		ret = -1;
		goto out_path;
	}
	zc = zlog_get_category("router_nfqueue");
	if (!zc) {
		fprintf(stderr, "Initiating logs failed\n");
		ret = -1;
		goto out_logs;
	}
	zlog_info(zc, "Netfilter initialization");

	/* Catching signals */
	if (signal(SIGINT, sig_handler) == SIG_ERR) {
		zlog_warn(zc, "Cannot catch SIG_INT");
	}

	/* Netlink setup - This code is inspired from https://www.netfilter.org/projects/libnetfilter_queue/doxygen/nf-queue_8c_source.html */
	nl = mnl_socket_open(NETLINK_NETFILTER);
	if (nl == NULL) {
		strerror_r(errno, err_buf, SIZEOF_ERR_BUF);
		zlog_error(zc, "mnl_socket_open %s", err_buf);
		ret = -1;
		goto out_logs;
	}

	if (mnl_socket_bind(nl, 0, MNL_SOCKET_AUTOPID) < 0) {
		strerror_r(errno, err_buf, SIZEOF_ERR_BUF);
		zlog_error(zc, "mnl_socket_bind %s", err_buf);
		ret = -1;
		goto out_netlink;
	}
	portid = mnl_socket_get_portid(nl);

	nlh = nfq_hdr_put(buf, NFQNL_MSG_CONFIG, queue_num);
	nfq_nlmsg_cfg_put_cmd(nlh, AF_INET6, NFQNL_CFG_CMD_BIND);
	if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0) {
		strerror_r(errno, err_buf, SIZEOF_ERR_BUF);
		zlog_error(zc, "mnl_socket_send NFQNL_CFG_CMD_BIND %s",
			   err_buf);
		ret = -1;
		goto out_netlink;
	}

	nlh = nfq_hdr_put(buf, NFQNL_MSG_CONFIG, queue_num);
	nfq_nlmsg_cfg_put_params(nlh, NFQNL_COPY_PACKET, 0xffff);

	mnl_attr_put_u32(nlh, NFQA_CFG_FLAGS, htonl(NFQA_CFG_F_GSO));
	mnl_attr_put_u32(nlh, NFQA_CFG_MASK, htonl(NFQA_CFG_F_GSO));
	if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0) {
		strerror_r(errno, err_buf, SIZEOF_ERR_BUF);
		zlog_error(zc, "mnl_socket_send NFQA_CFG_F_GSO "
			       "and NFQNL_COPY_PACKET %s", err_buf);
		ret = -1;
		goto out_netlink;
	}

	/* ENOBUFS is signalled to userspace when packets were lost
	 * on kernel side.  In most cases, userspace isn't interested
	 * in this information, so turn it off.
	 */
	err = 1;
	mnl_socket_setsockopt(nl, NETLINK_NO_ENOBUFS, &err, sizeof(int));

	zlog_info(zc, "nf_queue started");

	fd_set read_fds;
	struct timeval timeout;
	for (;!stop;) {
		FD_ZERO(&read_fds);
		FD_SET(mnl_socket_get_fd(nl), &read_fds);
		timeout.tv_sec = TIMEOUT_LOOP;
		timeout.tv_usec = 0;
		err = select(mnl_socket_get_fd(nl) + 1, &read_fds, NULL, NULL, &timeout);
		if (err < 0) {
			if (errno != EINTR) {
				strerror_r(errno, err_buf, SIZEOF_ERR_BUF);
				zlog_error(zc, "Select failed %s", err_buf);
				ret = -1;
			} else {
				zlog_warn(zc, "Program interrupted");
			}
			goto out_netlink;
		}
		if (FD_ISSET(mnl_socket_get_fd(nl), &read_fds)) {
			err = mnl_socket_recvfrom(nl, buf, SIZEOF_BUF);
			if (err == -1) {
				strerror_r(errno, err_buf, SIZEOF_ERR_BUF);
				zlog_error(zc, "mnl_socket_recvfrom %s", err_buf);
				ret = -1;
				goto out_netlink;
			}
			err = mnl_cb_run(buf, err, 0, portid, nf_queue_callback,
					 NULL);
			if (err < 0) {
				strerror_r(errno, err_buf, SIZEOF_ERR_BUF);
				zlog_error(zc, "mnl_cb_run %s", err_buf);
				ret = -1;
				goto out_netlink;
			}
		}
	}

out_netlink:
	mnl_socket_close(nl);
	zlog_info(zc, "Program exiting with error code %d", ret);
out_logs:
	zlog_fini();
out_path:
	free(path);
out:
	return ret;
}

