#include <arpa/inet.h>
#include <errno.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <zlog.h>

#include "sr-rerouted.h"


#define MAX_PATH 255
#define SIZEOF_ERR_BUF 256

static zlog_category_t *zc;
volatile int stop;

size_t icmp_len;
void *icmp;


void sig_handler(int signal_number _unused)
{
	stop = 1;
}

int build_srh(struct connection *conn, struct ipv6_sr_hdr *srh)
{
	memset(srh, 0, sizeof(*srh));
	srh->hdrlen = (2 * sizeof(struct in6_addr)) / 8; // We do not count the first 8 bytes
	srh->type = 4;
	srh->segments_left = 1;
	srh->first_segment = 1;

	struct in6_addr segment;
	inet_pton(AF_INET6, "fc00::2", &segment); // TODO Do not hardcode segment

	memcpy(&srh->segments[0], &conn->dst, sizeof(struct in6_addr));
	memcpy(&srh->segments[1], &segment, sizeof(struct in6_addr));
	return 0;
}

int main(int argc, char *argv[])
{
	int ret = 0;
	int err = 0;

	if (argc < 1) {
		fprintf(stderr, "Usage: %s zlog-config\n", argv[0]);
		ret = -1;
		goto out;
	}

	/* Logs setup */
	int rc = zlog_init(argv[1]);
	if (rc) {
		fprintf(stderr, "Initiating logs failed\n");
		ret = -1;
		goto out;
	}
	zc = zlog_get_category("sr-rerouted");
	if (!zc) {
		fprintf(stderr, "Initiating main log category failed\n");
		ret = -1;
		goto out_logs;
	}

	/* Catching signals */
	struct sigaction sa;
	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = sig_handler;
	sa.sa_flags = 0;
	if (sigaction(SIGINT, &sa, NULL) == -1) {
		zlog_warn(zc, "Cannot catch SIG_INT");
	}

	/* Netfilter setup */
	if (nf_queue_init()) {
		ret = -1;
		goto out_logs;
	}

	/* Notifier setup */
	if (notifier_init()) {
		ret = -1;
		goto out_nf_queue;
	}

	zlog_notice(zc, "SRv6 rerouting daemon has started");

	/* Main Processing */
	struct connection conn;
	icmp_len = notification_alloc_size();
	icmp = malloc(icmp_len);
	if (!icmp) {
		zlog_error(zc, "Cannot allocate memory for the ICMP");
	}
	while (!stop) {
		memset(&conn, 0, sizeof(conn));
		if ((err = nf_queue_recv(&conn)) < 0) {
			zlog_error(zc, "No connection was retrieved");
			continue;
		} else if (!err) {
			zlog_warn(zc, "Queue polling was interrupted");
			continue;
		}
	}

	free(icmp);
	notifier_free();
out_nf_queue:
	nf_queue_free();
out_logs:
	zlog_fini();
out:
	return ret;
}

