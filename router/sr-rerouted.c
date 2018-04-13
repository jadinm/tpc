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


void sig_handler(int signal_number _unused)
{
	stop = 1;
}

static int build_srh(struct connection *conn, struct ipv6_sr_hdr *srh,
		     size_t *srh_len)
{
	memset(srh, 0, sizeof(*srh));
	srh->hdrlen = 4;
	srh->type = 4;
	srh->segments_left = 1;
	srh->first_segment = 1;

	struct in6_addr segment;
	inet_pton(AF_INET6, "fc00::2", &segment); // TODO Do not hardcode segment

	memcpy(&srh->segments[0], &conn->dst, sizeof(struct in6_addr));
	memcpy(&srh->segments[1], &segment, sizeof(struct in6_addr));

	*srh_len = sizeof(*srh) + 2 * sizeof(struct in6_addr);
	return 0;
}

int main(int argc _unused, char *argv[] _unused)
{
	int ret = 0;
	int err = 0;

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
	zc = zlog_get_category("sr-rerouted");
	if (!zc) {
		fprintf(stderr, "Initiating main log category failed\n");
		ret = -1;
		goto out_logs;
	}

	/* Catching signals */
	if (signal(SIGINT, sig_handler) == SIG_ERR) {
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
	size_t srh_len = notification_alloc_size();
	struct ipv6_sr_hdr *srh = malloc(srh_len);
	if (!srh) {
		zlog_error(zc, "Cannot allocate memory for the SRH");
	}
	while (!stop) {
		memset(&conn, 0, sizeof(conn));
		if ((err = nf_queue_recv(&conn)) < 0)
			zlog_warn(zc, "No connection was retrieved");
		else if (!err)
			continue;

		if (build_srh(&conn, srh, &srh_len))
			zlog_warn(zc, "Cannot produce an SRH for a connection");

		if (notify_endhost(&conn, srh, srh_len))
			zlog_warn(zc, "Cannot notify the endhost");
	}

	notifier_free();
out_nf_queue:
	nf_queue_free();
out_logs:
	zlog_fini();
out_path:
	free(path);
out:
	return ret;
}

