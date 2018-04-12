#include <arpa/inet.h>
#include <errno.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <zlog.h>

#include "sr-rerouted.h"


#define MAX_PATH 255
#define SIZEOF_ERR_BUF 256
#define SRH_MAX_SIZE sizeof(struct ipv6_sr_hdr) + 2 * sizeof(struct in6_addr)

static zlog_category_t *zc;
static char err_buf[SIZEOF_ERR_BUF];
volatile int stop;


void sig_handler(int signal_number _unused)
{
	stop = 1;
}

static int build_srh(struct connection *conn, struct ipv6_sr_hdr *srh,
		     size_t srh_len)
{
	memset(&srh, 0, srh_len);
	srh->hdrlen = 4;
	srh->type = 4;
	srh->segment_left = 1;
	srh->first_segment = 1;

	struct in6_addr segment;
	inet_pton(AF_INET6, "fc00::2", &segment); // TODO Do not hardcode segment

	memset(&srh->segments[0], conn->dst, sizeof(struct in6_addr));
	memcpy(&srh->segments[1], &segment, sizeof(struct in6_addr));
	return 0;
}

int main(int argc _unused, char *argv[] _unused)
{
	int ret = 0;
	int err = 0;
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
	struct ipv6_sr_hdr *srh = malloc(SRH_MAX_SIZE);
	if (!srh) {
		zlog_error(zc, "Cannot allocate memory for the SRH");
	}
	while (!stop) {
		memset(&conn, 0, sizeof(conn));
		if ((err = nf_queue_recv(&conn)) < 0)
			zlog_warn(zc, "No connection was retrieved");
		else if (!err)
			continue;

		if (conn_processing(&conn, &srh, SRH_MAX_SIZE))
			zlog_warn(zc, "Cannot produce an SRH for a connection");

		if (notify_endhost(&conn, &srh, SRH_MAX_SIZE))
			zlog_warn(zc, "Cannot notify the endhost");
	}

out_notifier:
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

