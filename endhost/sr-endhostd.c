#include <stdio.h>
#include <errno.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <zlog.h>

#include "sr-endhostd.h"

#define MAX_PATH 255

static zlog_category_t *zc;
volatile int stop;


void sig_handler(int signal_number _unused)
{
	stop = 1;
}

int install_srh(struct connection *conn _unused,
		struct ipv6_sr_hdr *srh _unused,
		size_t srh_len _unused)
{
	// TODO Install the rule !
	return 0;
}

int main (int argc _unused, char *argv[] _unused)
{
	int ret;
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
	zc = zlog_get_category("sr-endhostd");
	if (!zc) {
		fprintf(stderr, "Initiating main log category failed\n");
		ret = -1;
		goto out_logs;
	}

	/* Catching signals */
	if (signal(SIGINT, sig_handler) == SIG_ERR) {
		zlog_warn(zc, "Cannot catch SIG_INT");
	}

	/* Monitor setup */
	if (monitor_init()) {
		ret = -1;
		goto out_logs;
	}

	zlog_notice(zc, "SRv6 rerouting endhost daemon has started");

	/* Main Processing */
	struct connection conn;
	struct ipv6_sr_hdr *srh;
	size_t srh_len = 0;
	while (!stop) {
		if ((err = monitor(&conn, &srh, &srh_len)) < 0)
			zlog_warn(zc, "No SRH was retrieved");
		else if (!err)
			continue;

		if (install_srh(&conn, srh, srh_len))
			zlog_warn(zc, "Cannot produce an SRH for a connection");
	}

	monitor_free();
out_logs:
	zlog_fini();
out_path:
	free(path);
out:
	return ret;
}

