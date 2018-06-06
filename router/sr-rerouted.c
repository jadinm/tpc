#include <arpa/inet.h>
#include <errno.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <zlog.h>
#include <jansson.h>
#include <stdio.h>

#include "sr-rerouted.h"


#define MAX_PATH 255
#define SIZEOF_ERR_BUF 256

static zlog_category_t *zc;
volatile int stop;

size_t icmp_len;
void *icmp;

struct config cfg;
static json_t *root_cfg;

void sig_handler(int signal_number _unused)
{
	stop = 1;
}

static void help(char *argv[])
{
	printf("Usage: %s [-h] [-d] config_file\n", argv[0]);
	printf("-d to only check the config_file syntax\n");
	printf("-h to print this message\n");
}

static void clean_config()
{
	if (root_cfg) {
		json_decref(root_cfg);
		root_cfg = NULL;
	}
}

static int load_config(const char *config_file)
{
	int err = 0;
	json_error_t json_err;
	root_cfg = json_load_file(config_file, 0, &json_err);
	if (!root_cfg) {
		fprintf(stderr, "Cannot load config file: %s\nCause: %s\n",
			config_file, json_err.text);
		return -1;
	}

	err = json_unpack_ex(root_cfg, &json_err, 0, "{s?s}",
			     "zlogfile", &cfg.zlog_conf_file); // Config file path for zlog (optional)
	if (err < 0) {
		fprintf(stderr, "Cannot parse config file: %s\nCause: %s\n",
			config_file, json_err.text);
		json_decref(root_cfg);
		return -1;
	}

	return 0;
}

int build_srh(struct connection *conn, struct ipv6_sr_hdr *srh)
{
	memset(srh, 0, sizeof(*srh));
	srh->hdrlen = (2 * sizeof(struct in6_addr)) / 8; // We do not count the first 8 bytes
	srh->type = 4;
	srh->segments_left = 1;
	srh->first_segment = 1;

	struct in6_addr segment;
	inet_pton(AF_INET6, "::1", &segment); // TODO Do not hardcode segment

	memcpy(&srh->segments[0], &conn->dst, sizeof(struct in6_addr));
	memcpy(&srh->segments[1], &segment, sizeof(struct in6_addr));
	return 0;
}

int main(int argc, char *argv[])
{
	int ret = 0;
	int err = 0;
	int dryrun = 0;
	char opt;

	/* Parsing arguments */
	while ((opt = getopt(argc, argv, "hd")) != -1) {
		switch (opt) {
		case 'h':
			help(argv);
			ret = 0;
			goto out;
		case 'd':
			dryrun = 1;
			break;
		default:
			fprintf(stderr, "Unrecognized option\n");
			help(argv);
			ret = -1;
			goto out;
		}
	}

	if (optind >= argc) {
		fprintf(stderr, "No config file in argument\n");
		help(argv);
		ret = -1;
		goto out;
	}

	if (load_config(argv[optind]) < 0) {
		ret = -1;
		goto out;
	}

	/* Logs setup */
	int rc = zlog_init(cfg.zlog_conf_file);
	if (rc) {
		fprintf(stderr, "Initiating logs failed\n");
		ret = -1;
		goto out_config;
	}
	zc = zlog_get_category("sr-rerouted");
	if (!zc) {
		fprintf(stderr, "Initiating main log category failed\n");
		ret = -1;
		goto out_logs;
	}

	/* Stop here if it was a dryrun */
	if (dryrun) {
		ret = 0;
		printf("Valid Configuration\n");
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
out_config:
	clean_config();
out:
	return ret;
}

