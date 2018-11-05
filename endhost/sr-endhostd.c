#include <arpa/inet.h>
#include <errno.h>
#include <jansson.h>
#include <linux/seg6.h>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <uthash.h>
#include <zlog.h>

#include "sr-endhostd.h"

#define MAX_PATH 255
#define MAX_ADDRESS 30

static zlog_category_t *zc;
static char buf[1024];

volatile int stop;
struct config cfg;


void sig_handler(int signal_number _unused)
{
	stop = 1;
	zlog_warn(zc, "SIGINT was received");
}

static void help(char *argv[])
{
	printf("Usage: %s [-h] [-d] config_file\n", argv[0]);
	printf("-d to only check the config_file syntax\n");
	printf("-h to print this message\n");
}

static struct ipv6_sr_hdr *get_srh(char *segments[], size_t segment_number)
{
	struct ipv6_sr_hdr *srh;
	size_t srh_len = sizeof(*srh) + (segment_number + 1) * sizeof(struct in6_addr);
	srh = malloc(srh_len);
	if (!srh) {
		zlog_error(zc, "Out of memory\n");
		return NULL;
	}

	srh->nexthdr = 0;
	srh->hdrlen = 2*(segment_number + 1);
	srh->type = 4;
	srh->segments_left = segment_number;
	srh->first_segment = srh->segments_left;
	srh->flags = 0;
	srh->tag = 0;
	memset(&srh->segments[0], 0, sizeof(struct in6_addr)); // Final destination segment

	for (size_t i = 0; i < segment_number; i++) {
		if (inet_pton(AF_INET6, segments[i],
			      &srh->segments[segment_number-i]) != 1) {
			zlog_error(zc, "Cannot parse %s as an IPv6 address\n",
				 segments[i]);
			free(srh);
			return NULL;
		}
	}

	return srh;
}

/**
 * Create a new TCP socket with the SRH in argument and start the TCP connection
 * with the server.
 * If no SRH is supplied, it creates the default one.
 * When connected, a new entry is added to the hashtable of sockets.
 */
static int create_new_socket(struct ipv6_sr_hdr *srh)
{
	int ret = -1;
	bool change_srh = false;
	int sfd = socket(AF_INET6, SOCK_STREAM, 0);
	if (sfd < 0) {
		zlog_error(zc, "Cannot initialize socket: errno = %d\n", errno);
		ret = -1;
		goto out;
	}
	struct sockaddr_in6 sin6;
	memset(&sin6, 0, sizeof(sin6));
	sin6.sin6_family = AF_INET6;
	sin6.sin6_port = htons(cfg.server_port);
	sin6.sin6_addr = cfg.server_addr;

	if (!srh) {
		change_srh = true;
		srh = get_srh(NULL, 0);
		if (!srh) {
			ret = -1;
			zlog_error(zc, "Cannot produce the default SRH\n");
			goto out;
		}
	}
	size_t srh_len = (srh->hdrlen + 1) << 3;

	if (setsockopt(sfd, IPPROTO_IPV6, IPV6_RTHDR, srh, srh_len) < 0) {
		zlog_error(zc, "Cannot set the SRH in the socket - errno = %d",
			   errno);
		ret = -1;
		goto err_srh;
	}

	int flag = true;
	if (setsockopt(sfd, IPPROTO_IPV6, IPV6_RECVERR, &flag, sizeof(flag))) {
		zlog_error(zc, "Cannot activate error catching - errno = %d",
			   errno);
		goto err_srh;
	}

	if (connect(sfd, (struct sockaddr *) &sin6, sizeof(sin6)) < 0) {
		zlog_error(zc, "Cannot connect to server: errno = %d\n", errno);
		ret = -1;
		goto err_srh;
	}

	struct hash_sfd *hsfd= malloc(sizeof(struct hash_sfd));
	if (!hsfd) {
		ret = -1;
		zlog_error(zc, "Cannot allocate hash_sfd\n");
		goto err_close;
	}
	hsfd->srh = srh;
	hsfd->sfd = sfd;
	HASH_ADD(hh, cfg.sockets, srh, srh_len, hsfd);

	ret = hsfd->sfd;
out:
	return ret;
err_close:
	close(sfd);
err_srh:
	if (change_srh)
		free(srh);
	goto out;
}

static int switch_socket(struct ipv6_sr_hdr *srh)
{
	size_t srh_len = (srh->hdrlen + 1) << 3;
	struct hash_sfd *hsfd = NULL;
	int sfd = -1;

	HASH_FIND(hh, cfg.sockets, srh, srh_len, hsfd);
	if (hsfd) { /* Switch to previously created socket */
		free(srh);

		srh = hsfd->srh;
		sfd = hsfd->sfd;

		/* The old SRH was erased by the ICMP so we need to reset it on
		 * the socket.
		 */
		if (setsockopt(sfd, IPPROTO_IPV6, IPV6_RTHDR, srh, srh_len) < 0) {
			zlog_error(zc, "Cannot set the SRH in the socket - errno = %d",
				   errno);
			return -1;
		}
		return sfd;
	}

	return create_new_socket(srh);
}

static struct ipv6_sr_hdr *send_traffic(int sfd)
{
	struct pollfd pfd;
	pfd.fd = sfd;
	pfd.events = POLLOUT; // POLLERR will be set on revent

	while (true) {
		if (poll(&pfd, 1, 0) < 1) {
			zlog_error(zc, "poll failed on socket %d - errno %d\n",
				   sfd, errno);
			return NULL;
		}
		if (pfd.revents & POLLNVAL) {
			zlog_error(zc, "poll - socket %d is not open\n",
				   sfd);
			return NULL;
		}
		if (pfd.revents & POLLERR) { // An ICMP was received

			int err = 0;
			socklen_t size = sizeof(err);
			if (getsockopt(sfd, SOL_SOCKET, SO_ERROR, &err,
				       &size) < 0) {
				zlog_error(zc, "Cannot get back the error\n");
				return NULL;
			}
			if (err != EPROTO) { // Likely some destination unreachable
				zlog_warn(zc, "A different error occurred - error %d\n",
					  err);
				continue;
			}

			socklen_t srh_len = sizeof(struct ipv6_sr_hdr) + 
				sizeof(struct in6_addr) * MAX_ADDRESS;
			struct ipv6_sr_hdr *srh = malloc(srh_len);
			if (!srh) {
				zlog_error(zc, "Cannot allocate memory for SRH\n");
				return NULL;
			}
			if (getsockopt(sfd, IPPROTO_IPV6, IPV6_RTHDR, &srh,
				       &srh_len) < 0) {
				zlog_error(zc, "Cannot get back the SRH in the ICMP - errno = %d\n",
					   errno);
				free(srh);
				srh = NULL;
			}
			return srh;
		}
		if (pfd.revents & POLLOUT) {
			if (send(sfd, buf, sizeof(buf), 0) < 0) {
				zlog_error(zc, "Cannot send on socket %d - errno %d\n",
					   sfd, errno);
				return NULL;
			}
		}
	}
}

static void clean_config()
{
	if (cfg.zlog_conf_file) {
		free(cfg.zlog_conf_file);
		cfg.zlog_conf_file = NULL;
	}
	if (cfg.sockets) {
		struct hash_sfd *hsfd, *tmp;
		HASH_ITER(hh, cfg.sockets, hsfd, tmp) {
			zlog_debug(zc, "Cleaning socket %d\n", hsfd->sfd);
			HASH_DEL(cfg.sockets, hsfd);
			if (close(hsfd->sfd)) {
				zlog_warn(zc, "Cannot close socket %d\n",
					  hsfd->sfd);
			}
			free(hsfd->srh);
			free(hsfd);
		}
	}
}

static void default_config()
{
	cfg.zlog_conf_file = NULL;
	cfg.sockets = NULL;
	cfg.server_addr = in6addr_loopback;
	cfg.server_port = 80;
}

static int load_var_string(json_t *root_cfg, json_error_t *json_err,
			   const char *name, char **value)
{
	char *tmp = NULL;
	int err = json_unpack_ex(root_cfg, json_err, 0, "{s?:s}", name, &tmp);
	if (err < 0) {
		return -1;
	} else if (tmp) {
		*value = malloc((strlen(tmp) + 1) * sizeof(char));
		if (!*value) {
			fprintf(stderr, "Cannot allocate parameter\n");
			return -1;
		}
		strcpy(*value, tmp);
	}
	return 0;
}

static int load_in6(json_t *root_cfg, json_error_t *json_err,
		    const char *name, struct in6_addr *addr)
{
	char *tmp = NULL;
	int err = json_unpack_ex(root_cfg, json_err, 0, "{s?:s}", name, &tmp);
	if (err < 0) {
		return -1;
	} else if (tmp) {
		if (!inet_pton(AF_INET6, tmp, addr))
			return -1;
	}
	return 0;
}

static int load_config(const char *config_file)
{
	json_t *root_cfg;
	json_error_t json_err;
	memset(&json_err, 0, sizeof(json_err));

	root_cfg = json_load_file(config_file, 0, &json_err);
	if (!root_cfg)
		goto err;

	/* Load default values */
	default_config();

	/* Config file path for zlog */
	if (load_var_string(root_cfg, &json_err, "zlogfile",
			    &cfg.zlog_conf_file))
		goto err;
	if (load_in6(root_cfg, &json_err, "server_addr",
		     &cfg.server_addr))
		goto err;
	if (json_unpack_ex(root_cfg, &json_err, 0, "{s?:i}", "server_port",
			   &cfg.server_port) < 0)
		goto err;

	json_decref(root_cfg);
	return 0;
err:
	fprintf(stderr, "Cannot parse config file: %s\nCause: %s\nSource: %s\nLine %d Column %d\n",
		config_file, json_err.text, json_err.source, json_err.line, json_err.column);
	if (root_cfg)
		json_decref(root_cfg);
	clean_config();
	return -1;
}

int main (int argc, char *argv[])
{
	bool dryrun = false;
	int ret = 0;
	int opt;

	/* Parsing arguments */
	while ((opt = getopt(argc, argv, "hd")) != -1) {
		switch (opt) {
		case 'h':
			help(argv);
			ret = 0;
			goto out;
		case 'd':
			dryrun = true;
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
	zc = zlog_get_category("sr-endhostd");
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
	sa.sa_handler = sig_handler;
	sa.sa_flags = 0;
	if (sigaction(SIGINT, &sa, NULL) == -1) {
		zlog_warn(zc, "Cannot catch SIG_INT\n");
	}

	/* Main Processing */
	int sfd = create_new_socket(NULL);
	if (sfd < 0) {
		ret = -1;
		zlog_error(zc, "Cannot create and connect the initial socket\n");
		goto out_logs;
	}
	zlog_notice(zc, "SRv6 ICMP endhost has started\n");

	while (!stop || sfd < 0) {
		struct ipv6_sr_hdr *srh = send_traffic(sfd);
		if (!srh) {
			ret = -1;
			goto out_logs;
		}
		sfd = switch_socket(srh);
	}

out_logs:
	zlog_notice(zc, "SRv6 ICMP endhost has finished\n");
	zlog_fini();
out_config:
	clean_config();
out:
	return ret;
}

