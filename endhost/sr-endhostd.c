#include <arpa/inet.h>
#include <errno.h>
#include <jansson.h>
#include <linux/seg6.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
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
#define MIN_CHANGE 1000 // Minimum different in µs of RTT to change the path

static zlog_category_t *zc;
static char buf[1024];
static char probe_buf[1024];

volatile int stop;
struct config cfg;
struct hash_sfd main_hsfd;
pthread_rwlock_t lock;


void sig_handler(int signal_number)
{
	if (signal_number == SIGINT) {
		stop = 1;
		pthread_kill(cfg.switch_thread, SIGUSR1);
		for(struct hash_sfd *iter = cfg.sockets; iter; iter = iter->hh.next)
			pthread_kill(iter->thread, SIGUSR1);
	}
}

static void help(char *argv[])
{
	printf("Usage: %s [-h] [-d] config_file\n", argv[0]);
	printf("-d to only check the config_file syntax\n");
	printf("-h to print this message\n");
}

static struct ipv6_sr_hdr *get_srh(char *segments[], size_t segment_number,
				   size_t *srh_len)
{
	struct ipv6_sr_hdr *srh;
	*srh_len = sizeof(*srh) + (segment_number + 1) * sizeof(struct in6_addr);
	srh = calloc(1, *srh_len);
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
	memcpy(&srh->segments[0], &cfg.server_addr, sizeof(struct in6_addr)); // Final destination segment

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
static struct hash_sfd *create_new_socket(struct hash_sfd *hsfd, bool main_fd)
{
	struct ipv6_sr_hdr *srh = hsfd->srh;
	bool change_srh = false;
	int sfd = socket(AF_INET6, SOCK_STREAM, 0);
	if (sfd < 0) {
		zlog_error(zc, "Cannot initialize socket: errno = %d\n", errno);
		goto out;
	}
	struct sockaddr_in6 sin6;
	memset(&sin6, 0, sizeof(sin6));
	sin6.sin6_family = AF_INET6;
	sin6.sin6_port = htons(cfg.server_port);
	sin6.sin6_addr = cfg.server_addr;

	size_t srh_len = 0;
	if (!srh) {
		change_srh = true;
		srh = get_srh(NULL, 0, &srh_len);
		if (!srh) {
			zlog_error(zc, "Cannot produce the default SRH\n");
			if (!main_fd)
				free(hsfd);
			hsfd = NULL;
			goto out;
		}
		zlog_debug(zc, "SRH of size %lu produced\n", srh_len);
	} else {
		srh_len = (srh->hdrlen + 1) << 3;
		zlog_debug(zc, "Creating a socket for SRH of size %lu\n",
			   srh_len);
	}

	if (setsockopt(sfd, IPPROTO_IPV6, IPV6_RTHDR, srh, srh_len) < 0) {
		zlog_error(zc, "Cannot set the SRH in the socket - errno = %d",
			   errno);
		if (!main_fd)
			free(hsfd);
		hsfd = NULL;
		goto err_srh;
	}

	int flag = true;
	if (setsockopt(sfd, IPPROTO_IPV6, IPV6_RECVERR, &flag, sizeof(flag))) {
		zlog_error(zc, "Cannot activate error catching - errno = %d",
			   errno);
		if (!main_fd)
			free(hsfd);
		hsfd = NULL;
		goto err_srh;
	}

	if (connect(sfd, (struct sockaddr *) &sin6, sizeof(sin6)) < 0) {
		char tmp [INET6_ADDRSTRLEN + 1];
		inet_ntop(AF_INET6, &sin6.sin6_addr, tmp, sizeof(tmp));
		zlog_error(zc, "Cannot connect to server ([%s]:%d): errno = %d\n",
			   tmp, ntohs(sin6.sin6_port), errno);
		if (!main_fd)
			free(hsfd);
		hsfd = NULL;
		goto err_srh;
	}

	hsfd->srh = srh;
	hsfd->sfd = sfd;

	struct tcp_info info;
	socklen_t tcp_info_length = sizeof(info);
	if (getsockopt(sfd, SOL_TCP, TCP_INFO, &info, &tcp_info_length)) {
		zlog_error(zc, "Cannot get TCP INFO when creating the probe socket: %s", strerror(errno));
		if (!main_fd)
			free(hsfd);
		hsfd = NULL;
		goto err_close;
	} else {
		hsfd->last_rtt = info.tcpi_rtt;
	}

	flag = true;
	if (setsockopt(sfd, SOL_TCP, TCP_NODELAY, &flag, sizeof(flag))) {
		zlog_error(zc, "Cannot disable Nagle algo in probes - errno = %d",
			   errno);
		if (!main_fd)
			free(hsfd);
		hsfd = NULL;
		goto err_srh;
	}

	if (!main_fd) {
		if (pthread_rwlock_wrlock(&lock)) {
			zlog_error(zc, "Cannot write lock");
			if (!main_fd)
				free(hsfd);
			hsfd = NULL;
			goto err_close;
		}
		HASH_ADD_KEYPTR(hh, cfg.sockets, hsfd->srh, srh_len, hsfd);
		pthread_rwlock_unlock(&lock);
	}
out:
	return hsfd;
err_close:
	close(sfd);
err_srh:
	if (change_srh)
		free(srh);
	goto out;
}

static void *probe_thread(void *arg)
{
	struct hash_sfd *hsfd;
	struct timespec sleep_time = {
		.tv_sec = 0,
		.tv_nsec = 100000L
	};
	probe_buf[0] = 0;

	sigset_t set;
	sigemptyset(&set);
	sigaddset(&set, SIGINT);
	if (sigprocmask(SIG_BLOCK, &set, NULL)) {
		zlog_error(zc, "%s: Cannot block SIGINT\n", strerror(errno));
		return NULL;
	}

	hsfd = create_new_socket((struct hash_sfd *) arg, false);
	int fd = hsfd->sfd;

	while (!stop) {
		for (int i = 0; i < 15; i++) {
			if (send(fd, probe_buf, sizeof(probe_buf), 0) < 0) {
				zlog_error(zc, "Cannot send probe: %s", strerror(errno));
				return NULL;
			}
		}
		struct tcp_info info;
		socklen_t tcp_info_length = sizeof(info);
		if (getsockopt(fd, SOL_TCP, TCP_INFO, &info, &tcp_info_length)) {
			zlog_error(zc, "Cannot get back TCP INFO when probing: %s", strerror(errno));
		} else {
			hsfd->last_rtt = info.tcpi_rtt;
			zlog_debug(zc, "Probing - last rtt %u", hsfd->last_rtt);
		}
		if (nanosleep(&sleep_time, NULL) < 0) {
			zlog_error(zc, "Cannot sleep %s", strerror(errno));
			return NULL;
		}
	}

	return NULL;
}

static int add_probe(struct ipv6_sr_hdr *srh)
{
	size_t srh_len = (srh->hdrlen + 1) << 3;
	struct hash_sfd *hsfd = NULL;

	HASH_FIND(hh, cfg.sockets, srh, srh_len, hsfd);
	if (hsfd) { /* Probe already exists */
		return -1;
	} else {
		hsfd = calloc(1, sizeof(struct hash_sfd));
		if (!hsfd) {
			zlog_error(zc, "Cannot allocate hash_sfd");
			return -1;
		}
		hsfd->srh = srh;
		if (pthread_create(&hsfd->thread, NULL, probe_thread, hsfd)) {
			zlog_error(zc, "Cannot create thread");
			return -1;
		}
		return 0;
	}
}

static struct ipv6_sr_hdr *send_traffic(int sfd)
{
	struct pollfd pfd;
	pfd.fd = sfd;
	pfd.events = POLLOUT; // POLLERR will be set on revent

	while (!stop) {
		if (poll(&pfd, 1, -1) < 1) {
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
			if (getsockopt(sfd, IPPROTO_IPV6, IPV6_RTHDR, srh,
				       &srh_len) < 0) {
				zlog_error(zc, "Cannot get back the SRH in the ICMP - errno = %d\n",
					   errno);
				free(srh);
				srh = NULL;
			}
			zlog_debug(zc, "Received an new SRH of size %u\n",
				   srh_len);
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
	return NULL;
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
			fprintf(stderr, "Cleaning socket %d\n", hsfd->sfd);
			HASH_DEL(cfg.sockets, hsfd);
			if (close(hsfd->sfd)) {
				fprintf(stderr, "Cannot close socket %d\n", hsfd->sfd);
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

static void *switch_thread_run(void *arg _unused)
{
	struct timespec sleep_time = {
		.tv_sec = 0,
		.tv_nsec = 100000L
	};
	struct hash_sfd *current_rtt = NULL;
	struct hash_sfd *min_rtt = NULL;
	struct hash_sfd *iter = NULL;

	sigset_t set;
	sigemptyset(&set);
	sigaddset(&set, SIGINT);
	if (sigprocmask(SIG_BLOCK, &set, NULL)) {
		zlog_error(zc, "%s: Cannot block SIGINT\n", strerror(errno));
		return NULL;
	}

	while (!stop) {
		if (nanosleep(&sleep_time, NULL) < 0) {
			zlog_error(zc, "Cannot sleep %s", strerror(errno));
			return NULL;
		}

		size_t srh_len = (main_hsfd.srh->hdrlen + 1) << 3;
		HASH_FIND(hh, cfg.sockets, main_hsfd.srh, srh_len, current_rtt);

		if (pthread_rwlock_rdlock(&lock)) {
			zlog_error(zc, "Cannot read lock");
			return NULL;
		}

		/* Loop on all keys - if sufficient DIFF, then switch */
		min_rtt = current_rtt;
		for(iter=cfg.sockets; iter; iter=iter->hh.next) {
			zlog_debug(zc, "RTT of socket %d is %d", iter->sfd, iter->last_rtt);
			if (!min_rtt || min_rtt->last_rtt > iter->last_rtt)
				min_rtt = iter;
		}
		if (min_rtt != current_rtt &&
		    min_rtt->last_rtt < current_rtt->last_rtt - MIN_CHANGE) {
			/* Set current SRH */
			zlog_debug(zc, "Switch socket event !\n");
			main_hsfd.srh = min_rtt->srh;
			size_t srh_len = (main_hsfd.srh->hdrlen + 1) << 3;
			if (setsockopt(main_hsfd.sfd, IPPROTO_IPV6, IPV6_RTHDR, main_hsfd.srh, srh_len) < 0) {
				zlog_error(zc, "Cannot set the SRH in the socket - errno = %d",
					   errno);
				return NULL;
			}
			current_rtt = min_rtt;
		}
		pthread_rwlock_unlock(&lock);
	}
	return NULL;
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
	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = sig_handler;
	if (sigaction(SIGINT, &sa, NULL) == -1) {
		zlog_warn(zc, "Cannot catch SIG_INT\n");
	}

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = sig_handler;
	if (sigaction(SIGUSR1, &sa, NULL) == -1) {
		zlog_warn(zc, "Cannot catch SIG_INT\n");
	}

	if (pthread_rwlock_init(&lock, NULL)) {
		zlog_error(zc, "Cannot create rwlock %s", strerror(errno));
		ret = -1;
		goto out_logs;
	}

	/* Main Processing */
	if (!create_new_socket(&main_hsfd, true)) {
		ret = -1;
		zlog_error(zc, "Cannot create and connect the initial socket\n");
		goto out_rwlock;
	}

	/* Start probe on main path */
	size_t srh_len = (main_hsfd.srh->hdrlen + 1) << 3;
	struct ipv6_sr_hdr *srh = malloc(srh_len);
	if (!srh) {
		zlog_error(zc, "Cannot allocate memory for srh\n");
		ret = -1;
		goto out_socket;
	}
	memcpy(srh, main_hsfd.srh, srh_len);
	if (add_probe(srh)) {
		ret = -1;
		free(srh);
		goto out_main_srh;
	}

	/* Start switching thread */
	pthread_create(&cfg.switch_thread, NULL, switch_thread_run, NULL);

	zlog_notice(zc, "SRv6 ICMP endhost has started\n");

	while (!stop || srh) {
		srh = send_traffic(main_hsfd.sfd);
		if (!srh) {
			ret = -1;
			goto out_threads;
		}
		if (add_probe(srh)) {
			ret = -1;
			free(srh);
			goto out_threads;
		}
	}

out_threads:
	stop = 1;
	pthread_join(cfg.switch_thread, NULL);
	for(struct hash_sfd *iter = cfg.sockets; iter; iter = iter->hh.next)
		pthread_join(iter->thread, NULL);
out_main_srh:
	if (main_hsfd.srh)
		free(main_hsfd.srh);
out_socket:
	if (main_hsfd.sfd > 0)
		close(main_hsfd.sfd);
out_rwlock:
	pthread_rwlock_destroy(&lock);
out_logs:
	zlog_notice(zc, "SRv6 ICMP endhost has finished\n");
	zlog_fini();
out_config:
	clean_config();
out:
	return ret;
}

