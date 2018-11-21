#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <jansson.h>
#include <netdb.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>
#include <time.h>
#include <zlog.h>


#define _unused __attribute__((unused))
#define MAX_CONNECTIONS 1000

struct config {
	char *zlog_conf_file;
	int server_port;
	int eval_file;
};

static zlog_category_t *zc;
static char buf [1024];
struct config cfg;
int stop;

struct timespec last_measure;
uint64_t transfer_size;

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

/* including code from manpage of getaddrinfo(3) */
static int create_listening_socket()
{
	struct addrinfo hints, *servinfo, *p;
	int sfd = -1;
	int rv;

	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_INET6;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE;

	snprintf(buf, 1024, "%d", cfg.server_port);
	if ((rv = getaddrinfo(NULL, buf, &hints, &servinfo)) != 0) {
		zlog_error(zc, "Cannot getaddrinfo - %d\n", errno);
		goto err;
	}

	for(p = servinfo; p != NULL; p = p->ai_next) {
		if ((sfd = socket(p->ai_family, p->ai_socktype,
				  p->ai_protocol)) == -1) {
			zlog_warn(zc, "Cannot create socket - %d\n", errno);
			continue;
		}

		int reuse = 1;
		if (setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(int)) < 0) {
			zlog_error(zc, "Cannot set reuse address - errno %d\n", errno);
			goto close_sfd;
		}

		if (bind(sfd, p->ai_addr, p->ai_addrlen) == -1) {
			close(sfd);
			zlog_warn(zc, "Binding socket socket - %d\n", errno);
			continue;
		}
		break;
	}
	freeaddrinfo(servinfo);

	if (p == NULL) {
		zlog_error(zc, "Cannot bind socket - %d\n", errno);
		goto err;
	}

	if (listen(sfd, 10) == -1) {
		zlog_error(zc, "Cannot listen - errno %d\n", errno);
		goto close_sfd;
	}

	return sfd;
close_sfd:
	close(sfd);
err:
	return -1;
}

static void clean_sfds(struct pollfd *pfd, size_t nbr_sockets)
{
	for (size_t i = 0; i < nbr_sockets; i++) {
		if (close(pfd[i].fd) < 0) {
			zlog_warn(zc, "Cannot close socket number %lu\n", i);
		}
	}
}

static void clean_config()
{
	if (cfg.zlog_conf_file) {
		free(cfg.zlog_conf_file);
		cfg.zlog_conf_file = NULL;
	}
	if (cfg.eval_file >= 0) {
		if (close(cfg.eval_file) < 0) {
			fprintf(stderr, "Cannot close the eval file"
			       " - errno %d\n", errno);
		}
		cfg.eval_file = -1;
	}
}

static void default_config()
{
	cfg.zlog_conf_file = NULL;
	cfg.server_port = 80;
	cfg.eval_file = -1;
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

static int load_fd(json_t *root_cfg, json_error_t *json_err,
		   const char *name, int *fd)
{
	char *tmp = NULL;
	int err = load_var_string(root_cfg, json_err, name, &tmp);
	if (err < 0) {
		return -1;
	} else if (tmp) {
		*fd = open(tmp, O_CREAT | O_TRUNC | O_WRONLY,
			   S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
		if (*fd < 0) {
			fprintf(stderr, "Cannot open eval file - errno %d\n",
				errno);
			free(tmp);
			return -1;
		}
	}
	free(tmp);
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
	if (json_unpack_ex(root_cfg, &json_err, 0, "{s?:i}", "server_port",
			   &cfg.server_port) < 0)
		goto err;
	if (load_fd(root_cfg, &json_err, "evalfile",
		    &cfg.eval_file))
		goto err;

	json_decref(root_cfg);
	return 0;
err:
	fprintf(stderr, "Cannot parse config file: %s\nCause: %s\n"
		"Source: %s\nLine %d Column %d\n",
		config_file, json_err.text, json_err.source,
		json_err.line, json_err.column);
	if (root_cfg)
		json_decref(root_cfg);
	clean_config();
	return -1;
}

static void write_evalfile(int sfd, int received)
{
	struct timespec tp;
	transfer_size += received;
	if (clock_gettime(CLOCK_MONOTONIC, &tp)) {
		zlog_warn(zc, "Cannot measure time ! - errno %d\n", errno);
	} else if (cfg.eval_file >= 0 && tp.tv_sec >= last_measure.tv_sec + 1) {
		char evalbuf[1024];
		snprintf(evalbuf, 1024, "%d %lu %lu.%lu\n", sfd, transfer_size,
			 tp.tv_sec, tp.tv_nsec);
		last_measure = tp;
		transfer_size = 0;
		if (write(cfg.eval_file, evalbuf, strlen(evalbuf)) < 0)
			zlog_warn(zc, "Cannot write to eval file !"
				  " - errno %d\n", errno);
	}
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
	zc = zlog_get_category("sr-serverd");
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

	/* Main Processing */
	int listen_sfd = create_listening_socket();
	if (listen_sfd < 0) {
		ret = -1;
		zlog_error(zc, "Cannot create the listening socket\n");
		goto out_logs;
	}
	zlog_notice(zc, "Server has started\n");

	struct pollfd pfd[MAX_CONNECTIONS + 1]; // Parametrize
	pfd[0].fd = listen_sfd;
	pfd[0].events = POLLIN;
	pfd[0].revents = 0;
	size_t nbr_conn = 0;
	int err = 0;
	while (!stop) {
		if ((err = poll(pfd, nbr_conn + 1, -1)) < 1) {
			zlog_error(zc, "poll failed - ret %d - errno %d\n",
				   err, errno);
			ret = -1;
			goto out_sfds;
		}

		/* Accept new connections */
		if (pfd[0].revents & POLLIN) {
			if (nbr_conn + 1 > MAX_CONNECTIONS) {
				zlog_error(zc, "Cannot accept connection - Maximum number of connections reached\n");
				ret = -1;
				goto out_sfds;
			}
			int sfd = accept(listen_sfd, NULL, NULL);
			if (sfd < 0) {
				zlog_error(zc, "Cannot accept connection - errno %d\n",
					   errno);
				ret = -1;
				goto out_sfds;
			}
			nbr_conn += 1;
			pfd[nbr_conn].fd = sfd;
			pfd[nbr_conn].events = POLLIN;
			pfd[nbr_conn].revents = 0;
		}
		if (pfd[0].revents & POLLNVAL) {
			zlog_error(zc, "poll - listening socket is not open\n");
			ret = -1;
			goto out_sfds;
		}
		if (pfd[0].revents & POLLERR) {
			zlog_error(zc, "ICMP received just for SYNs !\n");
			ret = -1;
			goto out_sfds;
		}

		/* Empty queues on all connections */
		for (size_t i = 1; i <= nbr_conn; i++) {
			if (pfd[i].revents & POLLNVAL) {
				zlog_error(zc, "poll - socket %d number %lu is not open\n",
					   pfd[i].fd, i);
				ret = -1;
				goto out_sfds;
			}
			if (pfd[i].revents & POLLERR) {
				zlog_warn(zc, "ICMP received just for ACKs");
			}
			if (pfd[i].revents & POLLIN) {
				int received;
				if ((received = recv(pfd[i].fd, buf,
						     sizeof(buf), 0)) < 0) {
					zlog_error(zc, "Cannot receive - errno %d\n",
						   errno);
					ret = -1;
					goto out_sfds;
				}
				if (cfg.eval_file >= 0) {
					write_evalfile(pfd[i].fd, received);
				} else {
					zlog_error(zc, "fd is %d\n", cfg.eval_file);
				}
			}
		}
	}

out_sfds:
	clean_sfds(pfd, nbr_conn);
out_logs:
	zlog_notice(zc, "Server has finished\n");
	zlog_fini();
out_config:
	clean_config();
out:
	return ret;
}

