#include <bpf.h>
#include <getopt.h>
#include <jansson.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <sys/socket.h>
#include <unistd.h>
#include <uthash.h>
#include <zlog.h>

#include "prefixmatch.h"
#include "sr-localctrl.h"

zlog_category_t *zc;
sem_t sem_stop;

struct config cfg;

static void help(char *argv[])
{
	printf("Usage: %s [-h] [-d] config_file\n", argv[0]);
	printf("-d to only check the config_file syntax\n");
	printf("-h to print this message\n");
}

void sig_handler(int signal_number _unused)
{
	sem_post(&sem_stop);
}

static int srdb_print(const char *fmt, ...)
{
	va_list args;
	va_start(args, fmt);
	vzlog_error(zc, fmt, args);
	va_end(args);
	return 0;
}

static void clean_config()
{
	if (cfg.zlog_conf_file) {
		free(cfg.zlog_conf_file);
		cfg.zlog_conf_file = NULL;
	}
	if (cfg.dest_map_fd >= 0) {
		close(cfg.dest_map_fd);
	}
}

static void default_config()
{
	cfg.zlog_conf_file = NULL;
	strncpy(cfg.ovsdb_conf.ovsdb_client, "ovsdb-client", SLEN + 1);
	strncpy(cfg.ovsdb_conf.ovsdb_server, "tcp:[::1]:6640", SLEN + 1);
	strncpy(cfg.ovsdb_conf.ovsdb_database, "SR_test", SLEN + 1);
	cfg.ovsdb_conf.ntransacts = 1;
	cfg.dest_map_fd = -1;
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

static int load_string(json_t *root_cfg, json_error_t *json_err,
		       const char *name, char *value)
{
	char *tmp = NULL;
	int err = json_unpack_ex(root_cfg, json_err, 0, "{s?:s}", name, &tmp);
	if (err < 0) {
		return -1;
	} else if (tmp) {
		strncpy(value, tmp, SLEN + 1);
	}
	return 0;
}

static int load_int(json_t *root_cfg, json_error_t *json_err,
		    const char *name, int *value)
{
	int tmp = -1;
	int err = json_unpack_ex(root_cfg, json_err, 0, "{s?:i}", name, &tmp);
	if (err < 0) {
		return -1;
	} else if (tmp > 0) {
		*value = tmp;
	}
	return 0;
}

static int load_config(const char *config_file)
{
	json_t *root_cfg;
	json_error_t json_err;

	root_cfg = json_load_file(config_file, 0, &json_err);
	if (!root_cfg)
		goto err;

	/* Load default values */
	default_config();

	/* Config file path for zlog */
	if (load_var_string(root_cfg, &json_err, "zlogfile",
			    &cfg.zlog_conf_file))
		goto err;

	/* ovsdb-client binary location */
	if (load_string(root_cfg, &json_err, "ovsdb-client",
			cfg.ovsdb_conf.ovsdb_client))
		goto err;

	/* Parameter describing the remote server (see ovsdb-client(1) for formatting) */
	if (load_string(root_cfg, &json_err, "ovsdb-server",
			cfg.ovsdb_conf.ovsdb_server))
		goto err;

	/* Name of the OVSDB database */
	if (load_string(root_cfg, &json_err, "ovsdb-database",
			cfg.ovsdb_conf.ovsdb_database))
		goto err;

	/* Number of threads of transactions for OVSDB */
	if (load_int(root_cfg, &json_err, "ntransacts",
		     &cfg.ovsdb_conf.ntransacts))
		goto err;

	/* Id of the connection map */
	int dest_map_id = -1;
	if (load_int(root_cfg, &json_err, "dest_map_id",
			&dest_map_id))
		goto err;

	cfg.dest_map_fd = bpf_map_get_fd_by_id(dest_map_id);
	if (cfg.dest_map_fd < 0) {
		fprintf(stderr, "Cannot retrieve destination map with id %d\n", dest_map_id);
		perror("");
		if (root_cfg)
			json_decref(root_cfg);
		clean_config();
		return -1;
	}

	json_decref(root_cfg);
	return 0;
err:
	fprintf(stderr, "Cannot parse config file: %s\nCause: %s\n",
		config_file, json_err.text);
	if (root_cfg)
		json_decref(root_cfg);
	clean_config();
	return -1;
}

int main(int argc, char *argv[])
{
	int ret = 0;
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
	zc = zlog_get_category("sr-localctrl");
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

	cfg.laddrs = get_global_addresses(&cfg.nbr_laddrs);
	if (!cfg.laddrs) {
		zlog_error(zc, "Cannot load IPv6 addresses\n");
		ret = -1;
		goto out_logs;
	}

	cfg.srdb = srdb_new(&cfg.ovsdb_conf, srdb_print);
	if (!cfg.srdb) {
		zlog_error(zc, "Cannot initialize SRDB\n");
		ret = -1;
		goto out_addrs;
	}

	/* Catching signals */
	struct sigaction sa;
	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = sig_handler;
	sa.sa_flags = 0;
	if (sigaction(SIGINT, &sa, NULL) == -1) {
		zlog_warn(zc, "Cannot catch SIG_INT");
	}

	if (launch_srdb() < 0) {
		zlog_error(zc, "Cannot start srdb monitors\n");
		ret = -1;
		goto out_srdb;
	}

	if (sem_init(&sem_stop, 0, 0)) {
		zlog_error(zc, "Cannot start the stop semaphore\n");
	}

	zlog_notice(zc, "SRv6 rerouting daemon has started");

	sem_wait(&sem_stop);
	sem_destroy(&sem_stop);

out_srdb:
	srdb_destroy(cfg.srdb);
	destroy_dest_cache();
out_addrs:
	if (cfg.laddrs)
    	free(cfg.laddrs);
out_logs:
	zlog_fini();
out_config:
	clean_config();
out:
	return ret;
}
