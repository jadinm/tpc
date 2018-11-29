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

void sig_handler(int signal_number _unused)
{
	stop = 1;
}

static int srdb_print(const char *fmt, ...)
{
	va_list args;
	va_start(args, fmt);
	vzlog_error(zc, fmt, args);
	va_end(args);
	return 0;
}

static void help(char *argv[])
{
	printf("Usage: %s [-h] [-d] config_file\n", argv[0]);
	printf("-d to only check the config_file syntax\n");
	printf("-h to print this message\n");
}

/* The hash is the same whatever the order of addresses in the pair */
static unsigned int hash_addr_pair(void *key)
{
	struct in6_addr *in6 = key;
	return hashint(hashint(in6->s6_addr32[0]) ^ hashint(in6->s6_addr32[1]) ^
		       hashint(in6->s6_addr32[2]) ^ hashint(in6->s6_addr32[3]) ^
		       hashint(in6[1].s6_addr32[0]) ^ hashint(in6[1].s6_addr32[1]) ^
		       hashint(in6[1].s6_addr32[2]) ^ hashint(in6[1].s6_addr32[3]));
}

static int compare_addr_pair(void *k1, void *k2)
{
	struct in6_addr *k1_in6 = k1;
	struct in6_addr *k2_in6 = k2;

	return !((!compare_in6(k1, k2)
		  && !compare_in6(&k1_in6[1], &k2_in6[1]))
		 || (!compare_in6(k1, &k2_in6[1])
		     && !compare_in6(&k1_in6[1], k2)));
}

static void clean_config()
{
	if (cfg.zlog_conf_file) {
		free(cfg.zlog_conf_file);
		cfg.zlog_conf_file = NULL;
	}
}

static void default_config()
{
	cfg.zlog_conf_file = NULL;
	strncpy(cfg.ovsdb_conf.ovsdb_client, "ovsdb-client", SLEN + 1);
	strncpy(cfg.ovsdb_conf.ovsdb_server, "tcp:[::1]:6640", SLEN + 1);
	strncpy(cfg.ovsdb_conf.ovsdb_database, "SR_test", SLEN + 1);
	cfg.ovsdb_conf.ntransacts = 1;
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

static void free_flow(struct flow *fl)
{
	if (fl) {
		for (size_t i = 0; i < fl->nb_paths; i++) {
			if (fl->paths[i].segments)
				free(fl->paths[i].segments);
		}
		if (fl->paths)
			free(fl->paths);
		if (fl->prefixes)
			free(fl->prefixes);
		if (fl->addrs)
			free(fl->addrs);
		free(fl);
	}
}

static int json_to_in6(json_t *array, struct in6_addr **addrs)
{
	bool allocated = false;
	int index, length;
	json_t *value;
	const char *buf;

	length = json_array_size(array);
	if (length <= 0)
		goto out;

	/* Allocate memory if needed */
	if (!*addrs) {
		allocated = true;
		*addrs = malloc(sizeof(struct in6_addr) * length);
		if (!*addrs) {
			length = -1;
			goto out;
		}
	}

	/* Convert json list of IPv6 addresses to an IPv6 list */
	json_array_foreach(array, index, value) {
		buf = json_string_value(value);
		if (!buf || !inet_pton(AF_INET6, buf, &(*addrs)[index])) {
			length = -1;
			goto err_addr_table;
		}
	}
out:
	return length;
err_addr_table:
	if (allocated)
		free(*addrs);
	goto out;
}

static struct prefix *parse_host_prefixes(const char *jbuf,
					  struct in6_addr *rt_addrs)
{
	json_t *array, *value, *sub_array;
	const char *ip;
	size_t index;
	int length;

	array = json_loads(jbuf, 0, NULL);
	length = json_array_size(array);
	if (length != 2)
		return NULL;

	length = json_array_size(json_array_get(array, 0))
		+ json_array_size(json_array_get(array, 1));
	if (length < 2) {
		json_decref(array);
		return NULL;
	}

	// TODO Allocate space for all prefixes
	struct prefix *prefixes = malloc(sizeof(struct prefix)*length);
	if (!prefixes) {
		json_decref(array);
		return NULL;
	}

	int j = 0;
	for (int i = 0; i < 2; i++) {
		sub_array = json_array_get(array, i);
		json_array_foreach(sub_array, index, value) {
			json_unpack(value, "{s:s, s:i}", "address", &ip,
				    "prefixlen", &prefixes[j].len);
			inet_pton(AF_INET6, ip, &prefixes[j].addr);
			lpm_insert(cfg.prefixes, &prefixes[j].addr,
				   prefixes[j].len, &rt_addrs[i]);
			j++;
		}
	}

	json_decref(array);
	return prefixes;
}

static int jsonchar_to_in6(const char *json_array, struct in6_addr **addrs)
{
	json_t *array;
	int length;

	array = json_loads(json_array, 0, NULL);
	length = json_to_in6(array, addrs);

	json_decref(array);
	return length;
}

static int json_to_paths(const char *json_array, struct path **paths)
{
	bool allocated = false;
	json_t *array, *value;
	struct path *current;
	int index, length;

	array = json_loads(json_array, 0, NULL);
	length = json_array_size(array);
	if (length <= 0)
		goto out;

	zlog_debug(zc, "%d paths for the flow:\n%s\n", length, json_array);

	/* Allocate memory if needed */
	if (!*paths) {
		allocated = true;
		*paths = calloc(length, sizeof(struct path));
		if (!*paths) {
			length = 0;
			goto out_json_decref;
		}
	}

	/* Convert json list of list of segments to a list of segments */
	json_array_foreach(array, index, value) {
		current = &(*paths)[index];
		int err = json_to_in6(value, &current->segments);
		if (err < 0) {
			length = -1;
			goto err_path_table;
		}
		current->nb_segments = (size_t) err;
	}

out_json_decref:
	json_decref(array);
out:
	return length;
err_path_table:
	if (allocated)
		free(*paths);
	goto out_json_decref;
}

static struct flow *new_flow(struct srdb_entry *entry)
{
	struct srdb_path_entry *path_entry = (struct srdb_path_entry *) entry;
	struct flow *fl = NULL;

	fl = calloc(1, sizeof(*fl));
	if (!fl) {
		zlog_warn(zc, "Cannot allocate memory for flow");
		goto out;
	}

	int nb = jsonchar_to_in6(path_entry->flow,
				 (struct in6_addr **) &fl->addrs);
	if (nb != 2) {
		zlog_warn(zc, "Cannot find flow information");
		goto free_fl;
	}

	fl->prefixes = parse_host_prefixes(path_entry->prefixes,
					   (struct in6_addr *) fl->addrs);
	if (!fl->prefixes) {
		zlog_warn(zc, "Cannot set host prefixes for flow");
		goto free_fl;
	}

	fl->nb_paths = json_to_paths(path_entry->segments, &fl->paths);
	if (fl->nb_paths < 1) {
		zlog_warn(zc, "Cannot find any path with the flow");
		goto free_fl;
	}

	/* TODO Not the best strategy since all paths are not interesting to keep */
	hmap_set(cfg.path_cache, fl->addrs, fl);

out:
	return fl;
free_fl:
	free_flow(fl);
	fl = NULL;
	goto out;
}

static int paths_read(struct srdb_entry *entry)
{
	zlog_debug(zc, "New path received");
	if (!new_flow(entry))
		zlog_warn(zc, "Cannot create the newly inserted flow");
	return 0;
}

static int paths_update(struct srdb_entry *entry, struct srdb_entry *diff __unused__,
			unsigned int mask __unused__)
{
	struct srdb_path_entry *path_entry = (struct srdb_path_entry *) entry;
	struct in6_addr *addrs = NULL;

	zlog_debug(zc, "Update of path received");

	int nb = jsonchar_to_in6(path_entry->flow, (struct in6_addr **) &addrs);
	if (nb != 2) {
		zlog_warn(zc, "Cannot find flow information");
		return 0;
	}

	struct flow *old_fl = hmap_get(cfg.path_cache, addrs);
	if (!old_fl)
		zlog_warn(zc, "Update received before the insertion");

	struct flow *fl = new_flow(entry);
	if (!fl) {
		zlog_warn(zc, "Cannot create flow from updated entry");
		return 0;
	}

	if (old_fl)
		free_flow(old_fl);
	return 0;
}

static void destroy_path_cache()
{
	struct hmap_entry *he;

	if (cfg.path_cache) {
		while (!llist_empty(&cfg.path_cache->keys)) {
			he = llist_first_entry(&cfg.path_cache->keys,
					       struct hmap_entry, key_head);
			llist_remove(&he->key_head);
			llist_remove(&he->map_head);
			cfg.path_cache->elems--;
			free_flow((struct flow *) he->elem);
			free(he);
		}
		hmap_destroy(cfg.path_cache);
	}
}

static int launch_srdb()
{
	unsigned int mon_flags;

	mon_flags = MON_INITIAL | MON_INSERT | MON_UPDATE;
	if (srdb_monitor(cfg.srdb, "Paths", mon_flags, paths_read,
			 paths_update, NULL, false, true) < 0)
		return -1;
	return 0;
}

static bool same_path(struct connection *conn, struct path *path, bool reversed)
{
	struct ipv6_sr_hdr *srh = conn->srh;
	if (srh && path->nb_segments == srh->first_segment) { // The destination segment is not in the Path segment list
		for (size_t i = 0; i < path->nb_segments; i++) {
			size_t idx = !reversed ? i : path->nb_segments - i - 1;
			if (memcmp(&srh->segments[srh->first_segment - i],
				   &path->segments[idx], sizeof(struct in6_addr)))
				return false;
		}
		return true;
	}
	return false;
}

int build_srh(struct connection *conn, struct ipv6_sr_hdr *srh)
{
	memset(srh, 0, sizeof(*srh));
	srh->type = 4;

	struct in6_addr addr_pair[2];
	addr_pair[0] = *(struct in6_addr *) lpm_lookup(cfg.prefixes, &conn->src);
	addr_pair[1] = *(struct in6_addr *) lpm_lookup(cfg.prefixes, &conn->dst);

	char buf_tmp [1024];
	inet_ntop(AF_INET6, addr_pair, buf_tmp, 1024);
	zlog_debug(zc, "lpm_lookup 1 - %s\n", buf_tmp);
	inet_ntop(AF_INET6, &addr_pair[1], buf_tmp, 1024);
	zlog_debug(zc, "lpm_lookup 2 - %s\n", buf_tmp);

	struct flow *fl = hmap_get(cfg.path_cache, addr_pair);
	if (!fl) {
		zlog_warn(zc, "Flow not found\n");
		return -1;
	}

	/* We need to reverse the SRH if the source and destination are reversed */
	bool reversed = !(!compare_in6(addr_pair, fl->addrs)
			  && !compare_in6(&addr_pair[1], &fl->addrs[1]));

	// TODO Check on malloced size

	/* Choose randomly one of the paths */
	int idx = rand() % fl->nb_paths;
	zlog_debug(zc, "Path index found %d\n", idx);
	if (same_path(conn, &fl->paths[idx], reversed)) {
		zlog_debug(zc, "Same path ! - alternative ? %d\n", fl->nb_paths > 1);
		if (fl->nb_paths == 1)
			return -1; // No alternative path
		idx = (idx + 1) % fl->nb_paths;
	}
	struct path *path = &fl->paths[idx];

	srh->hdrlen = ((path->nb_segments + 1) * sizeof(struct in6_addr)) / 8; // We do not count the first 8 bytes
	srh->segments_left = path->nb_segments;
	srh->first_segment = path->nb_segments;

	for (size_t i = 0; i < path->nb_segments; i++) {
		idx = reversed ? i : path->nb_segments - i - 1;
		memcpy(&srh->segments[i + 1], &path->segments[idx],
		       sizeof(struct in6_addr));
	}
	memcpy(&srh->segments[0], &conn->dst, sizeof(struct in6_addr));
	return sizeof(struct ipv6_sr_hdr) + srh->hdrlen * 8;
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

	cfg.path_cache = hmap_new(hash_addr_pair, compare_addr_pair);
	if (!cfg.path_cache) {
		zlog_error(zc, "Cannot create hashmap for path cache\n");
		ret = -1;
		goto out_logs;
	}

	cfg.prefixes = lpm_new();
	if (!cfg.prefixes) {
		zlog_error(zc, "Cannot create LPM tree\n");
		ret = -1;
		goto out_path_cache;
	}

	cfg.srdb = srdb_new(&cfg.ovsdb_conf, srdb_print);
	if (!cfg.srdb) {
		zlog_error(zc, "Cannot initialize SRDB\n");
		ret = -1;
		goto out_lpm;
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
		goto out_srdb;
	}

	/* Notifier setup */
	if (notifier_init()) {
		ret = -1;
		goto out_nf_queue;
	}

	if (launch_srdb() < 0) {
		zlog_error(zc, "Cannot start srdb monitors\n");
		ret = -1;
		goto out_notifier;
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
			zlog_debug(zc, "No connection was retrieved");
			continue;
		} else if (!err) {
			zlog_warn(zc, "Queue polling was interrupted");
			continue;
		}
	}

	free(icmp);
	srdb_monitor_join_all(cfg.srdb);
out_notifier:
	notifier_free();
out_nf_queue:
	nf_queue_free();
out_srdb:
	srdb_destroy(cfg.srdb);
out_lpm:
	lpm_destroy(cfg.prefixes);
out_path_cache:
	destroy_path_cache();
out_logs:
	zlog_fini();
out_config:
	clean_config();
out:
	return ret;
}

