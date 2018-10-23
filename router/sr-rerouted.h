#ifndef SR_REROUTED_H
#define SR_REROUTED_H

#include <linux/seg6.h>
#include <srdb.h>
#include <hashmap.h>
#include <lpm.h>

#define _unused __attribute__((unused))

struct connection {
	struct in6_addr src;
	struct in6_addr dst;
	__u16 src_port;
	__u16 dst_port;
};

struct prefix {
	struct in6_addr addr;
	int len;
};

struct config {
	struct ovsdb_config ovsdb_conf;
	char *zlog_conf_file;

	struct srdb *srdb;
	struct hashmap *path_cache;
	struct lpm_tree *prefixes; // Maps an host address to its access router address
};

struct path {
	struct in6_addr *segments;
	size_t nb_segments;
};

struct flow {
	struct in6_addr *addrs;
	struct path *paths;
	size_t nb_paths;
	struct prefix *prefixes;
};

extern struct config cfg;

int build_srh(struct connection *conn, struct ipv6_sr_hdr *srh);

int notifier_init();
size_t notification_alloc_size();
void *create_icmp(void *packet, size_t *icmp_len, struct connection *conn);
int notify_endhost(struct connection *conn, void *icmp, size_t icmp_len);
int notifier_free();

int nf_queue_init();
int nf_queue_recv(struct connection *conn);
int nf_queue_free();

#endif /* SR_RETOURED_H */

