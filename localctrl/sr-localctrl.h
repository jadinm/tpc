#ifndef LOCALCTRL_H
#define LOCALCTRL_H

#include <linux/seg6.h>
#include <netinet/in.h>
#include <srdb.h>
#include <sys/socket.h>
#include <zlog.h>

#define _unused __attribute__((unused))


struct srh_record {
        uint32_t srh_id;
        uint32_t is_valid;
        uint64_t curr_bw; 
        struct ipv6_sr_hdr srh;
} __attribute__((packed));

struct hash_srh {
	uint32_t srh_hash; // hash of the srh (also used for eBPF mapping)
	struct srh_record *srh_record;
	uint32_t refcount;
	UT_hash_handle hh;
};

struct hash_dest {
	struct in6_addr dest;
	uint32_t *srh_hash; // list of srhs that are valid for this destination
	UT_hash_handle hh;
};

struct config {
	struct ovsdb_config ovsdb_conf;
	struct srdb *srdb;

	struct in6_addr *laddrs;
	size_t nbr_laddrs;
	struct hash_srh *srh_cache; // hashmap of srhs

	char *zlog_conf_file;

	int srh_map_fd; // eBPF fd for the SRH map
	int conn_map_fd; // eBPF fd for the connection map
};

extern struct config cfg;
extern zlog_category_t *zc;

int launch_srdb();
void destroy_srh_cache();

#endif