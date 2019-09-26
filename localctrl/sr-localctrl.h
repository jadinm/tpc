#ifndef LOCALCTRL_H
#define LOCALCTRL_H

#include <linux/seg6.h>
#include <netinet/in.h>
#include <srdb.h>
#include <sys/socket.h>
#include <zlog.h>

#define _unused __attribute__((unused))

#define MAX_SRH_BY_DEST 3
#define MAX_SEGS_NBR 4

struct srh_record {
	uint32_t srh_id;
	uint32_t is_valid;
	uint64_t curr_bw; 
	struct ipv6_sr_hdr srh;

	struct in6_addr segments[MAX_SEGS_NBR];
} __attribute__((packed));

struct dest_infos {
	struct in6_addr dest;
	struct srh_record srhs[MAX_SRH_BY_DEST];
} __attribute__((packed));

#define DEST_KEY_VALUE_SIZE sizeof(in6_addr)
#define DEST_MAP_VALUE_SIZE sizeof(dest_infos)

struct hash_dest {
	struct dest_infos info;
	UT_hash_handle hh;
};

struct config {
	struct ovsdb_config ovsdb_conf;
	struct srdb *srdb;

	struct in6_addr *laddrs;
	size_t nbr_laddrs;
	struct hash_dest *dest_cache; // hashmap of srhs by destination

	char *zlog_conf_file;

	int dest_map_fd; // eBPF fd for the connection map
};

extern struct config cfg;
extern zlog_category_t *zc;

int launch_srdb();
void destroy_dest_cache();

#endif