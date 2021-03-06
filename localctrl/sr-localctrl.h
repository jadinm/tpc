#ifndef LOCALCTRL_H
#define LOCALCTRL_H

#include <linux/seg6.h>
#include <netinet/in.h>
#include <srdb.h>
#include <sys/socket.h>
#include <zlog.h>
#include <linux/bpf.h>

#define _unused __attribute__((unused))

#define MAX_SRH_BY_DEST 8
#define MAX_SEGS_NBR 10
#define MAX_EXPERTS MAX_SRH_BY_DEST + 2 // one expert telling 100% on a single path + one random expert + one expert always stable

struct srh_record {
	uint32_t srh_id;
	uint32_t is_valid;
	uint64_t curr_bw;
	uint64_t delay; // ms
	struct ipv6_sr_hdr srh;

	struct in6_addr segments[MAX_SEGS_NBR];
} __attribute__((packed));

struct dest_infos {
	struct in6_addr dest;
	__u32 max_reward;
	struct srh_record srhs[MAX_SRH_BY_DEST];
	floating exp4_weights[MAX_EXPERTS];
	__u32 last_srh_id;
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

	int dest_map_fd; // eBPF fd for the SRH map
	int short_dest_map_fd; // eBPF fd for the short connections SRH map
};

extern struct config cfg;
extern zlog_category_t *zc;

int launch_srdb();
void destroy_dest_cache();

#endif