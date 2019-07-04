#include <netinet/in.h>
#include <uthash.h>

#include "sr-localctrl.h"
#include "prefixmatch.h"

/**
 * Returns true iff at least one prefix matches at least one of the endhost's global IPv6 addresses
 */
static bool matching_prefix(json_t *prefixes)
{
    json_t *jprefix;
    size_t idx;
    json_array_foreach(prefixes, idx, jprefix) {
        char *prefixchar = (char *) json_string_value(json_object_get(jprefix, "address"));
        if (!*prefixchar) {
            zlog_warn(zc, "Prefix is not a string");
            continue;
        }
        struct in6_addr prefix;
        size_t prefixlen = (size_t) json_integer_value(json_object_get(jprefix, "prefixlen"));
        if (network_pton(prefixchar, &prefix, prefixlen)) {
        	zlog_warn(zc, "Prefixes cannot be read correctly");
            return false;
        }

        for (size_t i = 0; i < cfg.nbr_laddrs; i++) {
            if (address_in_prefix(&cfg.laddrs[i], &prefix, prefixlen))
                return true;
        }
    }

    return false;
}

static struct ipv6_sr_hdr *build_srh(json_t *segments, bool reverse_srh, size_t *srh_len)
{
    *srh_len = (json_array_size(segments) + 1) * sizeof(struct in6_addr) + sizeof(struct ipv6_sr_hdr);
    struct ipv6_sr_hdr *srh = calloc(1, *srh_len);
    if (!srh) {
        zlog_warn(zc, "Cannot allocate memory for a new SRH");
        return NULL;
    }
	srh->type = 4;

	srh->hdrlen = ((json_array_size(segments) + 1) * sizeof(struct in6_addr)) / 8; // We do not count the first 8 bytes
	srh->segments_left = json_array_size(segments);
	srh->first_segment = json_array_size(segments);

    json_t *jseg;
    size_t i;
    json_array_foreach(segments, i, jseg) {
        size_t idx = reverse_srh ? i : json_array_size(segments) - i - 1;

        struct in6_addr seg;
        if (inet_pton(AF_INET6, json_string_value(jseg), &seg) != 1) {
            free(srh);
            zlog_warn(zc, "Cannot parse segments as IPv6 addresses");
            return NULL;
        }
        memcpy(&srh->segments[idx + 1], &seg, sizeof(struct in6_addr));
    }
    // Destination segment is left at 0

	return srh;
}

/**
 * Creates a new SRH based on a list of segments and insert it in both the program hashmap and the eBPF hashmap
 */
static int insert_segments(json_t *segments, bool reverse_srh)
{
    int err = 0;
    size_t srh_len;
    struct hash_srh *hsrh = NULL;
    struct ipv6_sr_hdr *srh = build_srh(segments, reverse_srh, &srh_len);
    if (!srh) {
        return -1;
    }

    /* Insert it in the hash if not already present */

    if (cfg.srh_cache) {
        HASH_FIND(hh, cfg.srh_cache, srh, srh_len, hsrh);
        if (hsrh) {
            zlog_debug(zc, "Same SRH received twice");
            err = 0; /* Already inserted */
            goto free_srh;
        }
    }

    hsrh = calloc(1, sizeof(struct hash_srh));
    if (!hsrh) {
        zlog_warn(zc, "Cannot allocate memory for hash entry of SRH");
        err = -1;
        goto free_srh;
    }
    hsrh->srh = srh;
    HASH_ADD_KEYPTR(hh, cfg.srh_cache, srh, srh_len, hsrh);

    zlog_debug(zc, "SRH inserted in the Program Hashmap");

    // TODO Insert it in eBPF map

    return 0;
free_srh:
    if (srh)
        free(srh);
    return err;
}

void destroy_srh_cache()
{
    if (cfg.srh_cache) {
        struct hash_srh *hsrh, *tmp;
        HASH_ITER(hh, cfg.srh_cache, hsrh, tmp) {
            HASH_DEL(cfg.srh_cache, hsrh);
            free(hsrh->srh);
            free(hsrh);
        }
    }
}

static int paths_read(struct srdb_entry *entry)
{
    struct srdb_path_entry *path_entry = (struct srdb_path_entry *) entry;

	zlog_debug(zc, "New path received");

    json_t *prefixes = json_loads(path_entry->prefixes, 0, NULL);
    json_t *prefixes_rt1 = json_array_get(prefixes, 0);
    json_t *prefixes_rt2 = json_array_get(prefixes, 1);

    bool reverse_srh = false;
    if (matching_prefix(prefixes_rt1)) {
        reverse_srh = false;
    } else if (matching_prefix(prefixes_rt2)) {
        reverse_srh = true;
    } else {
        zlog_debug(zc, "The path is not for this endhost");
        goto free_prefixes;
    }
    zlog_debug(zc, "The path is for this endhost");

    json_t *segments = json_loads(path_entry->segments, 0, NULL);
    json_t *curr_segments;
    size_t idx = 0;
    json_array_foreach(segments, idx, curr_segments) {
        insert_segments(curr_segments, reverse_srh);
        // TODO: Insert the srhs ids to the dest <-> srh map 
    }

    json_decref(segments);
free_prefixes:
    json_decref(prefixes);
    return 0;
}

static int paths_update(struct srdb_entry *entry, struct srdb_entry *diff _unused,
                        unsigned int mask _unused)
{
	struct srdb_path_entry *path_entry = (struct srdb_path_entry *) entry;

	zlog_debug(zc, "New update path received");

    struct json_t *prefixes = json_loads(path_entry->prefixes, 0, NULL);
    struct json_t *prefixes_rt1 = json_array_get(prefixes, 0);
    struct json_t *prefixes_rt2 = json_array_get(prefixes, 1);

    bool reverse_srh = false;
    if (matching_prefix(prefixes_rt1)) {
        reverse_srh = false;
    } else if (matching_prefix(prefixes_rt2)) {
        reverse_srh = true;
    } else {
        zlog_debug(zc, "The path is not for this endhost");
        goto free_prefixes;
    }
    zlog_debug(zc, "The path is for this endhost");

    struct json_t *segments = json_loads(path_entry->segments, 0, NULL);
    struct json_t *curr_segments;
    size_t idx = 0;
    json_array_foreach(segments, idx, curr_segments) {
        insert_segments(curr_segments, reverse_srh);
        // TODO: Insert the srhs ids to the dest <-> srh map 
    }

    // TODO: For updates, Mapping between destination and SRHs should be removed if not renewed (+ a refcount on SRHs)

    json_decref(segments);
free_prefixes:
    json_decref(prefixes);
    return 0;
}

int launch_srdb()
{
	unsigned int mon_flags;

	mon_flags = MON_INITIAL | MON_INSERT | MON_UPDATE;
	if (srdb_monitor(cfg.srdb, "Paths", mon_flags, paths_read,
                     paths_update, NULL, false, true) < 0)
		return -1;
	return 0;
}
