#include <bpf.h>
#include <netinet/in.h>
#include <uthash.h>

#include "sr-localctrl.h"
#include "prefixmatch.h"

#define SRH_KEY_VALUE_SIZE sizeof(uint32_t)
#define SRH_MAP_VALUE_SIZE 16+72
#define MAX_SRH 3

static uint32_t counter;

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

static struct srh_record *build_srh(json_t *segments, bool reverse_srh, size_t *srh_record_len, size_t *srh_len)
{
    *srh_record_len = (json_array_size(segments) + 1) * sizeof(struct in6_addr) + sizeof(struct srh_record);
    *srh_len = (json_array_size(segments) + 1) * sizeof(struct in6_addr) + sizeof(struct ipv6_sr_hdr);
    struct srh_record *srh_record = calloc(1, *srh_record_len);
    if (!srh_record) {
        zlog_warn(zc, "Cannot allocate memory for a new SRH");
        return NULL;
    }
    struct ipv6_sr_hdr *srh = &srh_record->srh;
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

    srh_record->is_valid = 1;
	return srh_record;
}

static int remove_segments(json_t *segments, bool reverse_srh)
{
    int err = 0;
    bool init_cache = false;
    size_t srh_record_len;
    size_t srh_len;
    struct hash_srh *hsrh = NULL;

    if (cfg.srh_cache) {
        zlog_debug(zc, "SRH removal skipped because never inserted (the hashmap is empty)");
        return 0;
    }

    struct srh_record *srh_record = build_srh(segments, reverse_srh, &srh_record_len, &srh_len);
    if (!srh_record) {
        return -1;
    }

    HASH_FIND(hh, cfg.srh_cache, &srh_record->srh, srh_record_len, hsrh);
    if (!hsrh) {
        zlog_debug(zc, "SRH removal skipped because never inserted");
        free(srh_record);
        return 0;
    }
    free(srh_record);
    srh_record = hsrh->srh_record;

    hsrh->refcount -= 1;
    if (hsrh->refcount > 0) {
        zlog_debug(zc, "SRH is used for another destination");
        return 0;
    }

    /* Remove it in eBPF map (by inserting an invalid srh record) */

    srh_record->is_valid = 0;
    char value [SRH_MAP_VALUE_SIZE];
    memset(value, 0, SRH_MAP_VALUE_SIZE);
    memcpy(value, srh_record, srh_record_len);

    if (bpf_map_update_elem(cfg.srh_map_fd, &srh_record->srh_id, value, BPF_ANY)) {
        zlog_warn(zc, "SRH couldn't be removed !");
        err = -1;
    }

    zlog_debug(zc, "SRH removed from the eBPF map");

    return err;
}

/**
 * Creates a new SRH based on a list of segments and insert it in both the program hashmap and the eBPF hashmap
 */
static int insert_segments(json_t *segments, bool reverse_srh)
{
    int err = 0;
    bool init_cache = false;
    size_t srh_record_len;
    size_t srh_len;
    struct hash_srh *hsrh = NULL, *cur_hsrh=NULL, *tmp = NULL;
    struct srh_record *srh_record = build_srh(segments, reverse_srh, &srh_record_len, &srh_len);
    if (!srh_record) {
        return -1;
    }

    /* Insert it in the hash if not already present */

    if (cfg.srh_cache) {
        HASH_FIND(hh, cfg.srh_cache, &srh_record->srh, srh_len, hsrh);
        if (hsrh) {
            zlog_debug(zc, "Same SRH received twice");
            err = 0; /* Already inserted */
            hsrh->refcount += 1;
            goto free_srh;
        }
    }

    hsrh = calloc(1, sizeof(struct hash_srh));
    if (!hsrh) {
        zlog_warn(zc, "Cannot allocate memory for hash entry of SRH");
        err = -1;
        goto free_srh;
    }
    hsrh->srh_record = srh_record;
    if (!cfg.srh_cache)
        init_cache = true;

    /* Insert it in eBPF map */

    srh_record->srh_id = counter;
    if (srh_record->srh_id >= MAX_SRH) { // Look for room in deleted records
        HASH_ITER(hh, cfg.srh_cache, cur_hsrh, tmp) {
            if (!cur_hsrh->srh_record->is_valid) {
                srh_record->srh_id = cur_hsrh->srh_record->srh_id;
                HASH_DEL(cfg.srh_cache, cur_hsrh);
                free(cur_hsrh->srh_record);
                free(cur_hsrh);
                zlog_debug(zc, "Old SRH with id %u is garbage collected", srh_record->srh_id);
                break;
            }
        }
    } else {
        counter++;
    }

    if (srh_record->srh_id < MAX_SRH) {
        char value [SRH_MAP_VALUE_SIZE];
        memset(value, 0, SRH_MAP_VALUE_SIZE);
        memcpy(value, srh_record, srh_record_len);

        if (bpf_map_update_elem(cfg.srh_map_fd, &srh_record->srh_id, value, BPF_ANY)) {
            zlog_warn(zc, "SRH couldn't be inserted !");
            err = -1;
            goto free_hsrh;
        }

        zlog_debug(zc, "SRH inserted in the eBPF map");

        hsrh->refcount = 1;
        HASH_ADD_KEYPTR(hh, cfg.srh_cache, &srh_record->srh, srh_len, hsrh);
        zlog_debug(zc, "SRH inserted in the Program Hashmap");
    } else {
        zlog_warn(zc, "Not enough room for a new SRH in the map !");
        err = -1;
        goto free_hsrh;
    }

    return 0;

free_hsrh:
    if (hsrh)
        free(hsrh);
    if (init_cache)
        cfg.srh_cache = NULL;
free_srh:
    if (srh_record)
        free(srh_record);
    return err;
}

void destroy_srh_cache()
{
    if (cfg.srh_cache) {
        struct hash_srh *hsrh, *tmp;
        HASH_ITER(hh, cfg.srh_cache, hsrh, tmp) {
            HASH_DEL(cfg.srh_cache, hsrh);
            free(hsrh->srh_record);
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

static bool same_segments(json_t *segs1, json_t *segs2)
{
    json_t *seg1, *seg2;

    if (json_array_size(segs1) != json_array_size(segs2))
        return false;

    for (size_t i = 0; i < json_array_size(segs1); i++) {
        seg1 = json_array_get(segs1, i);
        seg2 = json_array_get(segs2, i);
        if (json_string_length(seg1) != json_string_length(seg2))
            return false;
        if (strcmp(json_string_value(seg1), json_string_value(seg2)))
            return false;
    }

    return true;
}

static int paths_update(struct srdb_entry *entry, struct srdb_entry *diff,
                        unsigned int mask)
{
	struct srdb_path_entry *path_entry = (struct srdb_path_entry *) entry;
	struct srdb_path_entry *diff_entry = (struct srdb_path_entry *) diff;

	zlog_debug(zc, "New update path received");

    if ((mask & ENTRY_MASK(PA_SEGMENTS)) == 0) {
	    zlog_debug(zc, "This update does not change the segments");
        return 0;
    }

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

    /* Compare with old paths */

    json_t *segments = json_loads(path_entry->segments, 0, NULL);
    json_t *curr_segments;
    size_t idx = 0;

    json_t *old_segments = json_loads(diff_entry->segments, 0, NULL);
    json_t *curr_old_segments;
    size_t old_idx = 0;

    /* Remove old SRHs */

    bool found = false;
    json_array_foreach(old_segments, old_idx, curr_old_segments) {
        found = false;
        json_array_foreach(segments, idx, curr_segments) {
            if (same_segments(curr_segments, curr_old_segments)) {
                found = true;
                break;
            }
        }
        if (!found) {// TODO: Remove the srhs ids to the dest <-> srh map
            zlog_debug(zc, "An old SRH was not in the update");
            remove_segments(old_segments, reverse_srh);
        }
    }

    /* Insert new SRHs */

    json_array_foreach(segments, idx, curr_segments) {
        found = false;
        json_array_foreach(old_segments, old_idx, curr_old_segments) {
            if (same_segments(curr_segments, curr_old_segments)) {
                found = true;
                break;
            }
        }
        if (!found) {// TODO: Insert the srhs ids to the dest <-> srh map
            zlog_debug(zc, "A new SRH is in the update");
            insert_segments(curr_segments, reverse_srh);
        }
    }

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
