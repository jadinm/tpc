#include <bpf.h>
#include <netinet/in.h>
#include <uthash.h>

#include "sr-localctrl.h"
#include "prefixmatch.h"

static uint32_t counter;



// floating part
// XXX Sync with the kernel

#define FLOATING_BIAS 1024
#define FLOATING_LARGEST_BIT ((uint64_t) 1U) << 63U

static uint64_t floating_u64_pow(uint64_t base, uint32_t exponent)
{
	uint32_t i;
	uint64_t pow = 1;
	for (i = 1; i <= 64; i++) { // -1024 is the maximum for an exponent in double
        uint32_t xxx = i;
		if (xxx <= exponent)
			pow *= base;
	}
	return pow;
}

static uint32_t floating_decimal_to_binary(uint32_t decimal, uint32_t digits)
{
	// Encode the decimal as a sum of negative powers of 2
	uint32_t i = 1;
	uint64_t shift = 0;
	uint64_t scale = floating_u64_pow(10, digits);
	uint32_t sol = 0;
	for (i = 1; i <= 32; i++) { // -1024 is the maximum for an exponent in double
		sol = sol << 1U;
		shift = ((uint64_t) decimal) << 1U;
		decimal = decimal << 1U;
		if (scale <= shift) {
			sol = sol | 1U;
			decimal -= scale;
		}
	}
	return sol;
}

static void floating_normalize(floating *number)
{
	// Get the position of the first 1 in the binary of the mantissa
	// and change the exponent
	uint32_t i = 0;
	uint32_t found = 0;

	if (!number->mantissa) {
		number->exponent = FLOATING_BIAS;
		return;
	}

	for (i = 0; i <= 63; i++) {
        if (!found && (number->mantissa & FLOATING_LARGEST_BIT) != 0) {
            found = 1;
        } else if (!found) {
            number->exponent = number->exponent - 1;
            number->mantissa = number->mantissa << 1U;
        }
	}
}

void to_floating(uint32_t integer, uint32_t decimal, uint32_t digits, floating *result)
{
	result->mantissa = (((uint64_t) integer) << 32U) | ((uint64_t) floating_decimal_to_binary(decimal, digits));
	result->exponent = FLOATING_BIAS + 31;
	// The first bit must be 1
	floating_normalize(result);
}

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

static struct srh_record *build_srh(json_t *rt_dst_addr, json_t *segments, bool reverse_srh, size_t *srh_record_len, size_t *srh_len)
{
    *srh_record_len = (json_array_size(segments) + 1) * sizeof(struct in6_addr) + sizeof(struct srh_record);
    *srh_len = (json_array_size(segments) + 1) * sizeof(struct in6_addr) + sizeof(struct ipv6_sr_hdr);
    if (json_array_size(segments) == 0) {
        *srh_record_len += sizeof(struct in6_addr);
        *srh_len  += sizeof(struct in6_addr);
    }

    if (json_array_size(segments) > MAX_SEGS_NBR - 1) {
        zlog_warn(zc, "Cannot have more than %d segments (destination included) in an SRH in the eBPF map", MAX_SEGS_NBR);
        return NULL;
    }

    struct srh_record *srh_record = calloc(1, sizeof(struct srh_record));
    if (!srh_record) {
        zlog_warn(zc, "Cannot allocate memory for a new SRH");
        return NULL;
    }
    struct ipv6_sr_hdr *srh = &srh_record->srh;
	srh->type = 4;

	srh->hdrlen = ((json_array_size(segments) + 1) * sizeof(struct in6_addr)) / 8; // We do not count the first 8 bytes
	srh->segments_left = json_array_size(segments);
	srh->first_segment = json_array_size(segments);
    if (json_array_size(segments) == 0) {
        srh->hdrlen += (sizeof(struct in6_addr) / 8);
        srh->segments_left  += 1;
        srh->first_segment  += 1;
    }

    json_t *jseg;
    size_t i;
    struct in6_addr seg;
    json_array_foreach(segments, i, jseg) {
        size_t idx = reverse_srh ? i : json_array_size(segments) - i - 1;

        if (inet_pton(AF_INET6, json_string_value(jseg), &seg) != 1) {
            free(srh);
            zlog_warn(zc, "Cannot parse segments as IPv6 addresses");
            return NULL;
        }
        memcpy(&srh_record->segments[idx + 1], &seg, sizeof(struct in6_addr));
    }
    if (json_array_size(segments) == 0) { // SRHs with only one segment are not correctly parsed => force at least two segments
        if (inet_pton(AF_INET6, json_string_value(rt_dst_addr), &seg) != 1) {
            free(srh);
            zlog_warn(zc, "Cannot parse rt_dst_addr as IPv6 addresses");
            return NULL;
        }
        memcpy(&srh_record->segments[json_array_size(segments) + 1], &seg, sizeof(struct in6_addr));
    }
    // Destination segment is left at 0

    srh_record->is_valid = 1;
	return srh_record;
}

static int remove_segments(json_t *destination, json_t *segments, bool reverse_srh, json_t *rt_dst_addr)
{
    int err = 0;
    size_t srh_record_len;
    size_t srh_len;
    struct in6_addr dest_ip;
    struct hash_dest *hdest = NULL;

    if (cfg.dest_cache) {
        zlog_debug(zc, "SRH removal skipped because never inserted (the hashmap is empty)");
        return 0;
    }

    struct srh_record *srh_record = build_srh(rt_dst_addr, segments, reverse_srh, &srh_record_len, &srh_len);
    if (!srh_record) {
        return -1;
    }

    /* Get destination IP */
    if (inet_pton(AF_INET6, json_string_value(destination), &dest_ip) != 1) {
        zlog_warn(zc, "Cannot parse destination as IPv6 addresses");
        free(srh_record);
        return 0;
    }

    HASH_FIND(hh, cfg.dest_cache, &dest_ip, sizeof(struct in6_addr), hdest);
    if (!hdest) {
        zlog_debug(zc, "SRH removal skipped because destination was never inserted");
        free(srh_record);
        return 0;
    }

    /* Find the SRH id */
    srh_record->srh_id = MAX_SRH_BY_DEST;
    for (int i = 0; i < MAX_SRH_BY_DEST; i++) {
        /* Skip free slot */
        if (!hdest->info.srhs[i].srh.type || !hdest->info.srhs[i].is_valid) {
            continue;
        }
        /* Check that the SRH was not already present */
        if (!memcmp(&hdest->info.srhs[i].srh, srh_record->segments, sizeof(srh_record->segments))) {
            srh_record->srh_id = i; // Overwrite if the tag or other info (like is_valid) is different
        }
    }
    if (srh_record->srh_id == MAX_SRH_BY_DEST) {
        zlog_debug(zc, "SRH removal skipped because SRH was never inserted");
        free(srh_record);
        return 0;
    }

    /* Invalidate the SRH */
    hdest->info.srhs[srh_record->srh_id].is_valid = 0;
    free(srh_record);

    /* Remove it in eBPF map (by updating the dest entry with an invalid srh record) */
    if (bpf_map_update_elem(cfg.dest_map_fd, &dest_ip, &hdest->info, BPF_ANY)) {
        zlog_warn(zc, "SRH couldn't be removed in dst_map !");
        err = -1;
    }
    if (bpf_map_update_elem(cfg.short_dest_map_fd, &dest_ip, &hdest->info, BPF_ANY)) {
        zlog_warn(zc, "SRH couldn't be removed in short_dst_map !");
        err = -1;
    }

    zlog_debug(zc, "SRH removed from the eBPF map");

    return err;
}

/**
 * Creates a new SRH based on a list of segments and insert it in both the program hashmap and the eBPF hashmap
 */
static int insert_segments(json_t *destination, json_t *segments, uint64_t bw, uint64_t delay, bool reverse_srh, json_t *rt_dst_addr)
{
    int err = 0;
    size_t srh_record_len;
    size_t srh_len;
    struct in6_addr dest_ip;
    struct hash_dest *hdest = NULL, *cur_hdest=NULL, *tmp = NULL;
    struct srh_record *srh_record = build_srh(rt_dst_addr, segments, reverse_srh, &srh_record_len, &srh_len);
    if (!srh_record) {
        return -1;
    }
    srh_record->curr_bw = bw;
    srh_record->delay = delay;

    /* Get destination IP */
    if (inet_pton(AF_INET6, json_string_value(destination), &dest_ip) != 1) {
        zlog_warn(zc, "Cannot parse destination as IPv6 addresses");
        goto free_srh;
    }

    /* Create the destination hash if not already present */
    if (cfg.dest_cache) {
        HASH_FIND(hh, cfg.dest_cache, &dest_ip, sizeof(struct in6_addr), hdest);
        if (hdest)
            zlog_debug(zc, "New SRH received for an existing destination");
    }
    if (!hdest) {
        hdest = calloc(1, sizeof(struct hash_dest));
        if (!hdest) {
            zlog_warn(zc, "Cannot allocate memory for hash entry of destination");
            err = -1;
            goto free_srh;
        }
        /* Setup destination hash entry and insert in the hashmap */
        memcpy(&hdest->info.dest, &dest_ip, sizeof(struct in6_addr));
        /* Add weights equal to 1 */
        for (int i = 0; i < MAX_EXPERTS; i++) {
            to_floating(1, 0, 1, &hdest->info.exp4_weights[i]);
        }
        HASH_ADD_KEYPTR(hh, cfg.dest_cache, &hdest->info.dest, sizeof(struct in6_addr), hdest);
    }

    /* Check that the SRH is not present and set the SRH id with a free slot index if any */
    srh_record->srh_id = MAX_SRH_BY_DEST;
    for (int i = 0; i < MAX_SRH_BY_DEST; i++) {
        /* Use the first free slot */
        zlog_debug(zc, "SRH insertion in %u ? Iteration %d - srh_type %u - srh_is_valid %u", srh_record->srh_id, i, hdest->info.srhs[i].srh.type, hdest->info.srhs[i].is_valid);
        zlog_debug(zc, "SRH insertion in %u ? Cond 1 %d", srh_record->srh_id, srh_record->srh_id == MAX_SRH_BY_DEST && (!hdest->info.srhs[i].srh.type || !hdest->info.srhs[i].is_valid));
        if (srh_record->srh_id == MAX_SRH_BY_DEST && (!hdest->info.srhs[i].srh.type || !hdest->info.srhs[i].is_valid)) {
            srh_record->srh_id = i;
        }
        /* The maximum reward is the number of bytes */
        if (hdest->info.max_reward < hdest->info.srhs[i].curr_bw)
            hdest->info.max_reward = hdest->info.srhs[i].curr_bw;
        /* Check that the SRH was not already present and overwrite if this is the case */
        zlog_debug(zc, "SRH insertion in %u ? Cond 2 %d", srh_record->srh_id, !memcmp(&hdest->info.srhs[i].srh, srh_record->segments, sizeof(srh_record->segments)));
        if (!memcmp(&hdest->info.srhs[i].srh, srh_record->segments, sizeof(srh_record->segments))) {
            srh_record->srh_id = i; // Overwrite if the tag or other info (like is_valid) is different
        }
    }
    uint32_t id = srh_record->srh_id;
    if (id < MAX_SRH_BY_DEST) {
        memcpy(&hdest->info.srhs[srh_record->srh_id], srh_record, sizeof(struct srh_record));
    }
    free(srh_record);

    /* Insert it in eBPF map */
    if (id < MAX_SRH_BY_DEST) {
        if (bpf_map_update_elem(cfg.dest_map_fd, &dest_ip, &hdest->info, BPF_ANY)) {
            zlog_warn(zc, "Dest entry couldn't be inserted in eBPF map !");
            return -1;
        }
        if (bpf_map_update_elem(cfg.short_dest_map_fd, &dest_ip, &hdest->info, BPF_ANY)) {
            zlog_warn(zc, "Dest entry couldn't be inserted in short eBPF map !");
            return -1;
        }
        zlog_debug(zc, "SRH inserted in the eBPF map");
    } else {
        zlog_warn(zc, "Not enough room for a new SRH in the map !");
        return -1;
    }
    return 0;

free_srh:
    if (srh_record)
        free(srh_record);
    return err;
}

void destroy_dest_cache()
{
    if (cfg.dest_cache) {
        struct hash_dest *hdest, *tmp;
        HASH_ITER(hh, cfg.dest_cache, hdest, tmp) {
            HASH_DEL(cfg.dest_cache, hdest);
            free(hdest);
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
    json_t *flow = json_loads(path_entry->flow, 0, NULL);
    json_t *rt_dst_addr = NULL;
    json_t *dest_addresses = NULL;
    size_t idx_dest = 0;
    json_t *curr_destination = NULL;

    bool reverse_srh = false;
    if (matching_prefix(prefixes_rt1)) {
        reverse_srh = false;
        rt_dst_addr = json_array_get(flow, 1);
        dest_addresses = prefixes_rt2;
    } else if (matching_prefix(prefixes_rt2)) {
        reverse_srh = true;
        rt_dst_addr = json_array_get(flow, 0);
        dest_addresses = prefixes_rt1;
    } else {
        zlog_debug(zc, "The path is not for this endhost");
        goto free_prefixes;
    }
    zlog_debug(zc, "The path is for this endhost");
    char *s = json_dumps(prefixes, 0);
    zlog_debug(zc, "Paths %s", s);
    free(s);
    s = json_dumps(dest_addresses, 0);
    zlog_debug(zc, "Destinations %s", s);
    free(s);

    json_t *segments = json_loads(path_entry->segments, 0, NULL);
    json_t *curr_segments;
    size_t idx = 0;
    json_array_foreach(segments, idx, curr_segments) {
        json_array_foreach(dest_addresses, idx_dest, curr_destination) {
            json_t *dest_json_str = json_object_get(curr_destination, "address");
            json_t *seg_list = json_object_get(curr_segments, "segs");
            uint64_t bw = (uint64_t) json_integer_value(json_object_get(curr_segments, "bw"));
            uint64_t delay = (uint64_t) json_integer_value(json_object_get(curr_segments, "delay"));
            zlog_debug(zc, "Inserting a segment path for a destination");
            insert_segments(dest_json_str, seg_list, bw, delay, reverse_srh, rt_dst_addr);
        }
    }

    json_decref(segments);
free_prefixes:
    json_decref(prefixes);
    json_decref(flow);
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
    json_t *flow = json_loads(path_entry->flow, 0, NULL);
    json_t *rt_dst_addr = NULL;
    json_t *dest_addresses = NULL;
    size_t idx_dest = 0;
    json_t *curr_destination = NULL;

    bool reverse_srh = false;
    if (matching_prefix(prefixes_rt1)) {
        reverse_srh = false;
        rt_dst_addr = json_array_get(flow, 1);
        dest_addresses = prefixes_rt2;
    } else if (matching_prefix(prefixes_rt2)) {
        reverse_srh = true;
        rt_dst_addr = json_array_get(flow, 0);
        dest_addresses = prefixes_rt1;
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

    json_t *seg_list = NULL;
    uint64_t bw = 0;
    uint64_t delay = 0;

    json_t *old_seg_list = NULL;
    /*uint64_t old_bw = 0;
    uint64_t old_delay = 0;*/

    json_t *dest_json_str = NULL;

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
        if (!found) {
            zlog_debug(zc, "An old SRH was not in the update");
            json_array_foreach(dest_addresses, idx_dest, curr_destination) {
                dest_json_str = json_object_get(curr_destination, "address");
                zlog_debug(zc, "Removing a segment path for a destination");
                old_seg_list = json_object_get(old_segments, "segs");
                remove_segments(dest_json_str, old_seg_list, reverse_srh, rt_dst_addr);
            }
        }
    }

    /* Insert new SRHs */

    json_array_foreach(segments, idx, curr_segments) {
        found = false;
        seg_list = json_object_get(curr_segments, "segs");
        bw = (uint64_t) json_integer_value(json_object_get(curr_segments, "bw"));
        delay = (uint64_t) json_integer_value(json_object_get(curr_segments, "delay"));
        json_array_foreach(old_segments, old_idx, curr_old_segments) {
            old_seg_list = json_object_get(old_segments, "segs");
            //old_bw = (uint64_t) json_integer_value(json_object_get(old_segments, "bw"));
            //old_delay = (uint64_t) json_integer_value(json_object_get(old_segments, "delay"));
            if (same_segments(curr_segments, curr_old_segments)) {
                found = true;
                break;
            }
        }
        if (!found) {
            zlog_debug(zc, "A new SRH is in the update");
            json_array_foreach(dest_addresses, idx_dest, curr_destination) {
                dest_json_str = json_object_get(curr_destination, "address");
                zlog_debug(zc, "Inserting a segment path for a destination");
                insert_segments(dest_json_str, seg_list, bw, delay, reverse_srh, rt_dst_addr);
            }
        }
        // TODO Update here the bandwidth or delay even if same segments were found
    }

    json_decref(segments);
free_prefixes:
    json_decref(prefixes);
    json_decref(flow);
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
