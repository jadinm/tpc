#ifndef PREFIXMATCH_H
#define PREFIXMATCH_H

#include <stdbool.h>
#include <unistd.h>

/**
 * Returns a list of global IPv6 addresses of all interfaces (at most 10)
 */
struct in6_addr *get_global_addresses(size_t *nbr_addrs);

/**
 * Converts a prefix encoded as a string (e.g., "2042::/16")
 * to a structure in6_addr representing the right part of the prefix (e.g., "2042::")
 * and its prefix length (e.g., 16)
 */
int network_pton(char *src, struct in6_addr *dst, size_t prefix_len);

/**
 * Returns true iff the address 'addr' and the 'prefix' share the same 'prefixlen' bits
 */
bool address_in_prefix(struct in6_addr *addr, struct in6_addr *prefix, size_t prefixlen);

#endif