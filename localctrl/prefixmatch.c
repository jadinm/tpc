#include <netinet/in.h>

#include <arpa/inet.h>
#include <errno.h>
#include <ifaddrs.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <stdio.h>

static inline bool valid_global_address(struct ifaddrs *ifa)
{
    return ifa->ifa_addr && ifa->ifa_addr->sa_family == AF_INET6
           && !IN6_IS_ADDR_LINKLOCAL(&((struct sockaddr_in6*) ifa->ifa_addr)->sin6_addr)
           && !IN6_IS_ADDR_LOOPBACK(&((struct sockaddr_in6*) ifa->ifa_addr)->sin6_addr);
}

struct in6_addr *get_global_addresses(size_t *nbr_addrs)
{
	struct ifaddrs *ifa, *ifa_tmp;

	if (getifaddrs(&ifa) == -1)
		return NULL;

	/* Get length */
	size_t i;
	ifa_tmp = ifa;
	for (i = 0; ifa_tmp; ifa_tmp = ifa_tmp->ifa_next)
	{
		if (valid_global_address(ifa_tmp))
			i++;
	}

	/* Allocate */
	*nbr_addrs = i;
	struct in6_addr *laddrs = (struct in6_addr *) malloc(sizeof(struct in6_addr) * (*nbr_addrs));
	if (!laddrs)
        goto out;

	/* Fill */
	ifa_tmp = ifa;
	for (i = 0; i < *nbr_addrs; ifa_tmp = ifa_tmp->ifa_next) {

		if (valid_global_address(ifa_tmp)) {
			memcpy(&laddrs[i], &((struct sockaddr_in6*) ifa_tmp->ifa_addr)->sin6_addr, sizeof(struct in6_addr));

            char buf [500];
            inet_ntop(AF_INET6, &laddrs[i], buf, 500);
            i++;
		}
	}

out:
    freeifaddrs(ifa);
	return laddrs;
}

int network_pton(char *src, struct in6_addr *dst, size_t prefix_len)
{
	if (inet_pton(AF_INET6, src, dst) != 1) {
		return -1;
	}

	if (prefix_len > 128)
		return -1;

	return 0;
}

bool address_in_prefix(struct in6_addr *addr, struct in6_addr *prefix, size_t prefixlen)
{
	prefixlen = prefixlen > 128 ? 128 : prefixlen;

	int nbr_bytes = prefixlen / 8;
	if (memcmp(addr, prefix, nbr_bytes))
		return false;

	int nbr_bits = prefixlen % 8;
	uint8_t *addr_ptr = ((uint8_t *) addr) + nbr_bytes;
	uint8_t *prefix_ptr = ((uint8_t *) prefix) + nbr_bytes;
	uint8_t mask = 1 << (8 - nbr_bits); // 2**(8-nbr_bits)
	mask -= 1; // All least significant bits are at 1 (i.e., 2**n - 1)
	mask = ~mask; // The most significant ones are at 1

	return (*addr_ptr & mask) == (*prefix_ptr & mask);
}
