#ifndef SR_ENDHOSTD_H
#define SR_ENDHOSTD_H

#include <linux/seg6.h>

#define _unused __attribute__((unused))

struct hash_sfd {
	int sfd;
	struct ipv6_sr_hdr *srh;
	UT_hash_handle hh;
};

struct config {
	char *zlog_conf_file;
	struct in6_addr server_addr;
	int server_port;
	struct hash_sfd *sockets;
};

#endif /* SR_ENDHOSTD_H */

