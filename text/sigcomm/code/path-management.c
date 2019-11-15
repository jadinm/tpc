int handle_sockop(struct bpf_sock_ops *skops)
{
	struct five_tuple five_tuple;
	get_five_tuple(&five_tuple, skops);

	struct conn *conn = bpf_map_lookup_elem(&conn_map, &five_tuple);
	if (!conn) { // New connection
		struct connection new_conn;
		memset(new_conn, 0, sizeof(new_conn));
		new_conn.srh = get_best_path(srh_map, &five_tuple.remote);
		bpf_setsockopt(skops, SOL_IPV6, IPV6_RTHDR, new_conn.srh, sizeof(*new_conn.srh));
		init_exponential_backoff(&new_conn);
		bpf_map_update_elem(conn_map, &five_tuple, &new_conn, BPF_ANY);
		*conn = new_conn;
	}

	switch (skops->op) {
		case BPF_SOCK_OPS_STATE_CB:
			if (skops->args[1] == BPF_TCP_CLOSE)
				bpf_map_delete_elem(conn_map, &five_tuple);
			break;
		case BPF_SOCK_OPS_ECN_CE:
			// TCP segment with CWR bit set
			react_to_congestion(five_tuple, conn);
			break;
		case BPF_SOCK_OPS_RTO_CB:
			// Retransmission timer expiration
			react_to_congestion(five_tuple, conn);
			break;
	}
	socks->reply = rv;
	return 0;
}
