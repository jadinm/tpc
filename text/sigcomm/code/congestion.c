void react_to_congestion() {
	// Wait exponential backoff
	if (current_time - conn->last_move_time < conn->wait_before_move)
		return;
	// Select the path with the highest bandwidth
	for (i = 0; i < MAX_SRH_BY_DEST; i++) {
		srh_entry = &dst_infos->srhs[i];
		current_bw = srh_entry->bw;
		if (current_bw > highest_bw) {
			best_srh = srh_entry->srh;
			highest_bw = current_bw;
		}
	}
	if (best_srh != null) {
		bpf_setsockopt(skops, SOL_IPV6, IPV6_RTHDR, best_srh, sizeof(*best_srh));
		conn->srh = best_srh;
		update_backoff_timers(conn);
	}
}
