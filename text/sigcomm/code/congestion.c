void react_to_congestion() {
	// Wait exponential backoff
	if (current_time - conn->last_move_time < conn->wait_before_move)
		return;
	// We compute the reward and update EXP3 weight
	theReward = reward(choice, t);
	estimatedReward = 1.0 * theReward / probabilityDistribution[current_path];
	weights[current_path] *= math.exp(estimatedReward * gamma / numActions); # important that we use estimated reward here!
	// Select the path with EXP3
	probabilityDistribution = distr(weights, gamma);
	best_srh = draw(probabilityDistribution);
	// Set the SRH
	bpf_setsockopt(skops, SOL_IPV6, IPV6_RTHDR, best_srh, sizeof(*best_srh));
}

void distr(weights, gamma) {
	return [(1.0 - GAMMA) * (w / sum(weights)) + (GAMMA / len(weights)) for w in weights]
}
