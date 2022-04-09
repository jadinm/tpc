import json
import os
from typing import List

import numpy as np

from eval.bpf_stats import FlowBenderSnapshot, Snapshot
from eval.db import TCPeBPFExperiment
from eval.plot.utils import plot_time, plot_cdf


def plot_non_aggregated_flowbender_failure(flowbender_experiments: List[TCPeBPFExperiment], output_path,
                                           hotnet_paper=False):
    colors = {
        "TPC": "orange",
    }

    done_topos = {}
    for exp in flowbender_experiments:
        if exp.random_strategy != "flowbender":
            continue
        if "paths.light" not in exp.topology:
            continue  # XXX We only consider failure plots here

        topo_folder = os.path.basename(os.path.dirname(exp.topology))
        topo_base = os.path.basename(exp.topology)
        demands_base = os.path.basename(exp.demands)
        key = "%s@%s@%s@%s" % (topo_folder, topo_base, demands_base, exp.random_strategy)
        if done_topos.get(key):  # Only take the most recent experiment
            continue
        done_topos[key] = True

        times_figure_name = "iperf_throughput_%s.times" % key

        srh_counts = {}
        first_sequence = -1
        start_time = 0
        srh_over_time = {}
        for db_snap in exp.snapshots.all():
            snap = FlowBenderSnapshot.retrieve_from_hex(db_snap.snapshot_hex)
            if first_sequence == -1:
                first_sequence = snap.seq
                start_time = snap.time
            srh_counts.setdefault(snap.srh_id, 0)
            srh_counts[snap.srh_id] += 1

            rel_time = (snap.time - start_time) / 10 ** 9  # in seconds
            srh_over_time.setdefault(snap.srh_id, []).append((rel_time, snap.srh_id))

        for id, count in srh_counts.items():
            print("{} - {}".format(id, count))

        plot_time(srh_over_time, ylabel="Path selection",
                  figure_name=times_figure_name + ".selections",
                  output_path=output_path, grid=True,
                  hotnet_paper=hotnet_paper)

        throughput = {"TPC": exp.iperfs.first().connections.first().throughput_over_time()}
        print(throughput)
        print(exp.iperfs.first().connections.first().max_volume)
        print(exp.iperfs.first().connections.first().bw_samples.count())
        plot_time(throughput, ylabel="Request completion (ms)", colors=colors,
                  figure_name=times_figure_name + ".throughput",
                  output_path=output_path, grid=True,
                  hotnet_paper=hotnet_paper)


def plot_flowbender_failure(flowbender_experiments: List[TCPeBPFExperiment],
                            output_path: str, timer_based: bool = False,
                            hotnet_paper=False):
    counter = 100  # Only take the 100 most recent experiment

    receiver_recovery = "Receiver recovery"
    sender_recovery = "Sender recovery"

    exp_by_key = {}
    strategy = ""
    for exp in flowbender_experiments:
        if exp.random_strategy != "flowbender" and not timer_based or \
                exp.random_strategy != "flowbender_timer" and timer_based:
            continue
        if "test_" in exp.topology:
            continue
        if "paths.light" not in exp.topology or exp.tc_changes is None:
            continue  # XXX We only consider failure plots here
        if "paths.light.ecmp.multiple.flows" in exp.demands and "_par_5." not in exp.demands \
                and "_par_10." not in exp.demands and "_par_20." not in exp.demands:
            continue  # 100 flows is too complicated to emulate

        tc_changes = json.loads(exp.tc_changes)
        if len(tc_changes) == 0:
            continue  # We need something to be broken to make it work

        topo_folder = os.path.basename(os.path.dirname(exp.topology))
        topo_base = os.path.basename(exp.topology)
        demands_base = os.path.basename(exp.demands)
        key = "%s@%s@%s@%s" % (topo_folder, topo_base, demands_base, exp.random_strategy)
        strategy = exp.random_strategy
        if key not in exp_by_key or len(exp_by_key[key]) < counter:
            exp_by_key.setdefault(key, []).append(exp)
        else:
            continue

    data_by_key = {}
    for key, exp_list in exp_by_key.items():
        print("Handling", key, "with", len(exp_list), "experiments")
        receiver_reaction_times: List[float] = []  # XXX Only tackle one failure
        sender_reaction_times: List[float] = []  # XXX Only tackle one failure

        for exp in exp_list:  # Multiple runs of the same setup
            changes = json.loads(exp.tc_changes)
            failure_time = int(changes[0][0] * 10 ** 9)  # monotonic clock
            # print(failure_time)

            for k, snaps in exp.snapshot_by_connection().items():  # For each side of a connection
                # XXX Careful if the failure is too close from the start of the connection,
                # snapshot of start of connection and change of path, might be reverted
                # This would cause the script to skip the change path snapshot
                snaps.sort()
                start_path = -1
                stable_reaction_time = -1  # The last change made after the failure
                operation = None
                # print(k)
                for snap in snaps:
                    # Retrieve the last path change time
                    if start_path == -1:
                        start_path = snap.srh_id
                    elif start_path != snap.srh_id and failure_time < snap.time and \
                            (not snap.operation or
                             (snap.operation == Snapshot.RTO or snap.operation == Snapshot.DUPACK)):
                        # Reaction after one failure
                        # XXX Adapt for multiple failures in a single connection
                        stable_reaction_time = (snap.time - failure_time) / 10 ** 9  # s
                        operation = snap.operation
                        # print(f"One recover after {stable_reaction_time} because of {operation}")

                # One entry by data connection in each run
                if operation == Snapshot.RTO:
                    sender_reaction_times.append(stable_reaction_time)
                elif operation == Snapshot.DUPACK:
                    receiver_reaction_times.append(stable_reaction_time)

        data = {}
        if len(sender_reaction_times):
            data[sender_recovery] = sender_reaction_times
        if len(receiver_reaction_times):
            data[receiver_recovery] = receiver_reaction_times
        print(sender_reaction_times)
        print(len(sender_reaction_times), "data for a means of", np.mean(sender_reaction_times),
              "and a median of", np.median(sender_reaction_times))
        print(receiver_reaction_times)
        print(len(receiver_reaction_times), "data for a means of", np.mean(receiver_reaction_times),
              "and a median of", np.median(receiver_reaction_times))
        if len(sender_reaction_times) == 0 and len(receiver_reaction_times) == 0:
            continue
        data_by_key[key] = data

    print("DATA")

    # Actual CDF plot of stable_reaction_times
    base_experience_key = "paths.light.ecmp@path_step_2_access_2.ecmp.graph@path_step_2_access_2.ecmp.flows@" + strategy
    if base_experience_key in data_by_key:
        times_figure_name = "iperf_reaction_simple_%s_%s.cdf" \
                            % ("flowbender" if not timer_based else "flowbender_timer", base_experience_key)
        plot_cdf({sender_recovery: data_by_key[base_experience_key][sender_recovery],
                  receiver_recovery: data_by_key[base_experience_key][receiver_recovery]},
                 {receiver_recovery: "orange", sender_recovery: "#00B0F0"},
                 {},
                 {receiver_recovery: receiver_recovery, sender_recovery: sender_recovery},
                 "Reaction time to failure (s)",
                 times_figure_name, output_path, grid=True,
                 linestyles={receiver_recovery: "-", sender_recovery: "--"},
                 hotnet_paper=hotnet_paper)

    # Different delay together
    delay_20_experience = "paths.light.ecmp.different.delay@path_step_2_access_2.ecmp.20.graph@" \
                          "path_step_2_access_2.ecmp.flows@" + strategy
    delay_40_experience = "paths.light.ecmp.different.delay@path_step_2_access_2.ecmp.40.graph@" \
                          "path_step_2_access_2.ecmp.flows@" + strategy

    if base_experience_key in data_by_key and delay_20_experience in data_by_key and delay_40_experience in data_by_key:
        rtt_base = "RTT 6ms"
        rtt_medium = "RTT 44ms"
        rtt_large = "RTT 84ms"
        filtered_data = {
            rtt_base: data_by_key[base_experience_key][receiver_recovery],
            rtt_medium: data_by_key[delay_20_experience][receiver_recovery],
            rtt_large: data_by_key[delay_40_experience][receiver_recovery],
        }
        times_figure_name = "iperf_reaction_%s_delays.cdf" % ("flowbender" if not timer_based else "flowbender_timer")
        plot_cdf(filtered_data, {rtt_base: "orange", rtt_medium: "#00B0F0", rtt_large: "green"},
                 {},
                 {rtt_base: rtt_base, rtt_medium: rtt_medium, rtt_large: rtt_large},
                 "Reaction time to failure (s)",
                 times_figure_name, output_path,
                 xlim_max=3, grid=True,
                 linestyles={rtt_base: "-", rtt_medium: "--", rtt_large: "-."},
                 hotnet_paper=hotnet_paper)  # s (to remove outliers)

    # Asymmetrical together + difference with symmetric full
    sender_only_experience = "paths.light.ecmp.asymetrical@path_step_2_access_2.ecmp.sender.graph@" \
                             "path_step_2_access_2.ecmp.flows@" + strategy
    receiver_only_experience = "paths.light.ecmp.asymetrical@path_step_2_access_2.ecmp.receiver.graph@" \
                               "path_step_2_access_2.ecmp.flows@" + strategy

    if base_experience_key in data_by_key and sender_only_experience in data_by_key \
            and receiver_only_experience in data_by_key:
        symmetric = "Symmetric failure"
        sender_only = "Sender path failure"
        receiver_only = "Receiver path failure"
        filtered_data = {
            symmetric: data_by_key[base_experience_key][receiver_recovery],
            sender_only: data_by_key[sender_only_experience][sender_recovery],
            receiver_only: data_by_key[receiver_only_experience][receiver_recovery],
        }
        times_figure_name = "iperf_reaction_%s_asymetrical.cdf" \
                            % ("flowbender" if not timer_based else "flowbender_timer")
        plot_cdf(filtered_data, {symmetric: "orange", sender_only: "#00B0F0", receiver_only: "green"},
                 {},
                 {symmetric: symmetric, sender_only: sender_only, receiver_only: receiver_only},
                 "Reaction time to failure (s)",
                 times_figure_name, output_path, grid=True,
                 linestyles={symmetric: "-", sender_only: "--", receiver_only: "-."},
                 hotnet_paper=hotnet_paper)

    # More than one path
    three_paths_experience = "paths.light.ecmp.more.paths@path_step_3_access_3.ecmp.graph@" \
                             "path_step_3_access_3.ecmp.flows@" + strategy

    if base_experience_key in data_by_key and three_paths_experience in data_by_key:
        two_paths = "1 failed paths over 2 available"
        three_paths = "2 failed paths over 3 available"
        filtered_data = {
            two_paths: data_by_key[base_experience_key][receiver_recovery],
            three_paths: data_by_key[three_paths_experience][receiver_recovery]
        }
        times_figure_name = "iperf_reaction_%s_more_paths.cdf" \
                            % ("flowbender" if not timer_based else "flowbender_timer")
        plot_cdf(filtered_data, {two_paths: "orange", three_paths: "#00B0F0"},
                 {},
                 {two_paths: two_paths, three_paths: three_paths},
                 "Reaction time to failure (s)",
                 times_figure_name, output_path, grid=True,
                 linestyles={two_paths: "-", three_paths: "--"},
                 hotnet_paper=hotnet_paper)

    # More than one connection
    five_connections_experience = "paths.light.ecmp.multiple.flows@path_step_2_access_2.ecmp.graph@" \
                                  "path_step_2_access_2_par_5.ecmp.flows@" + strategy
    ten_connections_experience = "paths.light.ecmp.multiple.flows@path_step_2_access_2.ecmp.graph@" \
                                 "path_step_2_access_2_par_10.ecmp.flows@" + strategy
    twenty_connections_experience = "paths.light.ecmp.multiple.flows@path_step_2_access_2.ecmp.graph@" \
                                    "path_step_2_access_2_par_20.ecmp.flows@" + strategy

    if base_experience_key in data_by_key and five_connections_experience in data_by_key \
            and ten_connections_experience in data_by_key and twenty_connections_experience in data_by_key:
        one_conn = "1 flow"
        five_conns = "5 flows"
        ten_conns = "10 flows"
        twenty_conns = "20 flows"
        filtered_data = {
            one_conn: data_by_key[base_experience_key][receiver_recovery],
            five_conns: data_by_key[five_connections_experience][receiver_recovery],
            ten_conns: data_by_key[ten_connections_experience][receiver_recovery],
            twenty_conns: data_by_key[twenty_connections_experience][receiver_recovery]
        }
        times_figure_name = "iperf_reaction_%s_multiple_connections.cdf" \
                            % ("flowbender" if not timer_based else "flowbender_timer")
        plot_cdf(filtered_data, {one_conn: "orange", five_conns: "#00B0F0", ten_conns: "green",
                                 twenty_conns: "purple"},
                 {},
                 {one_conn: one_conn, five_conns: five_conns, ten_conns: ten_conns, twenty_conns: twenty_conns},
                 "Reaction time to failure (s)",
                 times_figure_name, output_path, grid=True,
                 linestyles={one_conn: "-", five_conns: "--", ten_conns: "-.", twenty_conns: ":"},
                 hotnet_paper=hotnet_paper)

    print(list(data_by_key.keys()))
