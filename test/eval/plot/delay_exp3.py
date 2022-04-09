import json
import os
import re
from collections import OrderedDict
from typing import List

from matplotlib import pyplot as plt
from mininet.log import lg

from eval.bpf_stats import MAX_PATHS_BY_DEST, ShortSnapshot
from eval.db import ShortTCPeBPFExperiment
from eval.plot.utils import plot_time, subplot_time, plot_cdf
from eval.utils import FONTSIZE, LINE_WIDTH, cdf_data



def plot_stability_by_connection(experiments, id, output_dir):
    keys = {}
    for exp in experiments:
        if not exp.ebpf:
            continue
        if any([getattr(exp, key) != value for key, value in id.items()]):
            continue

        topo_base = os.path.basename(exp.topology)
        demands_base = os.path.basename(exp.demands)
        key = "%s@%s@%s" % (topo_base, demands_base, exp.gamma_value)
        if not keys.get(key, False):  # Only once by instance
            keys[key] = True

            # Snapshot changed
            try:
                nbr_changes_by_conn, exp3_srh_id_by_conn = \
                    exp.stability_by_connection()
            except OverflowError:
                print(exp.timestamp)
                continue

            plot_time(exp3_srh_id_by_conn, "Current path",
                      "chosen_path_%s.time" % key, output_dir,
                      ylim={"bottom": 0, "top": 1})


def retrieve_ab_related(single_path_exps: List[ShortTCPeBPFExperiment],
                        ecmp_delay_experiments: List[ShortTCPeBPFExperiment]):
    # Prepare single path experiments
    single_paths = {}
    for exp in single_path_exps:
        topo_base = os.path.basename(exp.topology)
        demands_base = os.path.basename(exp.demands)
        match = re.search(r"(.+)\.path\.(\d+)\.graph", topo_base)
        topo_full_paths = match.group(1) + ".graph"
        path_idx = int(match.group(2))
        key = "%s@%s" % (topo_full_paths, demands_base)
        # We only want the last result
        if path_idx not in single_paths.setdefault(key, {}):
            single_paths.setdefault(key, {})[path_idx] = exp

    ecmp = {}
    for exp in ecmp_delay_experiments:
        topo_base = os.path.basename(exp.topology)
        demands_base = os.path.basename(exp.demands)
        key = "%s@%s" % (topo_base, demands_base)
        # We only want the last result
        if key not in ecmp:
            ecmp[key] = exp

    return single_paths, ecmp


def plot_ab_cdfs(delay_experiments: List[ShortTCPeBPFExperiment],
                 single_path_exps: List[ShortTCPeBPFExperiment],
                 ecmp_delay_experiments: List[ShortTCPeBPFExperiment],
                 output_path, hotnet_paper=False):
    colors = {
        "TPC": "orange",
        "ECMP": "#00B0F0",
        0: "green",
        1: "red"
    }
    single_paths, ecmp = retrieve_ab_related(single_path_exps,
                                             ecmp_delay_experiments)

    done_topos = {}
    for exp in delay_experiments:
        if "paths.delay" not in exp.topology:  # TODO Remove
            continue  # TODO Remove

        topo_base = os.path.basename(exp.topology)
        demands_base = os.path.basename(exp.demands)
        key = "%s@%s@%s" % (topo_base, demands_base, exp.random_strategy)
        if done_topos.get(key):  # Only take the most recent experiment
            continue
        done_topos[key] = True

        fig = plt.figure()
        subplot = fig.add_subplot(111)

        single_path_key = "%s@%s" % (topo_base, demands_base)
        ecmp_key = single_path_key
        figure_name = "ab_completion_time_%s.cdf" % key
        times_figure_name = "ab_completion_time_%s.times" % key
        latencies_figure_name = "ab_completion_time_%s.times.latencies" % key

        # TODO Plot single path delays
        # for path_idx, single_path_exp in \
        #        single_paths.get(single_path_key, {}).items():
        #    cdf = []
        #    bins = []
        #    for cdf_dot in single_path_exp.abs.first().ab_latency_cdf.all():
        #        bins.append(cdf_dot.time)
        #        cdf.append(cdf_dot.percentage_served)

        #    subplot.step(bins, cdf, marker="." if not hotnet_paper else None, linewidth=LINE_WIDTH,
        #                 where="post", markersize=MARKER_SIZE,
        #                 label="Path %d" % path_idx, color=colors.get(path_idx))

        # Plot ECMP
        if ecmp_key in ecmp:
            cdf = []
            bins = []
            for cdf_dot in ecmp[ecmp_key].abs.first().ab_latency_cdf.all():
                bins.append(cdf_dot.time)
                cdf.append(cdf_dot.percentage_served)

            subplot.step(bins, cdf, linewidth=LINE_WIDTH,
                         where="post", label="ECMP",
                         color=colors["ECMP"])

        # Plot TPC
        cdf = []
        bins = []
        for cdf_dot in exp.abs.first().ab_latency_cdf.all():
            bins.append(cdf_dot.time)
            cdf.append(cdf_dot.percentage_served)

        subplot.step(bins, cdf, linewidth=LINE_WIDTH,
                     where="post", label="TPC",
                     color=colors["TPC"])

        subplot.legend(loc="best")
        subplot.set_yticks([0, 25, 50, 75, 100])
        subplot.set_xlabel("Completion time (ms)", fontsize=FONTSIZE)
        subplot.set_ylabel("CDF (\\%)", fontsize=FONTSIZE)
        if hotnet_paper:
            fig.tight_layout()
            subplot.grid()
        subplot.set_xlim(left=0)  # TODO Change right limit
        subplot.set_ylim(bottom=0, top=100)  # TODO Change right limit

        lg.info("Saving figure for plot ab cdfs to path {path}\n"
                .format(path=os.path.join(output_path, figure_name + ".pdf")))

        params = {}
        if not hotnet_paper:
            params = {'bbox_inches': 'tight', 'pad_inches': 0}
        fig.savefig(os.path.join(output_path, figure_name + ".pdf"), **params)
        fig.clf()
        plt.close()

        srh_counts = {}
        rewards = {}  # 50 - srtt / 1000
        reward_over_time = {}
        weights = OrderedDict()
        first_sequence = -1
        start_time = 0
        srh_over_time = {}
        for db_snap in exp.snapshots.all():
            snap = ShortSnapshot.retrieve_from_hex(db_snap.snapshot_hex)
            if first_sequence == -1:
                first_sequence = snap.seq
                start_time = snap.time
            srh_counts.setdefault(snap.last_srh_id_chosen, 0)
            srh_counts[snap.last_srh_id_chosen] += 1
            rewards.setdefault(snap.last_srh_id_chosen, []).append(
                snap.last_reward)

            rel_time = (snap.time - start_time) / 10 ** 9  # in seconds
            srh_over_time.setdefault(snap.last_srh_id_chosen, []).append(
                (rel_time, snap.last_srh_id_chosen))
            reward_over_time.setdefault(snap.last_srh_id_chosen, []).append(
                (rel_time, snap.last_reward))

            # Add the evolution of weights over time
            print(snap.weights)
            for idx, weight in enumerate(snap.weights):
                weights.setdefault(idx, []).append((rel_time, weight))

        # Remove not used weights, i.e., weights always set to 1
        for idx in list(weights.keys()):
            if all([1 - 10 ** -9 < w < 1 + 10 ** -9 for _, w in weights[idx]]):
                del weights[idx]

        for id, count in srh_counts.items():
            print("{} - {}".format(id, count))

        plot_cdf(rewards, colors={0: "orange", 1: "#00B0F0"},
                 markers={}, labels={0: "Path 0", 1: "Path 1"},
                 xlabel="Path reward", figure_name=figure_name + ".rewards",
                 output_path=output_path, grid=hotnet_paper)
        plot_time(reward_over_time, labels={0: "Path 0", 1: "Path 1"},
                  colors={0: "orange", 1: "#00B0F0"},
                  ylabel="Path reward",
                  figure_name=times_figure_name + ".rewards",
                  output_path=output_path, grid=hotnet_paper)
        plot_time(srh_over_time, labels={0: "Path 0", 1: "Path 1"},
                  colors={0: "orange", 1: "#00B0F0"},
                  ylabel="Path selection",
                  figure_name=times_figure_name + ".selections",
                  output_path=output_path, grid=hotnet_paper)
        subplot_time(weights, labels={0: "Path 0", 1: "Path 1", MAX_PATHS_BY_DEST: "stable",
                                      MAX_PATHS_BY_DEST + 1: "unstable"},
                     ylabel="Experts' weights",
                     figure_name=times_figure_name + ".weights",
                     output_path=output_path, grid=hotnet_paper)

        duration_over_time = {"TPC": exp.abs.first().latency_over_time()}
        labels = {"TPC": "TPC", "ECMP": "ECMP"}
        if ecmp_key in ecmp:
            duration_over_time["ECMP"] = \
                ecmp[ecmp_key].abs.first().latency_over_time()
        for path_idx, single_path_exp in \
                single_paths.get(single_path_key, {}).items():
            duration_over_time[path_idx] = \
                single_path_exp.abs.first().latency_over_time()
            labels[path_idx] = "Path %d" % path_idx

        plot_time(duration_over_time, labels=labels,
                  ylabel="Request completion (ms)", colors=colors,
                  figure_name=times_figure_name + ".latencies",
                  output_path=output_path)


def plot_aggregated_ab_cdfs(delay_experiments: List[ShortTCPeBPFExperiment], output_path, hotnet_paper=False,
                            use_cache=False):
    gamma_text = "$\Gamma$" if hotnet_paper else "Γ"  # for latex background, we cannot add the symbol directly

    cache = {}
    cache_path = os.path.expanduser(f"~/plot_aggregated_ab_cdfs.json")
    if os.path.exists(cache_path):
        with open(cache_path) as obj:
            cache = json.load(obj)

    to_aggregate = {}
    if use_cache:
        to_aggregate = {key: list(range(len(value["latencies"]))) for key, value in cache.items()}
    else:
        for exp in delay_experiments:
            if "test_" in exp.topology:  # TODO Remove
                continue  # TODO
            # if not exp.ebpf:  # TODO Remove
            #     continue  # TODO Remove
            if "paths.delays.flap" not in exp.topology:
                continue
            # if "paths.symetric.delays.flap" not in exp.topology:  # TODO Remove
            #    continue  # TODO
            if exp.max_reward_factor != 1:  # TODO
                continue  # TODO
            if exp.gamma_value not in [0.01, 0.1, 0.2]:  # TODO
                continue  # TODO

            topo_base = os.path.basename(exp.topology)
            demands_base = os.path.basename(exp.demands)
            parallel_connections = "2" if "_par_2" in demands_base else ("4" if "_par_4" in demands_base else "1")
            volume = exp.abs.first().volume
            delay_factor = re.findall(r"factor_(\d+)", topo_base)[0]
            gamma = "Random" if not exp.ebpf else f"{gamma_text}={exp.gamma_value}"
            key = f"{gamma}, {parallel_connections} queries in parallel, {volume}kB, {delay_factor} times"
            if len(to_aggregate.get(key, [])) >= 100:  # Only take the most recent experiment
                continue
            print(key, exp.timestamp)
            to_aggregate.setdefault(key, []).append(exp)

    print("Key produced")

    latencies = {}
    failure_time = {}
    weights_over_time = {}
    first_convergence_data = {}
    first_convergence_tries_data = {}
    second_convergence_data = {}
    second_convergence_tries_data = {}
    for key, exp_list in to_aggregate.items():
        # Plot Latencies
        latencies.setdefault(key, [])
        if use_cache:
            latencies[key] = cache.get(key, {}).get("latencies", [])
            print("CACHE ", len(latencies[key]))
        if len(latencies[key]) == 0:
            for exp in exp_list:
                for latency in exp.abs.first().ab_latency:
                    latencies[key].append(latency.latency / 10 ** 3)  # ms
            cache.setdefault(key, {})["latencies"] = latencies[key]
        print(key)
        print(len(latencies[key]))

        for exp in exp_list:
            weights_over_time.setdefault(key, [])
            first_sequence = -1
            start_time = 0
            if use_cache:
                weights_over_time[key] = cache.get(key, {}).get("weights_over_time", [])
            if len(weights_over_time[key]) == 0 and "Random" not in key:  # ECMP has no snapshot
                print("CACHE ", key, len(weights_over_time[key]))
                for db_snap in exp.snapshots.all():
                    snap = ShortSnapshot.retrieve_from_hex(db_snap.snapshot_hex)
                    if first_sequence == -1:
                        first_sequence = snap.seq
                        start_time = snap.time
                    rel_time = (snap.time - start_time) / 10 ** 9  # in seconds
                    weights_over_time[key].append((rel_time, snap.weights))
                cache.setdefault(key, {})["weights_over_time"] = weights_over_time[key]

            failure_time[key] = -1
            if use_cache:
                failure_time[key] = cache.get(key, {}).get("failure_time", -1)
            if failure_time[key] == -1:
                failure_time[key] = int(json.loads(exp.tc_changes)[0][
                                            0]) - start_time / 10 ** 9 if exp.tc_changes else -1  # monotonic clock in seconds
                cache.setdefault(key, {})["failure_time"] = failure_time[key]

        weights_over_time[key].sort()

        print("\tConvergence data inner ", len(exp_list))
        if use_cache:
            first_convergence_data[key] = cache.get(key, {}).get("first_convergence_data", [])
            first_convergence_tries_data[key] = cache.get(key, {}).get("first_convergence_tries_data", [])
            second_convergence_data[key] = cache.get(key, {}).get("second_convergence_data", [])
            second_convergence_tries_data[key] = cache.get(key, {}).get("second_convergence_tries_data", [])
        if len(first_convergence_data.get(key, [])) == 0 and "Random" not in key:
            for _ in exp_list:
                nbr_paths = 2  # TODO Recover from topo ?
                first_convergence = -1
                second_convergence = -1
                convergence_limit = 0.9
                first_convergence_tries = 0
                second_convergence_tries = 0
                for i in range(1, len(weights_over_time[key])):
                    weights = weights_over_time[key][i][1]
                    probs = [x / sum(weights[:nbr_paths]) for x in weights[:nbr_paths]]
                    if first_convergence == -1:
                        if probs[0] > convergence_limit:
                            first_convergence = weights_over_time[key][i][0]
                            # print("1st", first_convergence, probs)  # in seconds
                            if failure_time[key] == -1:
                                break  # No 2nd convergence tracking possible
                        else:
                            first_convergence_tries += 1
                    elif weights_over_time[key][i][0] > failure_time[key]:
                        if probs[1] > convergence_limit:
                            second_convergence = weights_over_time[key][i][0] - failure_time[key]
                            # print("2nd", second_convergence, probs)  # in seconds
                            break  # TODO Handle more convergences ?
                        else:
                            second_convergence_tries += 1
                if first_convergence > 0:
                    first_convergence_data.setdefault(key, []).append(first_convergence)
                    first_convergence_tries_data.setdefault(key, []).append(second_convergence_tries)
                if second_convergence > 0:
                    second_convergence_data.setdefault(key, []).append(second_convergence)
                    second_convergence_tries_data.setdefault(key, []).append(second_convergence_tries)
                # print(first_convergence_tries, second_convergence_tries)

            # Update cache
            cache.setdefault(key, {})["first_convergence_data"] = first_convergence_data.get(key, [])
            cache.setdefault(key, {})["first_convergence_tries_data"] = first_convergence_tries_data.get(key, [])
            cache.setdefault(key, {})["second_convergence_data"] = second_convergence_data.get(key, [])
            cache.setdefault(key, {})["second_convergence_tries_data"] = second_convergence_tries_data.get(key, [])

    print("Data extracted")

    with open(cache_path, "w") as obj:
        json.dump(cache, obj, indent=4)

    print("Data saved")

    all_styles = ["-", "--", ":", "-."]
    groups = {
        "gamma_var_4_conn": lambda x: "4 queries in parallel" in x and "100kB" in x and "10 times" in x,
        "gamma_10_conn_var": lambda x: f"{gamma_text}=0.1" in x and "100kB" in x and "10 times" in x,
        "gamma_var_conn_4_vol_1k_factor_10": lambda x: "4 queries in parallel" in x and "10 times" in x
                                                       and "1kB" in x,
        "gamma_var_conn_4_vol_10k_factor_10": lambda x: "4 queries in parallel" in x and "10 times" in x
                                                        and "10kB" in x,
        "gamma_var_conn_4_vol_100k_factor_10": lambda x: "4 queries in parallel" in x and "10 times" in x
                                                         and "100kB" in x,
        "gamma_var_conn_4_vol_1M_factor_10": lambda x: "4 queries in parallel" in x and "10 times" in x
                                                       and "1000kB" in x,
        "gamma_var_conn_4_vol_10M_factor_10": lambda x: "4 queries in parallel" in x and "10 times" in x
                                                        and "10000kB" in x,
        "gamma_var_conn_4_vol_100k_factor_var": lambda x: "4 queries in parallel" in x and "100kB" in x,
        "gamma_10_conn_4_vol_100k_factor_var": lambda
            x: f"{gamma_text}=0.1" in x and "4 queries in parallel" in x and "100kB" in x,
        "gamma_10_conn_4_vol_var_factor_10": lambda x: f"{gamma_text}=0.1" in x and "10 times" in x
                                                       and "4 queries in parallel" in x and "10000kB" not in x,
    }
    labels = {
        "gamma_var_4_conn": lambda x: x.split(", ")[0],
        "gamma_10_conn_var": lambda x: x.split(", ")[1],
        "gamma_var_conn_4_vol_1k_factor_10": lambda x: x.split(", ")[0] + ", " + x.split(", ")[2],
        "gamma_var_conn_4_vol_10k_factor_10": lambda x: x.split(", ")[0] + ", " + x.split(", ")[2],
        "gamma_var_conn_4_vol_100k_factor_10": lambda x: x.split(", ")[0] + ", " + x.split(", ")[2],
        "gamma_var_conn_4_vol_1M_factor_10": lambda x: x.split(", ")[0] + ", " + x.split(", ")[2],
        "gamma_var_conn_4_vol_10M_factor_10": lambda x: x.split(", ")[0] + ", " + x.split(", ")[2],
        "gamma_var_conn_4_vol_100k_factor_var": lambda x: x.split(", ")[0] + ", " + x.split(", ")[3],
        "gamma_10_conn_4_vol_100k_factor_var": lambda x: x.split(", ")[0] + ", " + x.split(", ")[3],
        "gamma_10_conn_4_vol_var_factor_10": lambda x: x.split(", ")[0] + ", " + x.split(", ")[2],
    }
    figs = {g: plt.figure() for g in groups}
    figs_convergence = {g: plt.figure() for g in groups}
    figs_convergence_2 = {g: plt.figure() for g in groups}
    figs_convergence_tries = {g: plt.figure() for g in groups}
    figs_convergence_tries_2 = {g: plt.figure() for g in groups}
    subplots = {g: fig.add_subplot(111) for g, fig in figs.items()}
    subplots_convergence = {g: fig.add_subplot(111) for g, fig in figs_convergence.items()}
    subplots_convergence_2 = {g: fig.add_subplot(111) for g, fig in figs_convergence_2.items()}
    subplots_convergence_tries = {g: fig.add_subplot(111) for g, fig in figs_convergence_tries.items()}
    subplots_convergence_tries_2 = {g: fig.add_subplot(111) for g, fig in figs_convergence_tries_2.items()}
    subplots_line_style_index = {g: 0 for g, fig in figs.items()}
    subplots_convergence_line_style_index = {g: 0 for g, fig in figs_convergence.items()}
    subplots_convergence_2_line_style_index = {g: 0 for g, fig in figs_convergence_2.items()}
    subplots_convergence_tries_line_style_index = {g: 0 for g, fig in figs_convergence_tries.items()}
    subplots_convergence_tries_2_line_style_index = {g: 0 for g, fig in figs_convergence_tries_2.items()}
    print("\tTODO ", len(to_aggregate.items()))
    for key, exp_list in to_aggregate.items():
        # Plot Latencies
        bins, cdf = cdf_data(latencies[key])
        for group, subplot in subplots.items():
            if groups[group](key):  # Filter experiences
                # TODO Change color
                subplot.step(bins, cdf, linewidth=LINE_WIDTH,
                             linestyle=all_styles[subplots_line_style_index[group] % len(all_styles)],
                             where="post", label=labels[group](key))
                subplots_line_style_index[group] += 1
        # Plot 1st and 2nd convergence times and tries
        for graph_group, \
            graph_subplots, \
            indices in [(first_convergence_data[key], subplots_convergence, subplots_convergence_line_style_index),
                        (second_convergence_data[key], subplots_convergence_2, subplots_convergence_2_line_style_index),
                        (first_convergence_tries_data[key], subplots_convergence_tries,
                         subplots_convergence_tries_line_style_index),
                        (second_convergence_tries_data[key], subplots_convergence_tries_2,
                         subplots_convergence_tries_2_line_style_index)]:
            bins, cdf = cdf_data(graph_group)
            for group, subplot in graph_subplots.items():
                if groups[group](key) and bins is not None:  # Filter experiences and ECMP experiments
                    # TODO Change color
                    subplot.step(bins, cdf, linewidth=LINE_WIDTH,
                                 linestyle=all_styles[indices[group] % len(all_styles)],
                                 where="post", label=labels[group](key))
                    indices[group] += 1

    print("Data in plots")

    xlabels = ["Completion time (ms)", "Initial convergence time (s)", "Event convergence time (s)",
               "Path changes before initial convergence", "Path changes before event convergence"]
    for i, subplot_list in enumerate([subplots, subplots_convergence, subplots_convergence_2,
                                      subplots_convergence_tries, subplots_convergence_tries_2]):
        for group, subplot in subplot_list.items():
            subplot.legend(loc="best")
            subplot.set_ylabel("CDF", fontsize=FONTSIZE)
            # TODO subplot.set_yticks([0, 0.25, 0.50, 0.75, 1])
            subplot.set_xlabel(xlabels[i], fontsize=FONTSIZE)
            if hotnet_paper:
                subplot.grid()
            subplot.set_xlim(left=0)  # TODO Change right limit
            subplot.set_ylim(bottom=0, top=1)

    name = ["latency", "1st_convergence", "2nd_convergence", "1st_convergence_tries", "2nd_convergence_tries"]
    for i, fig_list in enumerate([figs, figs_convergence, figs_convergence_2, figs_convergence_tries,
                                  figs_convergence_tries_2]):
        for group, fig in fig_list.items():
            figure_name = f"ab_{name[i]}_{group}_various_conditions"
            lg.info("Saving figure for plot ab cdfs to path {path}\n"
                    .format(path=os.path.join(output_path, figure_name + ".pdf")))

            params = {}
            if not hotnet_paper:
                params = {'bbox_inches': 'tight', 'pad_inches': 0}
            else:
                fig.tight_layout()
            fig.savefig(os.path.join(output_path, figure_name + ".pdf"), **params)
            fig.clf()
    plt.close()
