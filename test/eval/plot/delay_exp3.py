import os
import re
from collections import OrderedDict
from typing import List

from matplotlib import pyplot as plt
from mininet.log import lg

from eval.bpf_stats import MAX_PATHS_BY_DEST, ShortSnapshot
from eval.db import ShortTCPeBPFExperiment
from eval.plot.utils import plot_time, subplot_time, plot_cdf
from eval.utils import FONTSIZE, LINE_WIDTH, MARKER_SIZE


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

            subplot.step(bins, cdf, marker="." if not hotnet_paper else None, linewidth=LINE_WIDTH,
                         where="post", markersize=MARKER_SIZE, label="ECMP",
                         color=colors["ECMP"])

        # Plot TPC
        cdf = []
        bins = []
        for cdf_dot in exp.abs.first().ab_latency_cdf.all():
            bins.append(cdf_dot.time)
            cdf.append(cdf_dot.percentage_served)

        subplot.step(bins, cdf, marker="." if not hotnet_paper else None, linewidth=LINE_WIDTH,
                     where="post", markersize=MARKER_SIZE, label="TPC",
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
        fig.savefig(os.path.join(output_path, figure_name + ".pdf"), markersize=9, **params)
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
            for idx, weight in enumerate(snap.weights):
                weights.setdefault(idx, []).append((rel_time, weight))

        # Remove not used weights, i.e., weights always set to 1
        for idx in list(weights.keys()):
            if all([1 - 10 ** -9 < w < 1 + 10 ** -9 for _, w in weights[idx]]):
                del weights[idx]

        for id, count in srh_counts.items():
            print("{} - {}".format(id, count))

        plot_cdf(rewards, colors={0: "orangered", 1: "#00B0F0"},
                 markers={0: "o", 1: "s"}, labels={0: "Path 0", 1: "Path 1"},
                 xlabel="Path reward", figure_name=figure_name + ".rewards",
                 output_path=output_path, grid=hotnet_paper)
        plot_time(reward_over_time, labels={0: "Path 0", 1: "Path 1"},
                  colors={0: "orangered", 1: "#00B0F0"},
                  ylabel="Path reward",
                  figure_name=times_figure_name + ".rewards",
                  output_path=output_path)
        plot_time(srh_over_time, labels={0: "Path 0", 1: "Path 1"},
                  colors={0: "orangered", 1: "#00B0F0"},
                  ylabel="Path selection",
                  figure_name=times_figure_name + ".selections",
                  output_path=output_path)
        subplot_time(weights, labels={0: "Path 0", 1: "Path 1", MAX_PATHS_BY_DEST: "stable",
                                      MAX_PATHS_BY_DEST + 1: "unstable"},
                     ylabel="Experts' weights",
                     figure_name=times_figure_name + ".weights",
                     output_path=output_path)

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
