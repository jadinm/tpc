import argparse
import datetime
import os
from typing import List

import matplotlib.pyplot as plt
import numpy as np
from mininet.log import LEVELS, lg

from eval.bpf_stats import ShortSnapshot
from eval.db import get_connection, TCPeBPFExperiment, ShortTCPeBPFExperiment
from eval.utils import FONTSIZE, LINE_WIDTH, MARKER_SIZE, cdf_data, \
    AB_MEASUREMENT_TIME, MEASUREMENT_TIME
from explore_data import explore_maxflow_json_files

script_dir = os.path.dirname(os.path.abspath(__file__))


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('--log', choices=LEVELS.keys(), default='info',
                        help='The level of details in the logs.')
    parser.add_argument('--out-dir', help='Output directory root',
                        default='/root/graphs-ebpf/%s' % datetime.datetime.now().strftime('%Y-%m-%d_%H-%M-%S'))
    parser.add_argument('--srmip-dir',
                        help='Source directory root all sr-mip optimization',
                        default="/root/maxflow-out")
    return parser.parse_args()


def bw_ebpf_or_no_ebpf_by_topo(topo_keys, output_path):

    colors = {
        False: "#00B0F0",  # Blue
        True: "orangered",
        "srmip": "#009B55"  # Green
    }
    markers = {
        False: "s",
        True: "o"
    }
    labels = {
        False: "No eBPF",
        True: "eBPF"
    }

    cdf_data = {
        True: [],
        False: []
    }
    for topo, demands in topo_keys:
        topo_base = os.path.basename(topo)
        demands_base = os.path.basename(demands)

        figure_name = "bw_ebpf_or_no_ebpf_by_topo" \
                      "_{topo}_{demands}"\
            .format(topo=topo_base, demands=demands_base)
        fig = plt.figure()
        subplot = fig.add_subplot(111)

        for zorder, ebpf in enumerate([False, True]):

            id = {
                "valid": True, "failed": False, "topology": topo,
                "demands": demands, "ebpf": ebpf, "congestion_control": "cubic",
                "gamma_value": 0.5, "random_strategy": "exp3"
            }
            experiment = db.query(TCPeBPFExperiment).filter_by(
                **id).order_by(TCPeBPFExperiment.timestamp.desc()).first()
            if experiment is None:
                continue
            cdf_data[ebpf].extend(experiment.bw_by_connection(db))

            times, bw = experiment.bw_sum_through_time(db)
            subplot.step(times, [b / 10**6 for b in bw],
                         color=colors[ebpf],
                         marker=markers[ebpf], linewidth=LINE_WIDTH,
                         where="post", markersize=MARKER_SIZE,
                         zorder=zorder, label=labels[ebpf])

        subplot.set_xlabel("Time (s)", fontsize=FONTSIZE)
        subplot.set_ylabel("Bandwidth (Mbps)", fontsize=FONTSIZE)
        subplot.set_title("Bandwidth for {topo} - {demand}"
                          .format(topo=topo_base, demand=demands_base))

        # Add line for max value of maxflow if any
        objective = optim_bw_data.get(topo_base, {})\
            .get(demands_base, {}).get(6, None)  # TODO Change 6 by maxseg
        if objective is not None:
            subplot.hlines(objective, 0, 100, colors=colors["srmip"],  # Objective values are in kbps
                           linestyles="solid", label="optimum")
        else:
            lg.error("No optimum computation found for '{topo}' - '{demands}'\n"
                     .format(topo=topo_base, demands=demands_base))

        lg.info("Saving figure for bandwidth for '{topo}' demand '{demands}'\n"
                .format(topo=topo_base, demands=demands_base,
                        path=os.path.join(output_path,
                                          figure_name + ".pdf")))
        subplot.set_ylim(bottom=0)
        subplot.set_xlim(left=1, right=MEASUREMENT_TIME)
        subplot.legend(loc="best")
        fig.savefig(os.path.join(output_path, figure_name + ".pdf"),
                    bbox_inches='tight', pad_inches=0, markersize=9)
        fig.clf()
        plt.close()

        figure_name = "bw_fairness_{topo}_{demands}" \
            .format(name=figure_name, topo=topo_base, demands=demands_base)
        fairness_cdf_plot(output_path, [cdf_data[True], cdf_data[False]],
                          title="", legends=["TCPPathChanger", "ECMP"],
                          colors=[colors[True], colors[False]],
                          markers=[markers[True], markers[False]],
                          figure_name=figure_name)


def fairness_cdf_plot(output_path, data_vectors: List[List[float]],
                      title: str, legends: List[str], colors: List[str],
                      markers: List[str], figure_name,
                      xlabel="Mean bandwidth (Mbps)", ylabel="CDF"):
    fig = plt.figure()
    subplot = fig.add_subplot(111)

    min_value = np.inf
    max_value = -np.inf
    for i, vector in enumerate(data_vectors):
        # Get mean of each connection, then cdf
        mean_data = [x / 10**6 for x in vector]
        if len(mean_data) == 0:
            continue
        bin_edges, cdf = cdf_data(mean_data)

        min_value = min(bin_edges[1:] + [min_value])
        max_value = max(bin_edges[1:] + [max_value])

        subplot.step(bin_edges + [max_value * 10 ** 7], cdf + [cdf[-1]],
                     color=colors[i], marker=markers[i], label=legends[i],
                     linewidth=LINE_WIDTH, where="post", markersize=MARKER_SIZE)

    subplot.set_xlabel(xlabel, fontsize=FONTSIZE)
    subplot.set_ylabel(ylabel, fontsize=FONTSIZE)
    subplot.set_title(title)

    if max_value <= min_value:
        xdiff = 0.0
    else:
        xdiff = (max_value - min_value) * 0.1

    xlim_min = min(0.0, min_value - xdiff)
    xlim_max = max_value + xdiff
    if xlim_min != xlim_max:  # To avoid being too near of 0
        subplot.set_xlim(left=xlim_min, right=xlim_max)
    subplot.set_ylim(bottom=0, top=1)

    subplot.legend(loc="best")
    out_path = os.path.join(output_path, figure_name + ".cdf.pdf")
    fig.savefig(out_path, bbox_inches='tight', pad_inches=0, markersize=9)
    lg.info("Saving fairness figure {}\n".format(out_path))
    fig.clf()
    plt.close()


def bw_param_influence_by_topo(topo_keys, param_name="congestion_control"):
    colors = [
        "orangered",
        "blue",
        "green",
        "black",
        "yellow"
    ]
    markers = [
        "o",
        ".",
        "^",
        "v"
    ]

    for topo, demands in topo_keys:
        topo_base = os.path.basename(topo)
        demands_base = os.path.basename(demands)

        params = []
        db_query = db.query(getattr(TCPeBPFExperiment, param_name)) \
            .filter_by(valid=True, failed=False, topology=topo,
                       demands=demands).distinct()
        for row in db_query:
            params.append(getattr(row, param_name))

        figure_name = "bw_{param_name}_by_topo_{topo}_{demands}" \
            .format(topo=topo_base, demands=demands_base, param_name=param_name)
        fig = plt.figure()
        subplot = fig.add_subplot(111)

        i = 0
        cdf_data = [[] for i in range(len(params) + 1)]
        labels = ["NO LABEL" for i in range(len(params) + 1)]
        for param in params:
            i += 1

            id = {
                "valid": True, "failed": False, "topology": topo,
                "demands": demands, param_name: param, "ebpf": True
            }
            experiment = db.query(TCPeBPFExperiment).filter_by(
                **id).order_by(TCPeBPFExperiment.timestamp.desc()).first()
            cdf_data[i - 1].extend(experiment.bw_by_connection(db))

            times, bw = experiment.bw_sum_through_time(db)
            subplot.step(times, [b / 10**6 for b in bw], color=colors[i - 1],
                         marker=markers[i - 1], linewidth=LINE_WIDTH,
                         where="post", markersize=MARKER_SIZE,
                         zorder=i,
                         label="{} {}".format(param_name, param))
            labels[i - 1] = "{} {}".format(param_name, param)

            if i == 1:  # Add no ebpf
                id["ebpf"] = False
                del id[param_name]
                experiment = db.query(TCPeBPFExperiment).filter_by(
                    **id).order_by(TCPeBPFExperiment.timestamp.desc()).first()
                if experiment is not None:
                    cdf_data[-1].extend(experiment.bw_by_connection(db))

                    times, bw = experiment.bw_sum_through_time(db)
                    subplot.step(times, [b / 10**6 for b in bw],
                                 color="#00B0F0", marker="s",
                                 linewidth=LINE_WIDTH, where="post",
                                 markersize=MARKER_SIZE, zorder=i,
                                 label="No eBPF")
                    labels[-1] = "ECMP"

        subplot.set_xlabel("Time (s)", fontsize=FONTSIZE)
        subplot.set_ylabel("Bandwidth (Mbps)", fontsize=FONTSIZE)
        subplot.set_title("Bandwidth for {topo} - {demand}"
                          .format(topo=topo_base, demand=demands_base))

        # Add line for max value of maxflow if any
        objective = optim_bw_data.get(topo_base, {}) \
            .get(demands_base, {}).get(6, None)  # TODO Change 6 by maxseg
        if objective is not None:
            subplot.hlines(objective, 0, 100, colors="#009B55",
                           # Objective values are in kbps
                           linestyles="solid", label="optimum")
        else:
            lg.error("No optimum computation found for '{topo}'"
                     " - '{demands}'\n".format(topo=topo_base,
                                               demands=demands_base))

        lg.info("Saving figure for {param_name}s for '{topo}' demand "
                "'{demands}' to {path}\n"
                .format(param_name=param_name, topo=topo_base,
                        demands=demands_base,
                        path=os.path.join(args.out_dir,
                                          figure_name + ".pdf")))
        subplot.set_ylim(bottom=0)
        subplot.set_xlim(left=1, right=MEASUREMENT_TIME)
        subplot.legend(loc="best")
        fig.savefig(os.path.join(args.out_dir, figure_name + ".pdf"),
                    bbox_inches='tight', pad_inches=0, markersize=9)
        plt.clf()
        plt.close(fig)

        # Draw CDF of fairness comparison
        if len(cdf_data[0]) == 0:
            continue

        figure_name = "bw_fairness_{param_name}_{topo}_{demands}" \
            .format(param_name=param_name, topo=topo_base, demands=demands_base)
        fairness_cdf_plot(args.out_dir, cdf_data,
                          title="", legends=labels,
                          colors=colors + ["#00B0F0"],
                          markers=markers + ["s"],
                          figure_name=figure_name)


def bw_ebpf_or_no_ebpf_aggregate(topo_keys, output_path, max_history=8):
    colors = {
        False: "#00B0F0",  # Blue
        True: "orangered",
        "srmip": "#009B55"  # Green
    }
    markers = {
        False: "s",
        True: "o"
    }
    labels = {
        False: "No eBPF",
        True: "eBPF"
    }

    bw_diff = {True: [], False: []}
    bw_diff_stdv = {True: [], False: []}
    fairness = {True: [], False: []}
    fairness_stdv = {True: [], False: []}
    print("HERE 2")
    for topo, demands in topo_keys:
        topo_base = os.path.basename(topo)
        demands_base = os.path.basename(demands)
        print("HERE 2.1 %s@%s" % (topo_base, demands_base))

        optim_bw = optim_bw_data.get(topo_base, {}) \
            .get(demands_base, {}).get(6, None)  # TODO Change 6 by maxseg
        if optim_bw is None:
            continue

        topo_diffs = {False: [], True: []}
        topo_fairness = {False: [], True: []}
        for ebpf in [False, True]:
            print("param %s" % ebpf)
            id = {
                "valid": True, "failed": False, "topology": topo,
                "demands": demands, "ebpf": ebpf, "congestion_control": "cubic",
                "gamma_value": 0.5, "random_strategy": "exp3"
            }
            experiments = db.query(TCPeBPFExperiment).filter_by(
                **id).order_by(TCPeBPFExperiment.timestamp.desc())
            if experiments is None:
                continue
            for i, experiment in enumerate(experiments):
                if i >= max_history:
                    break
                print("\t%s" % experiment.id)
                topo_diffs[ebpf].append(experiment.bw_mean_sum(db) / 10**6 /
                                        optim_bw)
                topo_fairness[ebpf].append(experiment.jain_fairness(db))

        if len(topo_diffs[True]) >= max_history \
                and len(topo_diffs[False]) >= max_history:
            print("HERE 2.2")
            # We only use the topology if all parameters were tested equally
            bw_diff[True].append(np.mean(topo_diffs[True]))
            bw_diff[False].append(np.mean(topo_diffs[False]))
            bw_diff_stdv[True].append(np.std(topo_diffs[True]))
            bw_diff_stdv[False].append(np.std(topo_diffs[False]))
        else:
            print(len(topo_diffs[True]))
            print(len(topo_diffs[False]))
        if len(topo_fairness[True]) >= max_history \
                and len(topo_fairness[False]) >= max_history:
            # We only use the topology if all parameters were tested equally
            fairness[True].append(np.mean(topo_fairness[True]))
            fairness[False].append(np.mean(topo_fairness[False]))
            fairness_stdv[True].append(np.std(topo_fairness[True]))
            fairness_stdv[False].append(np.std(topo_fairness[False]))

    # Build graph of mean bw_diff
    plot_cdf(bw_diff, colors, markers, labels, "Network usage (%)",
             "mean_network_usage.cdf", output_path)

    # Build graph of std bw_diff
    plot_cdf(bw_diff_stdv, colors, markers, labels, "Stdv Network usage (%)",
             "stdv_network_usage.cdf", output_path)

    # Build graph of mean fairness
    plot_cdf(fairness, colors, markers, labels, "Mean Jain Fairness",
             "mean_fairness.cdf", output_path)

    # Build graph of std fairness
    plot_cdf(fairness_stdv, colors, markers, labels, "Stdv Jain Fairness",
             "stdv_fairness.cdf", output_path)


def bw_param_influence_aggregate(experiments, param_name, id, colors,
                                 markers, labels, output_path, max_history=8):
    bw_diff = {}
    bw_diff_stdv = {}
    fairness = {}
    fairness_stdv = {}

    # Get all param values
    print("HERE 1")
    param_experiments = {}
    optim_data = {}
    for exp in experiments:
        topo_base = os.path.basename(exp.topology)
        demands_base = os.path.basename(exp.demands)
        key = "%s@%s" % (topo_base, demands_base)
        optim_data[key] = optim_bw_data.get(topo_base, {}) \
            .get(demands_base, {}).get(6, None)  # TODO Change 6 by maxseg
        if optim_data[key] is None:
            continue
        if any([getattr(exp, key) != value for key, value in id.items()]):
            continue

        param_experiments.setdefault(key, {})
        if exp.ebpf:
            param_value = getattr(exp, param_name)
            param_experiments[key].setdefault(param_value, [])
            if len(param_experiments[key][param_value]) < max_history:
                param_experiments[key][param_value].append(exp)
        else:
            param_experiments[key].setdefault("ECMP", [])
            if len(param_experiments[key]["ECMP"]) < max_history:
                param_experiments[key]["ECMP"].append(exp)

    print("HERE 2")
    for key, values in param_experiments.items():
        print("HERE 2.1 %s" % key)
        topo_diffs = {}
        topo_fairness = {}
        for param_value, exps in values.items():
            print("param %s" % param_value)
            for exp in exps:
                print("\t%s" % exp.id)
                topo_diffs.setdefault(param_value, []) \
                    .append(exp.bw_mean_sum(db) / 10 ** 6 / optim_data[key])
                topo_fairness.setdefault(param_value, []) \
                    .append(exp.jain_fairness(db))

        if all([len(topo_diffs[param_value]) == max_history
                for param_value in values.keys()]):
            print("HERE 2.2")
            # We only use the topology if all parameters were tested equally
            for param_value in values.keys():
                bw_diff.setdefault(param_value, []) \
                    .append(np.mean(topo_diffs[param_value]))
                bw_diff_stdv.setdefault(param_value, []) \
                    .append(np.std(topo_diffs[param_value]))
                fairness.setdefault(param_value, []) \
                    .append(np.mean(topo_fairness[param_value]))
                fairness_stdv.setdefault(param_value, []) \
                    .append(np.std(topo_fairness[param_value]))
        else:
            print("Not enough data for param %s in %s" % (param_name, key))
    print("HERE 3")

    # Build graph of mean bw_diff
    plot_cdf(bw_diff, colors, markers, labels, "Network usage (%)",
             "%s_mean_network_usage.cdf" % param_name, output_path)

    # Build graph of std bw_diff
    plot_cdf(bw_diff_stdv, colors, markers, labels, "Stdv Network usage (%)",
             "%s_stdv_network_usage.cdf" % param_name, output_path)

    # Build graph of mean fairness
    plot_cdf(fairness, colors, markers, labels, "Mean Jain Fairness",
             "%s_mean_fairness.cdf" % param_name, output_path)

    # Build graph of std fairness
    plot_cdf(fairness_stdv, colors, markers, labels, "Stdv Jain Fairness",
             "%s_stdv_fairness.cdf" % param_name, output_path)


def plot_stability_by_connection(experiments, id):
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
                nbr_changes_by_conn, exp3_last_prob_by_conn = \
                    exp.stability_by_connection()
            except OverflowError:
                print(exp.timestamp)
                continue

            plot_time(exp3_last_prob_by_conn, "Probability of current path",
                      "last_prob_%s.time" % key, args.out_dir,
                      ylim={"bottom": 0, "top": 1})


def plot_cdf(data, colors, markers, labels, xlabel, figure_name, output_path):
    fig = plt.figure()
    subplot = fig.add_subplot(111)

    min_value = np.inf
    max_value = -np.inf
    for zorder, key in enumerate(data.keys()):
        bin_edges, cdf = cdf_data(data[key])
        if bin_edges is None or cdf is None:
            lg.error("bin_edges or cdf data are None... {bin_edges} - {cdf}\n"
                     .format(bin_edges=bin_edges, cdf=cdf))
            return
        min_value = min(bin_edges[1:] + [min_value])
        max_value = max(bin_edges[1:] + [max_value])

        subplot.step(bin_edges + [max_value * 10 ** 7], cdf + [cdf[-1]],
                     color=colors[key], marker=markers[key],
                     linewidth=LINE_WIDTH, where="post",
                     markersize=MARKER_SIZE, zorder=zorder, label=labels[key])

    subplot.set_xlabel(xlabel, fontsize=FONTSIZE)
    subplot.set_ylabel("CDF", fontsize=FONTSIZE)
    subplot.legend(loc="best")

    lg.info("Saving figure for cdf to path {path}\n"
            .format(path=os.path.join(output_path, figure_name + ".pdf")))

    if max_value <= min_value:
        xdiff = 0.0
    else:
        xdiff = (max_value - min_value) * 0.1

    xlim_min = min(0.0, min_value - xdiff)
    xlim_max = max_value + xdiff
    if xlim_min != xlim_max:  # To avoid being too near of 0
        subplot.set_xlim(left=xlim_min, right=xlim_max)
    subplot.set_ylim(bottom=0, top=1)
    fig.savefig(os.path.join(output_path, figure_name + ".pdf"),
                bbox_inches='tight', pad_inches=0, markersize=9)
    fig.clf()
    plt.close()


def plot_time(data, ylabel, figure_name, output_path, ylim=None, labels=None):
    fig = plt.figure()
    subplot = fig.add_subplot(111)

    for key, values in data.items():
        times = []
        data_y = []
        for t, y in values:
            times.append(t)
            data_y.append(y)
        subplot.step(times, data_y, marker=".", linewidth=LINE_WIDTH,
                     where="post", markersize=MARKER_SIZE)

    subplot.set_xlabel("time (s)", fontsize=FONTSIZE)
    subplot.set_ylabel(ylabel, fontsize=FONTSIZE)
    if labels is not None:
        subplot.legend(loc="best")

    lg.info("Saving figure for plot through time to path {path}\n"
            .format(path=os.path.join(output_path, figure_name + ".pdf")))

    if ylim is not None:
        subplot.set_ylim(**ylim)
    fig.savefig(os.path.join(output_path, figure_name + ".pdf"),
                bbox_inches='tight', pad_inches=0, markersize=9)
    fig.clf()
    plt.close()


def plot_ab_cdfs(delay_experiments: List[ShortTCPeBPFExperiment], output_path):
    for exp in delay_experiments:
        if "investigation" not in exp.topology:  # TODO Remove
            continue  # TODO Remove

        fig = plt.figure()
        subplot = fig.add_subplot(111)

        topo_base = os.path.basename(exp.topology)
        demands_base = os.path.basename(exp.demands)
        key = "%s@%s@%s" % (topo_base, demands_base, exp.random_strategy)
        figure_name = "ab_completion_time_%s.cdf" % key
        times_figure_name = "ab_completion_time_%s.times.reward" % key

        for ab in exp.abs.all():
            cdf = []
            bins = []
            for cdf_dot in ab.ab_latency_cdf.all():
                bins.append(cdf_dot.time)
                cdf.append(cdf_dot.percentage_served)

            subplot.step(bins, cdf, marker=".", linewidth=LINE_WIDTH,
                         where="post", markersize=MARKER_SIZE)

        subplot.set_xlabel("completion time (ms)", fontsize=FONTSIZE)
        subplot.set_ylabel("CDF", fontsize=FONTSIZE)
        subplot.set_xlim(left=0)  # TODO Change right limit

        lg.info("Saving figure for plot ab cdfs to path {path}\n"
                .format(path=os.path.join(output_path, figure_name + ".pdf")))

        fig.savefig(os.path.join(output_path, figure_name + ".pdf"),
                    bbox_inches='tight', pad_inches=0, markersize=9)
        fig.clf()
        plt.close()

        srh_counts = {}
        rewards = {}  # 50 - srtt / 1000
        reward_over_time = {}
        first_sequence = -1
        start_time = 0
        for db_snap in exp.snapshots.all():
            snap = ShortSnapshot.retrieve_from_hex(db_snap.snapshot_hex)
            if first_sequence == -1:
                first_sequence = snap.seq
                start_time = snap.time
                print(first_sequence)
            srh_counts.setdefault(snap.last_srh_id_chosen, 0)
            srh_counts[snap.last_srh_id_chosen] += 1
            rewards.setdefault(snap.last_srh_id_chosen, []).append(
                snap.last_reward)
            reward_over_time.setdefault(snap.last_srh_id_chosen, []).append(
                (snap.time - start_time, snap.last_reward))
        for id, count in srh_counts.items():
            print("{} - {}".format(id, count))

        plot_cdf(rewards, colors={0: "orangered", 1: "#00B0F0"},
                 markers={0: "o", 1: "s"}, labels={0: "Path 0", 1: "Path 1"},
                 xlabel="Path reward", figure_name=figure_name + ".reward",
                 output_path=output_path)
        plot_time(reward_over_time, labels={0: "Path 0", 1: "Path 1"},
                  ylabel="Path reward", figure_name=times_figure_name,
                  output_path=output_path)

        break  # Only take the most recent experiment


if __name__ == "__main__":
    args = parse_args()
    lg.setLogLevel(args.log)
    os.mkdir(args.out_dir)

    db = get_connection()

    experiments = []
    for row in db.query(TCPeBPFExperiment) \
            .filter_by(valid=True, failed=False) \
            .order_by(TCPeBPFExperiment.timestamp.desc()):
        # Filter out
        if "path_step_6_access_6" in row.topology \
                or "pcc" in row.congestion_control:
            continue
        experiments.append(row)

    optim_bw_data = explore_maxflow_json_files(args.srmip_dir)
    # Plot comparison between ebpf topo or not
    # bw_ebpf_or_no_ebpf_by_topo(keys, args.out_dir)

    # Parse gamma diffs
    # bw_param_influence_by_topo(keys, param_name="gamma_value")
    colors = {
        False: "#00B0F0",  # Blue
        True: "orangered",
        "srmip": "#009B55"  # Green
    }
    markers = {
        False: "s",
        True: "o"
    }
    labels = {
        False: "No eBPF",
        True: "eBPF"
    }
    bw_param_influence_aggregate(experiments, param_name="gamma_value",
                                 id={"congestion_control": "cubic",
                                     # "gamma_value": 0.5,
                                     "random_strategy": "exp3"},
                                 colors={0.1: "springgreen",
                                         0.5: "orangered",
                                         0.9: "violet",
                                         "ECMP": "#00B0F0"},
                                 markers={0.1: ".", 0.5: "o", 0.9: "^",
                                          "ECMP": "s"},
                                 labels={0.1: "TPC $\\Gamma = 0.1$",
                                         0.5: "TPC $\\Gamma = 0.5$",
                                         0.9: "TPC $\\Gamma = 0.9$",
                                         "ECMP": "ECMP"},
                                 output_path=args.out_dir)

    bw_param_influence_aggregate(experiments, param_name="random_strategy",
                                 id={"congestion_control": "cubic",
                                     "gamma_value": 0.5,
                                     # "random_strategy": "exp3"
                                     },
                                 colors={"uniform": "springgreen",
                                         "exp3": "orangered",
                                         "ECMP": "#00B0F0"},
                                 markers={"uniform": ".",
                                          "exp3": "o",
                                          "ECMP": "s"},
                                 labels={"uniform": "Uniformly random TPC",
                                         "exp3": "TPC with Exp3",
                                         "ECMP": "ECMP"},
                                 output_path=args.out_dir)

    bw_param_influence_aggregate(experiments, param_name="congestion_control",
                                 id={#"congestion_control": "cubic",
                                     "gamma_value": 0.5,
                                     "random_strategy": "exp3"
                                     },
                                 colors={"cubic": "orangered",
                                         "bbr": "springgreen",
                                         "ECMP": "#00B0F0"},
                                 markers={"cubic": "o",
                                          "bbr": ".",
                                          "ECMP": "s"},
                                 labels={"cubic": "TPC cubic",
                                         "bbr": "TPC bbr",
                                         "ECMP": "ECMP cubic"},
                                 output_path=args.out_dir)

    bw_param_influence_aggregate(experiments, param_name="ebpf",
                                 id={"congestion_control": "cubic",
                                     "gamma_value": 0.5,
                                     "random_strategy": "exp3"
                                     },
                                 colors={True: "orangered",
                                         "ECMP": "#00B0F0"},
                                 markers={True: "o",
                                          "ECMP": "s"},
                                 labels={True: "TPC",
                                         "ECMP": "ECMP"},
                                 output_path=args.out_dir)

    # Parse CC diffs
    # bw_param_influence_by_topo(keys, param_name="congestion_control")

    # Parse rand diffs
    # bw_param_influence_by_topo(keys, param_name="random_strategy")

    # Plot aggregates
    # keys = []
    # for row in db.query(TCPeBPFExperiment.topology,
    #  TCPeBPFExperiment.demands) \
    #         .filter_by(valid=True, failed=False).distinct():
    #     keys.append((row.topology, row.demands))
    # bw_ebpf_or_no_ebpf_aggregate(keys, args.out_dir)
