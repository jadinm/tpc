import argparse
import copy
import datetime
import os
from typing import Dict, List

import matplotlib.pyplot as plt
import numpy as np
from mininet.log import LEVELS, lg

from eval.bpf_stats import Snapshot
from eval.utils import FONTSIZE, LINE_WIDTH, MARKER_SIZE, cdf_data, \
    MEASUREMENT_TIME
from explore_data import explore_bw_json_files, explore_maxflow_json_files

script_dir = os.path.dirname(os.path.abspath(__file__))


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('--log', choices=LEVELS.keys(), default='info',
                        help='The level of details in the logs.')
    parser.add_argument('--out-dir', help='Output directory root',
                        default='/root/graphs-ebpf/%s' % datetime.datetime.now().strftime('%Y-%m-%d_%H-%M-%S'))
    parser.add_argument('--src-dirs', nargs='*', action='store',
                        help='Source directories root all test logs',
                        default=["/root/experiences",
                                 "/root/paths-gamma-variable/no-ebpf"])
    parser.add_argument('--srmip-dir',
                        help='Source directory root all sr-mip optimization',
                        default="/root/maxflow-out")
    parser.add_argument('--gamma-dirs', nargs='*', action='store',
                        help='List of source directories for different '
                             'values of gamma. Each element of the list has '
                             'its gamma value appended to the list as well',
                        default=["/root/paths-gamma-variable/ebpf-gamma-0.1",
                                 0.1,
                                 "/root/paths-gamma-variable/ebpf-gamma-0.5",
                                 0.5,
                                 "/root/paths-gamma-variable/ebpf-gamma-0.9",
                                 0.9])
    parser.add_argument('--reward-mult-dirs', nargs='*', action='store',
                        help='List of source directories for different '
                             'values of gamma. Each element of the list has '
                             'its gamma value appended to the list as well',
                        default=["/root/paths-reward-mult-variable/ebpf-reward-mult-1",
                                 1,
                                 "/root/paths-reward-mult-variable/ebpf-reward-mult-10",
                                 10,
                                 "/root/paths-reward-mult-variable/ebpf-reward-mult-100",
                                 100])
    parser.add_argument('--cc-dirs', nargs='*', action='store',
                        help='List of source directories for different '
                             'values of gamma. Each element of the list has '
                             'its gamma value appended to the list as well',
                        default=["/root/paths-cc-variable/ebpf-cc-cubic",
                                 "cubic",
                                 "/root/paths-cc-variable/ebpf-cc-bbr",
                                 "bbr",
                                 "/root/paths-cc-variable/ebpf-cc-pcc",
                                 "pcc"])
    parser.add_argument('--rand-dirs', nargs='*', action='store',
                        help='List of source directories for different '
                             'random strategies. Each element of the list has '
                             'its random strategy value appended to the list '
                             'as well',
                        default=["/root/paths-rand-variable/exp3",
                                 "exp3",
                                 "/root/paths-rand-variable/uniform",
                                 "uniform"])
    return parser.parse_args()


def bw_ebpf_or_no_ebpf_by_topo(json_bandwidths, json_srmip_maxflow,
                               output_path, unaggregated_bw):

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

    for topo, topo_exp in json_bandwidths.items():
        for demands, demands_exp in topo_exp.items():
            for maxseg, maxseg_exp in demands_exp.items():

                if True not in maxseg_exp.keys() \
                        or False not in maxseg_exp.keys():
                    continue

                figure_name = "bw_ebpf_or_no_ebpf_by_topo" \
                              "_{topo}_{demands}_{maxseg}"\
                    .format(topo=topo, demands=demands, maxseg=maxseg)
                fig = plt.figure()
                subplot = fig.add_subplot(111)

                for zorder, ebpf in enumerate([False, True]):

                    # Get back data
                    times = []
                    bw = []
                    for t, b in sorted(maxseg_exp[ebpf]):
                        times.append(t)
                        bw.append(copy.deepcopy(b))
                    subplot.step(times, bw, color=colors[ebpf],
                                 marker=markers[ebpf], linewidth=LINE_WIDTH,
                                 where="post", markersize=MARKER_SIZE,
                                 zorder=zorder, label=labels[ebpf])

                    subplot.set_xlabel("Time (s)", fontsize=FONTSIZE)
                    subplot.set_ylabel("Bandwidth (Mbps)", fontsize=FONTSIZE)

                    maxseg_description = "with max {maxseg} segments"\
                        .format(maxseg=maxseg) if maxseg >= 0\
                        else "without segment limit"
                    subplot.set_title("Bandwidth for {topo} - {demand}"
                                      .format(topo=topo, demand=demands)
                                      + maxseg_description)

                # Add line for max value of maxflow if any
                objective = json_srmip_maxflow.get(topo, {})\
                    .get(demands, {}).get(6, None)  # TODO Change 6 by maxseg
                if objective is not None:
                    subplot.hlines(objective, 0, 100, colors=colors["srmip"],  # Objective values are in kbps
                                   linestyles="solid", label="optimum")
                else:
                    lg.error("No optimum computation found for '{topo}'"
                             " - '{demands}' with maximum {maxseg} segments\n"
                             .format(topo=topo, demands=demands, maxseg=maxseg))

                lg.info("Saving figure for bandwidth for '{topo}' demand "
                        "'{demands}' with maxseg={maxseg} to {path}\n"
                        .format(topo=topo, maxseg=maxseg, demands=demands,
                                path=os.path.join(output_path,
                                                  figure_name + ".pdf")))
                subplot.set_ylim(bottom=0)
                subplot.set_xlim(left=1, right=MEASUREMENT_TIME)
                subplot.legend(loc="best")
                fig.savefig(os.path.join(output_path, figure_name + ".pdf"),
                            bbox_inches='tight', pad_inches=0, markersize=9)
                fig.clf()
                plt.close()

                # Add a graph with a boxplot every second
                cdf_no_ebpf_bw_by_conn = {}
                cdf_ebpf_bw_by_conn = {}
                if unaggregated_bw.get(topo, {}).get(demands, {}) \
                        .get(maxseg, {}).get(True) is not None:
                    fig = plt.figure()
                    subplot = fig.add_subplot(111)

                    times = []
                    bw = []
                    for t, b in sorted(
                            unaggregated_bw[topo][demands][maxseg][True]):
                        times.append(t)
                        bw.append(b)
                        for conn in range(len(b)):
                            cdf_ebpf_bw_by_conn.setdefault(conn, []) \
                                .append(copy.deepcopy(b[conn]))
                    # XXX Remove early data and last measure (with the FIN)
                    times = times[4:-1]
                    bw = bw[4:-1]
                    subplot.boxplot(bw)
                    subplot.set_ylim(bottom=0, top=200)  # TODO Change

                    figure_name = "bw_ebpf_fairness_by_topo" \
                                  "_{topo}_{demands}_{maxseg}" \
                        .format(topo=topo, demands=demands, maxseg=maxseg)
                    fig.savefig(os.path.join(output_path,
                                             figure_name + "_boxplot.pdf"),
                                bbox_inches='tight', pad_inches=0, markersize=9)
                    fig.clf()
                    plt.close()

                # Add a graph with a boxplot every second
                if unaggregated_bw.get(topo, {}).get(demands, {}) \
                        .get(maxseg, {}).get(False) is not None:
                    fig = plt.figure()
                    subplot = fig.add_subplot(111)

                    times = []
                    bw = []
                    for t, b in sorted(
                            unaggregated_bw[topo][demands][maxseg][False]):
                        times.append(t)
                        bw.append(b)
                        for conn in range(len(b)):
                            cdf_no_ebpf_bw_by_conn.setdefault(conn, []) \
                                .append(b[conn])
                    # XXX Remove early data and last measure (with the FIN)
                    times = times[4:-1]
                    bw = bw[4:-1]
                    subplot.boxplot(bw)
                    subplot.set_ylim(bottom=0, top=200)  # TODO Change

                    figure_name = "bw_no_ebpf_fairness_by_topo" \
                                  "_{topo}_{demands}_{maxseg}" \
                        .format(topo=topo, demands=demands, maxseg=maxseg)
                    fig.savefig(os.path.join(output_path,
                                             figure_name + "_boxplot.pdf"),
                                bbox_inches='tight', pad_inches=0,
                                markersize=9)
                    fig.clf()
                    plt.close()

                # Draw CDF of fairness comparison
                if len(cdf_ebpf_bw_by_conn) == 0 \
                        or len(cdf_no_ebpf_bw_by_conn) == 0:
                    continue

                figure_name = "bw_fairness_{topo}_{demands}_{maxseg}" \
                    .format(name=figure_name, topo=topo, demands=demands,
                            maxseg=maxseg)
                fairness_cdf_plot(output_path,
                                  [list(cdf_ebpf_bw_by_conn.values()),
                                   list(cdf_no_ebpf_bw_by_conn.values())],
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
        mean_data = [np.mean(x) for x in vector]
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


def bw_param_influence_by_topo(json_bandwidths, json_srmip_maxflow, output_path,
                               snapshots, unaggregated_bw, param_name="cc"):
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

    topos = {}

    for param, param_exp in json_bandwidths.items():
        for topo, topo_exp in param_exp.items():
            for demands, demands_exp in topo_exp.items():
                for maxseg, maxseg_exp in demands_exp.items():
                    snaps = snapshots.get(param, {}).get(topo, {})\
                        .get(demands, {}).get(param, [])
                    topos.setdefault(topo, {}).setdefault(demands, {})\
                        .setdefault(maxseg, {})[param] = maxseg_exp, snaps

    for topo, topo_exp in topos.items():
        for demands, demands_exp in topo_exp.items():
            for maxseg, maxseg_exp in demands_exp.items():

                figure_name = "bw_{param_name}_by_topo" \
                              "_{topo}_{demands}" \
                    .format(topo=topo, demands=demands, param_name=param_name)
                fig = plt.figure()
                subplot = fig.add_subplot(111)

                i = 0
                cdf_data = [{} for i in range(len(maxseg_exp) + 1)]
                labels = ["" for i in range(len(maxseg_exp) + 1)]
                for param, param_exp in maxseg_exp.items():
                    i += 1

                    param_exp, snaps = param_exp

                    if i == 1:  # Add no ebpf
                        times = []
                        bw = []
                        for t, b in sorted(param_exp[False]):
                            times.append(t)
                            bw.append(b)
                        if unaggregated_bw.get(param, {}).get(topo) is not None:
                            for t, b in sorted(
                                    unaggregated_bw[param][topo][demands][
                                        maxseg][False]):
                                for conn in range(len(b)):
                                    cdf_data[-1].setdefault(conn, []).append(
                                        b[conn])
                        subplot.step(times, bw, color="#00B0F0",
                                     marker="s", linewidth=LINE_WIDTH,
                                     where="post", markersize=MARKER_SIZE,
                                     zorder=i, label="No eBPF")
                        labels[-1] = "ECMP"

                    # Get back data
                    times = []
                    bw = []
                    for t, b in sorted(param_exp[True]):
                        times.append(t)
                        bw.append(b)
                        if unaggregated_bw.get(param, {}).get(topo) is not None:
                            for t, b in sorted(
                                    unaggregated_bw[param][topo][demands][
                                        maxseg][True]):
                                for conn in range(len(b)):
                                    cdf_data[i - 1].setdefault(conn, []) \
                                        .append(b[conn])
                    subplot.step(times, bw, color=colors[i - 1],
                                 marker=markers[i - 1], linewidth=LINE_WIDTH,
                                 where="post", markersize=MARKER_SIZE,
                                 zorder=i,
                                 label="{} {}".format(param_name, param))
                    labels[i - 1] = "{} {}".format(param_name, param)

                subplot.set_xlabel("Time (s)", fontsize=FONTSIZE)
                subplot.set_ylabel("Bandwidth (Mbps)", fontsize=FONTSIZE)

                maxseg_description = "with max {maxseg} segments"\
                    .format(maxseg=maxseg) if int(maxseg) >= 0\
                    else "without segment limit"
                subplot.set_title("Bandwidth for {topo} - {demand}"
                                  .format(topo=topo, demand=demands)
                                  + maxseg_description)

                # Add line for max value of maxflow if any
                objective = json_srmip_maxflow.get(topo, {})\
                    .get(demands, {}).get(6, None)  # TODO Change 6 by maxseg
                if objective is not None:
                    subplot.hlines(objective, 0, 100, colors="#009B55",  # Objective values are in kbps
                                   linestyles="solid", label="optimum")
                else:
                    lg.error("No optimum computation found for '{topo}'"
                             " - '{demands}' with maximum {maxseg} segments\n"
                             .format(topo=topo, demands=demands, maxseg=maxseg))

                lg.info("Saving figure for {param_name}s for '{topo}' demand "
                        "'{demands}' with maxseg={maxseg} to {path}\n"
                        .format(param_name=param_name, topo=topo,
                                maxseg=maxseg, demands=demands,
                                path=os.path.join(output_path,
                                                  figure_name + ".pdf")))
                subplot.set_ylim(bottom=0)
                subplot.set_xlim(left=1, right=MEASUREMENT_TIME)
                subplot.legend(loc="best")
                fig.savefig(os.path.join(output_path, figure_name + ".pdf"),
                            bbox_inches='tight', pad_inches=0, markersize=9)
                plt.clf()
                plt.close(fig)

                # Draw CDF of fairness comparison
                if len(cdf_data[0]) == 0:
                    continue

                figure_name = "bw_fairness_{param_name}_{topo}_{demands}_" \
                              "{maxseg}" \
                    .format(param_name=param_name, topo=topo, demands=demands,
                            maxseg=maxseg)
                fairness_cdf_plot(output_path,
                                  [list(dic.values()) for dic in cdf_data],
                                  title="", legends=labels,
                                  colors=colors + ["#00B0F0"],
                                  markers=markers + ["s"],
                                  figure_name=figure_name)


def bw_ebpf_or_no_ebpf_aggregate(json_bandwidths, json_srmip_maxflow,
                                 output_path):
    color = "orangered"
    marker = "o"

    bw_diff = []
    for topo, topo_exp in json_bandwidths.items():
        for demands, demands_exp in topo_exp.items():
            if "rand.1" not in demands:
                # TODO Replace by plots by type of
                #  demand files
                continue
            for maxseg, maxseg_exp in demands_exp.items():

                if True not in maxseg_exp.keys() \
                        or False not in maxseg_exp.keys():
                    continue

                ebpf_example = np.median([x for _, x in maxseg_exp[True]])
                no_ebpf_example = np.median([x for _, x in maxseg_exp[False]])
                bw_diff.append(float(ebpf_example - no_ebpf_example)
                               / float(no_ebpf_example) * 100)

                if bw_diff[-1] > 50:
                    print("Good example ! %f %s" % (bw_diff[-1], topo))
                elif bw_diff[-1] < -25:
                    print("BAD example ! %f %s" % (bw_diff[-1], topo))
                    print(ebpf_example)
                    print(no_ebpf_example)
                    print([x for _, x in maxseg_exp[True]])
                    print([x for _, x in maxseg_exp[False]])
                    print(float(ebpf_example - no_ebpf_example))
                    print(float(no_ebpf_example))

    # Build CDF
    bin_edges, cdf = cdf_data(bw_diff)
    if bin_edges is None or cdf is None:
        lg.error("bin_edges or cdf data are None... {bin_edges} - {cdf}\n"
                 .format(bin_edges=bin_edges, cdf=cdf))
        return
    min_value = min(bin_edges[1:])
    max_value = max(bin_edges[1:])

    # Build graph
    figure_name = "sr_effectiveness_real"
    fig = plt.figure()
    subplot = fig.add_subplot(111)

    subplot.step(bin_edges + [max_value * 10 ** 7], cdf + [cdf[-1]],
                 color=color, marker=marker, linewidth=LINE_WIDTH,
                 where="post", markersize=MARKER_SIZE)

    subplot.set_xlabel("Maximum flow improvement (%)", fontsize=FONTSIZE)
    subplot.set_ylabel("CDF", fontsize=FONTSIZE)

    subplot.set_title("Maximum flow improvement by adding SRv6")

    lg.info("Saving figure for SR effectiveness in reality to path {path}\n"
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


def plot_bw_per_topo(times, bw, output_path, demand_id,
                     snapshots: Dict[str, List[Snapshot]], ebpf=True):

    suffix = "ebpf" if ebpf else "no-ebpf"

    # Bandwidth
    figure_name = "bw_iperf_%s_%s" % (demand_id, suffix)
    fig = plt.figure()
    subplot = fig.add_subplot(111)
    x = times
    bw = [float(b) for b in bw]

    subplot.step(x, bw, color="#00B0F0", marker="o", linewidth=2.0,
                 where="post", markersize=5, zorder=2)

    # Parse snapshots
    for h, snaps in snapshots.items():
        conn_snaps = {}
        for s in snaps:
            conn_snaps.setdefault(s.conn_key(), []).append(s)
        for by_conn_snaps in conn_snaps.values():
            if len(by_conn_snaps) <= 2:
                continue
            for i in range(1, len(by_conn_snaps) - 1):
                # Vertical line
                t = (by_conn_snaps[i].time - by_conn_snaps[0].time) / 10**9
                subplot.axvline(x=t)

    subplot.set_xlabel("Time (s)", fontsize=FONTSIZE)
    subplot.set_ylabel("Bandwidth (Mbps)", fontsize=FONTSIZE)
    subplot.set_ylim(bottom=0)
    subplot.set_xlim(left=0, right=MEASUREMENT_TIME)

    pdf = os.path.join(output_path, "%s.pdf" % figure_name)
    lg.info("Save figure for bandwidth to %s\n" % pdf)
    fig.savefig(pdf, bbox_inches='tight', pad_inches=0, markersize=9)
    fig.clf()
    plt.close()


def produce_param_diff_graphs(dirs, param_name="cc"):
    param_loaded_data = {}
    param_unaggregated_data = {}
    param_snap_data = {}
    for i in range(0, len(dirs), 2):
        bw_data, snaps, unaggregated_bw = explore_bw_json_files([dirs[i]])
        param_value = dirs[i + 1]
        param_loaded_data.setdefault(param_value, bw_data)
        param_snap_data.setdefault(param_value, snaps)
        param_unaggregated_data.setdefault(param_value, unaggregated_bw)

        # Add no ebpf data
        for topo, topo_exp in param_loaded_data[param_value].items():
            for demands, demands_exp in topo_exp.items():
                for maxseg, maxseg_exp in demands_exp.items():
                    bws_no_ebpf = bw_loaded_data.get(topo, {}) \
                        .get(demands, {}).get(maxseg, {}).get(False)
                    if bws_no_ebpf is not None:
                        unagg_bw_no_ebpf = unaggregated_loaded_bw.get(topo, {}) \
                            .get(demands, {}).get(maxseg, {}).get(False)
                        maxseg_exp[False] = bws_no_ebpf

                        if unagg_bw_no_ebpf is not None:
                            param_unaggregated_data[param_value][topo][demands] \
                                [maxseg][False] = unagg_bw_no_ebpf
                        else:
                            print("Cannot find unaggregated data")
                    else:
                        print("Cannot find solution without ebpf for topo"
                              " {topo} demand {demand}".format(topo=topo,
                                                               demand=demands))

    bw_param_influence_by_topo(param_loaded_data, optim_bw_data,
                               args.out_dir, param_snap_data,
                               param_unaggregated_data, param_name=param_name)


if __name__ == "__main__":
    args = parse_args()
    lg.setLogLevel(args.log)
    os.mkdir(args.out_dir)

    bw_loaded_data, snap_data, unaggregated_loaded_bw = explore_bw_json_files(
        args.src_dirs)
    optim_bw_data = explore_maxflow_json_files(args.srmip_dir)
    # Plot aggregates and comparison between ebpf topo or not
    bw_ebpf_or_no_ebpf_by_topo(bw_loaded_data, optim_bw_data, args.out_dir,
                               unaggregated_loaded_bw)
    bw_ebpf_or_no_ebpf_aggregate(bw_loaded_data, optim_bw_data, args.out_dir)

    # Parse gamma diffs
    produce_param_diff_graphs(args.gamma_dirs, param_name="gamma")

    # Parse reward mult diffs
    produce_param_diff_graphs(args.reward_mult_dirs, param_name="reward_mult")

    # Parse CC diffs
    produce_param_diff_graphs(args.cc_dirs, param_name="cc")

    # Parse rand diffs
    produce_param_diff_graphs(args.rand_dirs, param_name="rand")

    # Plot bw by topology
    for topo, topo_exp in bw_loaded_data.items():
        for demands, demands_exp in topo_exp.items():
            for maxseg, maxseg_exp in demands_exp.items():
                for ebpf in maxseg_exp.keys():
                    # Get back data
                    times_tmp = []
                    bw_tmp = []
                    for t, b in sorted(maxseg_exp[ebpf]):
                        times_tmp.append(t)
                        bw_tmp.append(b)
                    plot_bw_per_topo(times_tmp, bw_tmp, args.out_dir,
                                     demands,
                                     snap_data.get(topo, {}).get(demands, {})
                                     .get(maxseg, {}).get(ebpf, []),
                                     ebpf)
