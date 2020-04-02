import argparse
import datetime
import os
from typing import List

import matplotlib.pyplot as plt
import numpy as np
from mininet.log import LEVELS, lg

from eval.db import get_connection, TCPeBPFExperiment
from eval.utils import FONTSIZE, LINE_WIDTH, MARKER_SIZE, cdf_data, \
    MEASUREMENT_TIME
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


def jain_fairness(bw_data):
    # https://en.wikipedia.org/wiki/Fairness_measure
    return sum(bw_data) * sum(bw_data) \
           / (len(bw_data) * sum([b*b for b in bw_data]))


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
            for iperf in experiment.iperfs:
                cdf_data[ebpf].extend(
                    [[sample.bw for sample in conn.bw_samples]
                     for conn in iperf.connections])

            times, bw = experiment.bw_sum_through_time()
            subplot.step(times, bw, color=colors[ebpf],
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
        mean_data = [np.mean(x[4:-1]) for x in vector]
        print("param: " + legends[i])
        if len(mean_data) != 0:
            print(jain_fairness(mean_data))
        else:
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
            for iperf in experiment.iperfs:
                cdf_data[i - 1].extend(
                    [[sample.bw for sample in conn.bw_samples]
                     for conn in iperf.connections])

            times, bw = experiment.bw_sum_through_time()
            subplot.step(times, bw, color=colors[i - 1],
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
                    for iperf in experiment.iperfs:
                        cdf_data[-1].extend(
                            [[sample.bw for sample in conn.bw_samples]
                             for conn in iperf.connections])

                    times, bw = experiment.bw_sum_through_time()
                    subplot.step(times, bw, color="#00B0F0",
                                 marker="s", linewidth=LINE_WIDTH,
                                 where="post", markersize=MARKER_SIZE,
                                 zorder=i, label="No eBPF")
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


if __name__ == "__main__":
    args = parse_args()
    lg.setLogLevel(args.log)
    os.mkdir(args.out_dir)

    db = get_connection()

    keys = []
    for row in db.query(TCPeBPFExperiment.topology, TCPeBPFExperiment.demands) \
            .filter_by(valid=True, failed=False).distinct():
        keys.append((row.topology, row.demands))

    optim_bw_data = explore_maxflow_json_files(args.srmip_dir)
    # Plot comparison between ebpf topo or not
    bw_ebpf_or_no_ebpf_by_topo(keys, args.out_dir)

    # Parse gamma diffs
    bw_param_influence_by_topo(keys, param_name="gamma_value")

    # Parse CC diffs
    bw_param_influence_by_topo(keys, param_name="congestion_control")

    # Parse rand diffs
    bw_param_influence_by_topo(keys, param_name="random_strategy")

    # Plot aggregates
    # bw_ebpf_or_no_ebpf_aggregate(bw_loaded_data, optim_bw_data, args.out_dir)
