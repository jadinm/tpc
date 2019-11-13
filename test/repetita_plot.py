import argparse
import datetime
import os

import matplotlib.pyplot as plt
import numpy as np
from mininet.log import LEVELS, lg

from eval.utils import FONTSIZE, LINE_WIDTH, MARKER_SIZE, cdf_data
from explore_data import explore_bw_json_files, explore_maxflow_json_files

script_dir = os.path.dirname(os.path.abspath(__file__))


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('--log', choices=LEVELS.keys(), default='info',
                        help='The level of details in the logs.')
    parser.add_argument('--out-dir', help='Output directory root',
                        default='/root/graphs-ebpf/%s' % datetime.datetime.now().strftime('%Y-%m-%d_%H-%M-%S'))
    parser.add_argument('--src-dir', help='Source directory root all test logs',
                        default="/root/experiences")
    parser.add_argument('--srmip-dir', help='Source directory root all sr-mip optimization',
                        default="/root/maxflow-out")
    return parser.parse_args()


def bw_ebpf_or_no_ebpf_by_topo(json_bandwidths, json_srmip_maxflow, output_path):

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

                figure_name = "bw_ebpf_or_no_ebpf_by_topo_{topo}_{demands}_{maxseg}".format(topo=topo,
                                                                                            demands=demands,
                                                                                            maxseg=maxseg)
                fig = plt.figure()
                subplot = fig.add_subplot(111)

                for zorder, ebpf in enumerate([False, True]):
                    if ebpf not in maxseg_exp:
                        continue

                    # Get back data
                    times = []
                    bw = []
                    for t, b in sorted(maxseg_exp[ebpf]):
                        times.append(t)
                        bw.append(b)
                    subplot.step(times, bw, color=colors[ebpf], marker=markers[ebpf], linewidth=LINE_WIDTH,
                                 where="post", markersize=MARKER_SIZE, zorder=zorder, label=labels[ebpf])

                    subplot.set_xlabel("Time (s)", fontsize=FONTSIZE)
                    subplot.set_ylabel("Bandwidth (Mbps)", fontsize=FONTSIZE)

                    maxseg_description = "with max {maxseg} segments".format(maxseg=maxseg) if maxseg >= 0\
                        else "without segment limit"
                    subplot.set_title("Bandwidth for {topo} - {demand}".format(topo=topo, demand=demands)
                                      + maxseg_description)

                # Add line for max value of maxflow if any
                objective = json_srmip_maxflow.get(topo, {}).get(demands, {}).get(6, None)  # TODO Change 6 by maxseg
                if objective is not None:
                    print(objective)
                    subplot.hlines(objective, 0, 100, colors=colors["srmip"],  # Objective values are in kbps
                                   linestyles="solid", label="optimum")
                else:
                    lg.error("No optimum computation found for '{topo}' - '{demands}' with maximum {maxseg} segments\n"
                             .format(topo=topo, demands=demands, maxseg=maxseg))

                lg.info("Saving figure for bandwidth for '{topo}' demand '{demands}' with maxseg={maxseg} to {path}\n"
                        .format(topo=topo, maxseg=maxseg, demands=demands, path=os.path.join(output_path, figure_name + ".pdf")))
                subplot.set_ylim(bottom=0)
                subplot.set_xlim(left=1, right=29)
                fig.savefig(os.path.join(output_path, figure_name + ".pdf"),
                            bbox_inches='tight', pad_inches=0, markersize=9)
                fig.clf()
                plt.close()

                break  # TODO Remove


def bw_ebpf_or_no_ebpf_aggregate(json_bandwidths, json_srmip_maxflow, output_path):
    color = "orangered"
    marker = "o"

    bw_diff = []
    for topo, topo_exp in json_bandwidths.items():
        for demands, demands_exp in topo_exp.items():
            for maxseg, maxseg_exp in demands_exp.items():
                ebpf_example = np.median(maxseg_exp[True])
                print(ebpf_example)
                no_ebpf_example = np.median(maxseg_exp[False])
                print(no_ebpf_example)
                bw_diff.append(float(ebpf_example - no_ebpf_example) / float(no_ebpf_example) * 100)
    print(bw_diff)

    # Build CDF
    bin_edges, cdf = cdf_data(bw_diff)
    if bin_edges is None or cdf is None:
        lg.error("bin_edges or cdf data are None... {bin_edges} - {cdf}\n".format(bin_edges=bin_edges, cdf=cdf))
        return
    min_value = min(bin_edges[1:])
    max_value = max(bin_edges[1:])

    # Build graph
    figure_name = "sr_effectiveness_real"
    fig = plt.figure()
    subplot = fig.add_subplot(111)

    subplot.step(bin_edges + [max_value * 10 ** 7], cdf + [cdf[-1]], color=color, marker=marker, linewidth=LINE_WIDTH,
                 where="post", markersize=MARKER_SIZE)

    subplot.set_xlabel("Maximum flow improvement (%)", fontsize=FONTSIZE)
    subplot.set_ylabel("CDF", fontsize=FONTSIZE)

    subplot.set_title("Maximum flow improvement by adding SRv6")

    lg.info("Saving figure for SR effectiveness in reality to path {path}\n".format(path=os.path.join(output_path, figure_name + ".pdf")))

    if max_value <= min_value:
        xdiff = 0.0
    else:
        xdiff = (max_value - min_value) * 0.1

    xlim_min = min(0.0, min_value - xdiff)
    xlim_max = max_value + xdiff
    if xlim_min != xlim_max:
        subplot.set_xlim(left=xlim_min, right=xlim_max)  # To avoid being too near of 0
    subplot.set_ylim(bottom=0, top=1)
    fig.savefig(os.path.join(output_path, figure_name + ".pdf"),
                bbox_inches='tight', pad_inches=0, markersize=9)
    fig.clf()
    plt.close()


if __name__ == "__main__":
    args = parse_args()
    lg.setLogLevel(args.log)
    os.mkdir(args.out_dir)

    bw_loaded_data = explore_bw_json_files(args.src_dir)
    optim_bw_data = explore_maxflow_json_files(args.srmip_dir)
    bw_ebpf_or_no_ebpf_by_topo(bw_loaded_data, optim_bw_data, args.out_dir)
    bw_ebpf_or_no_ebpf_aggregate(bw_loaded_data, optim_bw_data, args.out_dir)
