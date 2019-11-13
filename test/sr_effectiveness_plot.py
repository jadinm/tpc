import argparse
import datetime
import json
import os

import matplotlib.pyplot as plt
from mininet.log import LEVELS, lg

from eval.utils import FONTSIZE, LINE_WIDTH, MARKER_SIZE, cdf_data
from explore_data import explore_maxflow_json_files


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('--log', choices=LEVELS.keys(), default='info',
                        help='The level of details in the logs.')
    parser.add_argument('--out-dir', help='Output directory root',
                        default='/root/graphs-sr-effectiveness/%s'
                                % datetime.datetime.now().strftime('%Y-%m-%d_%H-%M-%S'))
    parser.add_argument('--srmip-dir', help='Source directory root all sr-mip optimization',
                        default="/root/maxflow-out")
    return parser.parse_args()


def sr_effectiveness_plot(json_bandwidths, output_path, maxseg=6):
    color = "orangered"
    marker = "o"

    topo_improving = []

    # Get back data
    bw_diff = []
    for topo, topo_exp in json_bandwidths.items():
        for demands, demands_exp in topo_exp.items():
            if maxseg not in demands_exp or 1 not in demands_exp:
                continue
            if demands_exp[1] == 0:
                lg.warning("Topo {topo} - demands {demands} did not manage to get any flow through\n"
                           .format(topo=topo, demands=demands))
                continue
            bw_diff.append(float(demands_exp[maxseg] - demands_exp[1]) / float(demands_exp[1]) * 100)
            if bw_diff[-1] > 0:
                topo_improving.append({"topo": topo, "demands": demands, "improvement": bw_diff[-1]})

    # Build CDF
    bin_edges, cdf = cdf_data(bw_diff)
    if bin_edges is None or cdf is None:
        lg.error("bin_edges or cdf data are None... {bin_edges} - {cdf}\n".format(bin_edges=bin_edges, cdf=cdf))
        return
    min_value = min(bin_edges[1:])
    max_value = max(bin_edges[1:])

    # Build graph
    figure_name = "sr_effectiveness_{maxseg}".format(maxseg=maxseg)
    fig = plt.figure()
    subplot = fig.add_subplot(111)

    subplot.step(bin_edges + [max_value * 10 ** 7], cdf + [cdf[-1]], color=color, marker=marker, linewidth=LINE_WIDTH,
                 where="post", markersize=MARKER_SIZE)

    subplot.set_xlabel("Maximum flow improvement (%)", fontsize=FONTSIZE)
    subplot.set_ylabel("CDF", fontsize=FONTSIZE)

    subplot.set_title("Maximum flow improvement by adding {maxseg} segments".format(maxseg=maxseg))

    lg.info("Saving figure for SR effectiveness for maxseg={maxseg}\n" .format(maxseg=maxseg))

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

    json_path = os.path.join(output_path, "improvement_combinations.json")
    lg.info("Writing improvements in JSON to {json_path}\n" .format(json_path=json_path))
    with open(json_path, "w") as fileobj:
        json.dump(topo_improving, fileobj, indent=4)


if __name__ == "__main__":
    args = parse_args()
    lg.setLogLevel(args.log)
    os.mkdir(args.out_dir)

    optim_bw_data = explore_maxflow_json_files(args.srmip_dir)
    sr_effectiveness_plot(optim_bw_data, args.out_dir)
