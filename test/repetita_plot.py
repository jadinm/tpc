import argparse
import datetime
import json
import os

import matplotlib.pyplot as plt
from mininet.log import LEVELS, lg

from eval.utils import FONTSIZE, LINE_WIDTH, MARKER_SIZE

script_dir = os.path.dirname(os.path.abspath(__file__))


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('--log', choices=LEVELS.keys(), default='info',
                        help='The level of details in the logs.')
    parser.add_argument('--out-dir', help='Output directory root',
                        default='/root/graphs-ebpf/%s' % datetime.datetime.now().strftime('%Y-%m-%d_%H-%M-%S'))
    parser.add_argument('--src-dir', help='Source directory root all test logs',
                        default="/root/experiences")
    return parser.parse_args()


def explore_bw_json_files(src_dir):
    bw_data = {}
    bw_files = []
    for root, directories, files in os.walk(src_dir):
        if "logs-" not in root:
            continue
        for f in files:
            if ".json" in f and "repetita_" in f:
                bw_files.append(os.path.join(root, f))

    # Order files by date so that old data gets erased by newest experiments
    bw_files.sort()

    # Get back the bandwidth data
    for f in bw_files:
        if ".json" in f and "repetita_" in f:
            with open(f) as file_obj:
                data = json.load(file_obj)
                if "bw" not in data or "id" not in data:
                    continue
                data_copy = [(int(k), float(v)) for k, v in data["bw"].items()]
                bw_data.setdefault(data["id"]["topo"], {})\
                    .setdefault(data["id"]["maxseg"], {})[data["id"]["ebpf"]] = data_copy

    return bw_data


def bw_ebpf_or_no_ebpf_by_topo(json_bandwidths, output_path):

    colors = {
        False: "#00B0F0",  # Blue
        True: "orangered"
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
        for maxseg, maxseg_exp in topo_exp.items():

            figure_name = "bw_ebpf_or_no_ebpf_by_topo_{topo}_{maxseg}".format(topo=topo, maxseg=maxseg)
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
                subplot.step(times, bw, color=colors[ebpf], marker=markers[ebpf], linewidth=LINE_WIDTH, where="post",
                             markersize=MARKER_SIZE, zorder=zorder, label=labels[ebpf])

                subplot.set_xlabel("Time (s)", fontsize=FONTSIZE)
                subplot.set_ylabel("Bandwidth (Mbps)", fontsize=FONTSIZE)

                maxseg_description = "with max {maxseg} segments".format(maxseg=maxseg) if maxseg >= 0\
                    else "without segment limit"
                subplot.set_title("Bandwidth for {topo} ".format(topo=topo) + maxseg_description)

            print("Saving figure for bandwidth for '{topo}' with maxseg={maxseg}".format(topo=topo, maxseg=maxseg))
            subplot.set_ylim(bottom=0)
            subplot.set_xlim(left=0)
            fig.savefig(os.path.join(output_path, figure_name + ".pdf"),
                        bbox_inches='tight', pad_inches=0, markersize=9)
            fig.clf()
            plt.close()


if __name__ == "__main__":
    args = parse_args()
    lg.setLogLevel(args.log)
    os.mkdir(args.out_dir)

    bw_loaded_data = explore_bw_json_files(args.src_dir)
    bw_ebpf_or_no_ebpf_by_topo(bw_loaded_data, args.out_dir)
