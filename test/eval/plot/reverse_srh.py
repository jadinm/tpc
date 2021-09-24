import os

from matplotlib import pyplot as plt
from mininet.log import lg

from eval.db import TCPeBPFExperiment
from eval.utils import FLOWBENDER_MEASUREMENT_TIME, LINE_WIDTH, MARKER_SIZE, FONTSIZE


def bw_over_failure(db, output_path):

    # Take the last working experiment of reverse SRH with flowbender
    exp = db.query(TCPeBPFExperiment) \
        .filter_by(valid=True, failed=False, random_strategy="reverse_srh_flowbender") \
        .order_by(TCPeBPFExperiment.timestamp.desc())[0]

    figure_name = "bw_over_failure_{topo}_{demands}" \
        .format(topo=os.path.basename(exp.topology), demands=os.path.basename(exp.demands))
    fig = plt.figure()
    subplot = fig.add_subplot(111)

    times, bw = exp.bw_sum_through_time(db)
    subplot.step(times, [b / 10 ** 6 for b in bw], color="orangered", marker=".", linewidth=LINE_WIDTH,
                 where="post", markersize=MARKER_SIZE)
    subplot.set_xlabel("Time (s)", fontsize=FONTSIZE)
    subplot.set_ylabel("Bandwidth (Mbps)", fontsize=FONTSIZE)
    subplot.set_ylim(bottom=0)
    subplot.set_xlim(left=1, right=FLOWBENDER_MEASUREMENT_TIME)

    lg.info("Saving figure of bw_over_failure for '{topo}' demand '{demands}' to {path}\n"
            .format(topo=os.path.basename(exp.topology), demands=os.path.basename(exp.demands),
                    path=os.path.join(output_path, figure_name + ".pdf")))
    fig.savefig(os.path.join(output_path, figure_name + ".pdf"), bbox_inches='tight', pad_inches=0, markersize=9)
    plt.clf()
    plt.close(fig)
