import matplotlib.pyplot as plt
import os

from sr6mininet.cli import SR6CLI

from examples.albilene import Albilene
from reroutemininet.net import ReroutingNet


COLORS = ["#00B0F0", "orangered", "#009B55", "white", "#D883B7", "yellowgreen", "black"]
MARKERS = ["s", "o", "v", ",", "D", "v", "s", "<"]


def launch_eval(args, ovsschema):
    topo_args = {"schema_tables": ovsschema["tables"],
                 "cwd": os.path.join(args.log_dir, "eval"),
                 "clients": 2}
    net = ReroutingNet(topo=Albilene(**topo_args), static_routing=True, clients=["client", "clientB"], servers=["server"])
    try:
        net.start()
        SR6CLI(net)
    finally:
        net.stop()

    evals = net.eval_files()
    for filename in evals:
        x = {}
        y = {}
        with open(filename, "r") as fileobj:
            for line in fileobj:
                splitted = line.split(" ")
                t = float(splitted[2])
                b = int(splitted[1])
                x.setdefault(splitted[0], []).append(t)
                y.setdefault(splitted[0], []).append(b)
        sfds = x.keys()

        # Plot data
        fig1 = plt.figure()
        subplot = fig1.add_subplot(111)
        for idx in range(len(sfds)):
            subplot.plot(x[sfds[idx]], y[sfds[idx]],
                         color=COLORS[idx], marker=MARKERS[idx],
                         linestyle=":", markersize=2.0)
        fig1.savefig(os.path.join(topo_args["cwd"], "%s.pdf" % "raw_eval"),
                     bbox_inches='tight', pad_inches=0)
        fig1.clf()
        plt.close()
