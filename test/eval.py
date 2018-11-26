import matplotlib.pyplot as plt
import os
import time

from examples.albilene import Albilene
from examples.repetita_network import RepetitaTopo
from reroutemininet.net import ReroutingNet

COLORS = ["#00B0F0", "orangered", "#009B55", "white", "#D883B7", "yellowgreen", "black"]
MARKERS = ["s", "o", "v", ",", "D", "v", "s", "<"]
FONTSIZE = 20


def bandwidth_graphs(net, topo_args):
    evals = net.eval_files()
    for filename in evals:
        server_node = os.path.basename(filename).split(".")[0]
        server_port = os.path.basename(os.path.dirname(filename))
        x = {}
        y = {}
        with open(filename, "r") as fileobj:
            for line in fileobj:
                splitted = line.split(" ")
                t = float(splitted[2])  # sec
                b = (int(splitted[1]) * 8) / 1000.0  # Bytes -> kbits
                x.setdefault(splitted[0], []).append(t)
                y.setdefault(splitted[0], []).append(b)
        sfds = x.keys()

        # Plot data
        fig1 = plt.figure()
        subplot = fig1.add_subplot(111)
        subplot.set_xlabel("Time (sec)", fontsize=FONTSIZE)
        subplot.set_ylabel("Bandwidth (kbps)", fontsize=FONTSIZE)
        subplot.set_title("Bandwidth experienced by %s on port %s" % (server_node, server_port), fontsize=FONTSIZE)
        subplot.set_ylim(0.0)
        for idx in range(len(sfds)):
            subplot.plot(x[sfds[idx]], y[sfds[idx]],
                         color=COLORS[idx], marker=MARKERS[idx],
                         linestyle=":", markersize=2.0)
        fig1.savefig(os.path.join(topo_args["cwd"], "%s-%s.pdf" % (server_node, server_port)),
                     bbox_inches='tight', pad_inches=0)
        fig1.clf()
        plt.close()


def launch_eval(args, ovsschema):
    topo_args = {"schema_tables": ovsschema["tables"],
                 "cwd": os.path.join(args.log_dir, "eval")}
    net = ReroutingNet(topo=Albilene(**topo_args), static_routing=True, clients=["client", "clientB"], servers=["server"])
    try:
        net.start()
        time.sleep(30)
    finally:
        net.stop()

    bandwidth_graphs(net, topo_args)


def launch_repetita_eval(args, ovsschema):
    topo_args = {"schema_tables": ovsschema["tables"],
                 "cwd": os.path.join(args.log_dir, "eval"),
                 "repetita_graph": args.repetita_topo}
    topo = RepetitaTopo(**topo_args)
    net = ReroutingNet(topo=topo, static_routing=True, clients=topo.hosts(), servers=topo.hosts())
    try:
        net.start()
        time.sleep(60)
    finally:
        net.stop()

    bandwidth_graphs(net, topo_args)
