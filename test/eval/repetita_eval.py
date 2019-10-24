import json
import os
import subprocess
import time
from shlex import split

import matplotlib.pyplot as plt
from sr6mininet.cli import SR6CLI

from examples.albilene import Albilene
from reroutemininet.net import ReroutingNet
from .utils import get_addr, debug_tcpdump

MAX_BANDWIDTH = 75
MEASUREMENT_TIME = 100

FONTSIZE = 12
INTERVALS = 1


def launch_iperf(net, clients, servers, result_files, ebpf=True):
    """
    :param net: The Network object
    :param clients: The list of client node names
    :param servers: The list of server node names
     (same size as the client list and it means that clients[i] will have a connection to servers[i])
    :param result_files: The list of file object where to store the output
     (same size as the client list and it means that clients[i] will have its output written to result_files[i])
    :param ebpf: Whether there is eBPF and ccgroup activated
    :return: a tuple <list of popen objects of servers, list of popen objects of clients>
    """
    try:
        subprocess.check_call(split("pkill iperf3"))
    except subprocess.CalledProcessError:
        pass

    pid_servers = []
    ports = [5201 + i for i in range(len(servers))]
    for i, server in enumerate(servers):
        cmd = "iperf3 -J -s -p %d" % ports[i]
        if ebpf:
            pid_servers.append(net[server].run_cgroup(cmd))
        else:
            pid_servers.append(net[server].popen(split(cmd)))
    time.sleep(5)

    for pid in pid_servers:
        if pid.poll() is not None:
            print("The server exited too early with err=%s" % pid.poll())
            for pid in pid_servers:
                if pid.poll() is None:
                    pid.kill()
            return [], []

    pid_clients = []
    for i, client in enumerate(clients):
        cmd = "iperf3 -J -c {server_ip} -t {duration} -B {client_ip} -b {bw}M -i {intervals} -p {port}"\
            .format(server_ip=get_addr(net[servers[i]]), client_ip=get_addr(net[client]),
                    duration=MEASUREMENT_TIME, bw=MAX_BANDWIDTH, intervals=INTERVALS, port=ports[i])
        if ebpf:
            pid_clients.append(net[client].run_cgroup(cmd, stdout=result_files[i]))
        else:
            pid_clients.append(net[client].popen(split(cmd), stdout=result_files[i]))
    time.sleep(5)

    for pid in pid_clients:
        if pid.poll() is not None:
            print("The client exited too early with err=%s" % pid.poll())
            for pid in pid_clients + pid_servers:
                if pid.poll() is None:
                    pid.kill()
            return [], []

    return pid_servers, pid_clients


def plot(start, bw, retransmits, output_path, ebpf=True):

    suffix = "ebpf" if ebpf else "no-ebpf"

    # Bandwidth
    figure_name = "bw_repetita_iperf_%s" % suffix
    fig = plt.figure()
    subplot = fig.add_subplot(111)
    x = [i * float(INTERVALS) for i in range(len(bw))]
    bw = [float(b) / 10**6 for b in bw]

    subplot.step(x, bw, color="#00B0F0", marker="o", linewidth=2.0, where="post",
                 markersize=5, zorder=2)

    subplot.set_xlabel("Time (s)", fontsize=FONTSIZE)
    subplot.set_ylabel("Bandwidth (Mbps)", fontsize=FONTSIZE)
    subplot.set_ylim(bottom=0)
    subplot.set_xlim(left=0, right=MEASUREMENT_TIME)

    print("Save figure for bandwidth")
    fig.savefig(os.path.join(output_path, "%s.pdf" % figure_name),
                bbox_inches='tight', pad_inches=0, markersize=9)
    fig.clf()
    plt.close()

    # Retransmission
    figure_name = "retrans_repetita_iperf_%s" % suffix
    fig = plt.figure()
    subplot = fig.add_subplot(111)

    subplot.step(x, retransmits, color="orangered", marker="s", linewidth=2.0, where="post",
                 markersize=9, zorder=1)

    subplot.set_xlabel("Time (s)", fontsize=FONTSIZE)
    subplot.set_ylabel("Retransmissions", fontsize=FONTSIZE)

    print("Save figure for retransmissions")
    fig.savefig(os.path.join(output_path, "%s.pdf" % figure_name),
                bbox_inches='tight', pad_inches=0, markersize=9)
    fig.clf()
    plt.close()

    print("Saving raw data")
    with open(os.path.join(output_path, "repetita_%s.json" % suffix), "w") as file:
        json.dump({"bw": bw, "retransmits": retransmits, "start": start},
                  file, indent=4)


def eval_albilene(args, ovsschema):
    topo_args = {"schema_tables": ovsschema["tables"], "cwd": args.log_dir,
                 "ebpf_program": os.path.expanduser("~/ebpf_hhf/ebpf_socks_ecn.o"),
                 "always_redirect": True,  # TODO Change to correct ECN parameters
                 "maxseg": 4}
    net = ReroutingNet(topo=Albilene(**topo_args), static_routing=True)
    result_files = []
    tcpdumps = []
    subprocess.call("pkill -9 iperf".split(" "))
    try:
        net.start()
        SR6CLI(net)

        out_prefix = "albilene" + ("-ebpf" if args.ebpf else "")
        tcpdumps = debug_tcpdump(net["client"], "client-eth0", args.log_dir, out_prefix=out_prefix) \
            + debug_tcpdump(net["clientB"], "clientB-eth0", args.log_dir, out_prefix=out_prefix)
        time.sleep(1)

        clients = ["client", "clientB"]
        servers = ["server", "server"]
        result_files = [open("results_%s_%s.json" % (clients[i], servers[i]), "w") for i in range(len(clients))]
        pid_servers, pid_clients = launch_iperf(net, clients, servers, result_files, ebpf=args.ebpf)
        if len(pid_servers) == 0:
            return
        time.sleep(MEASUREMENT_TIME)

        err = False
        for i, pid in enumerate(pid_clients):
            if pid.poll() is None:
                print("The iperf (%s,%s) has not finish yet" % (clients[i], servers[i]))
                err = True
                pid.kill()
                break
            elif pid.poll() != 0:
                print("The iperf (%s,%s) returned with error code %d" % (clients[i], servers[i], pid.poll()))
                err = True
                break

        for pid in pid_servers:
            pid.kill()
    finally:
        for pid in tcpdumps:
            pid.kill()
        net.stop()
        for fileobj in result_files:
            if fileobj is not None:
                fileobj.close()
        subprocess.call("pkill -9 iperf".split(" "))

    if not err:
        # Extract JSON output
        bw = {}
        retrans = {}
        for i in range(len(clients)):
            with open("results_%s_%s.json" % (clients[i], servers[i]), "r") as fileobj:
                results = json.load(fileobj)
                for interval in results["intervals"]:
                    bw.setdefault("%s-%s" % (clients[i], servers[i]), []).append(interval["sum"]["bits_per_second"])
                    retrans.setdefault("%s-%s" % (clients[i], servers[i]), []).append(interval["sum"]["retransmits"])
                start = results["start"]["timestamp"]["timesecs"]

        plot(start, bw["client-server"], retrans["client-server"], args.log_dir, ebpf=args.ebpf)
