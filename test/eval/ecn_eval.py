import json
import os
import subprocess
import tempfile
import time
from mininet.log import lg
from shlex import split

import matplotlib.pyplot as plt
import psutil
from ipmininet.clean import cleanup
from sr6mininet.cli import SR6CLI
from sr6mininet.examples.ecn_sr_network import ECNSRNet
from sr6mininet.sr6net import SR6Net

FONTSIZE = 12
CGROUP = "test.slice"
output_path = os.path.dirname(os.path.abspath(__file__))


def run_in_cgroup(node, cmd, **kwargs):
    """
    Run asynchronously the command cmd in a cgroup
    """
    popen = node.popen(split("bash"), stdin=subprocess.PIPE, **kwargs)
    parent_pid = psutil.Process(popen.pid).ppid()
    with open("/sys/fs/cgroup/unified/%s/cgroup.procs" % CGROUP, "a") as cgroup_file:
        cgroup_file.write("%d\n" % parent_pid)

    popen.stdin.write(bytes(cmd))
    popen.stdin.close()
    return popen


# Setup Mininet network
def launch(**kwargs):
    """
    Setup Mininet network and launch test
    """
    lg.setLogLevel("critical")
    cleanup()
    net = SR6Net(topo=ECNSRNet(**kwargs), static_routing=True, allocate_IPs=False)
    pid_client = None
    pid_server = None
    try:
        net.start()

        results_path = "/tmp/results.json"
        with open(results_path, "w") as results_file:
            pid_server = net["server"].popen(split("iperf3 -J -s"))
            time.sleep(1)
            if pid_server.poll() is not None:
                print("The server exited too early with err=%s" % pid_server.poll())
                return 0, [], []

            SR6CLI(net)  # TODO Remove

            pid_client = run_in_cgroup(net["client"], "iperf3 -J -c fc11::2 -b 1M",
                                       stdout=results_file)
            time.sleep(15)
            if pid_client.poll() is None:
                print("The client did not finished after 15 seconds")
                return 0, [], []

        res = parse_results(results_path)
    finally:
        net.stop()
        if pid_client is not None and pid_client.poll() is None:
            pid_client.kill()
        if pid_server is not None and pid_server.poll() is None:
            pid_server.kill()
    return res


def parse_results(results_path):
    bw = []
    retransmits = []
    with open(results_path, "r") as results_file:
        results = json.load(results_file)
        for interval in results["intervals"]:
            bw.append(interval["sum"]["bits_per_second"])
            retransmits.append(interval["sum"]["retransmits"])
        start = results["start"]["timestamp"]["timesecs"]
    return start, bw, retransmits


def plot(start, bw, retransmits):
    # Bandwidth

    figure_name = "bw_ecn_iperf"
    fig = plt.figure()
    subplot = fig.add_subplot(111)
    x = [i for i in range(len(bw))]
    bw = [float(b) / 10**6 for b in bw]

    subplot.step(x, bw, color="orangered", marker="s", linewidth=2.0, where="post",
                 markersize=9, zorder=1)

    subplot.set_xlabel("Time (s)", fontsize=FONTSIZE)
    subplot.set_ylabel("Bandwidth (Mbps)", fontsize=FONTSIZE)

    print("Save figure for bandwidth")
    fig.savefig(os.path.join(output_path, "%s.pdf" % figure_name),
                bbox_inches='tight', pad_inches=0, markersize=9)
    fig.clf()
    plt.close()

    # Retransmission

    figure_name = "retrans_ecn_iperf"
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
    with open(os.path.join(output_path, "ecn.json"), "w") as file:
        json.dump({"bw": bw, "retransmits": retransmits, "start": start},
                  file, indent=4)


# Customize parameters
plot(*launch(red_min=1000, red_max=2000, red_avpkt=1000, red_probability=0.9,
             red_burst=1, red_limit=1))
