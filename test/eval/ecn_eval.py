import json
import os
import subprocess
import time
from mininet.log import lg
from shlex import split

import matplotlib.pyplot as plt
from ipmininet.clean import cleanup
from ipmininet.utils import realIntfList
from sr6mininet.cli import SR6CLI
from sr6mininet.examples.ecn_sr_network import ECNSRNet
from sr6mininet.sr6net import SR6Net

INTERVALS = 1
FONTSIZE = 12
CGROUP = "test.slice"
output_path = os.path.dirname(os.path.abspath(__file__))


def run_in_cgroup(node, cmd, **kwargs):
    """
    Run asynchronously the command cmd in a cgroup
    """
    popen = node.popen(split("bash"), stdin=subprocess.PIPE, **kwargs)
    time.sleep(1)

    os.system('echo %d > /sys/fs/cgroup/unified/%s/cgroup.procs' % (popen.pid, CGROUP))
    time.sleep(1)

    popen.stdin.write(bytes(cmd))
    popen.stdin.close()
    return popen


def tcpdump(node, *itfs):
    """
    Run a tcpdump for each interface in itfs
    It returns the list of popen objects matching the tcpdumps
    """
    processes = []
    for itf in itfs:
        # Triggers for Routing Headers
        cmd = "tcpdump -i %s -s 1 -tt ip6 proto 43" % itf
        print(cmd)
        processes.append(node.popen(split(cmd)))
    return processes


def launch(ebpf=True, **kwargs):
    """
    Setup Mininet network and launch test
    """
    lg.setLogLevel("critical")
    cleanup()
    net = SR6Net(topo=ECNSRNet(**kwargs), static_routing=True, allocate_IPs=False)
    pid_client = None
    pid_server = None
    pid_conc_client = None
    pid_conc_server = None
    tcpdump_pids = []
    timestamp_paths = []
    try:
        net.start()

        tcpdump_pids = tcpdump(net["client"], *realIntfList(net["client"]))

        results_path = "/tmp/results.json"
        with open(results_path, "w") as results_file:
            pid_server = net["server"].popen(split("iperf3 -J -s"))
            time.sleep(1)
            if pid_server.poll() is not None:
                print("The server exited too early with err=%s" % pid_server.poll())
                return 0, [], [], []

            pid_conc_server = net["r5"].popen(split("iperf3 -s -p 8000"))
            time.sleep(1)
            if pid_conc_server.poll() is not None:
                print("The concurrent server exited too early with err=%s" % pid_conc_server.poll())
                return 0, [], [], []

            SR6CLI(net)  # TODO Remove

            if ebpf:
                pid_client = run_in_cgroup(net["client"], "iperf3 -J -c fc11::2 -b 10M -t 30 -i %s" % INTERVALS,
                                           stdout=results_file)
            else:
                pid_client = net["client"].popen(split("iperf3 -J -c fc11::2 -b 10M -t 30 -i %s" % INTERVALS),
                                                 stdout=results_file)

            time.sleep(5)

            # Launch the concurrent flow after 5 seconds
            pid_conc_client = net["r3"].popen(split("iperf3 -c fc11::5 -t 100 -p 8000"))
            time.sleep(1)
            if pid_conc_client.poll() is not None:
                print("The concurrent client exited too early with err=%s" % pid_conc_client.poll())
                return 0, [], [], []

            time.sleep(30)

            if pid_client.poll() is None:
                print("The client did not finished after 35 seconds")
                return 0, [], [], []

        # Get packet timestamps for each interface/path
        path = 0
        for pid in tcpdump_pids:
            if pid.poll() is None:
                pid.kill()
            out, _ = pid.communicate()
            lines = out.split("\n")
            with open("/tmp/tcpdump_%s" % pid.pid, "w") as fileobj:
                for line in lines:
                    fileobj.write(line + "\n")
            timestamp_paths.append([float(line.split(" ")[0]) for line in lines if len(line) > 0 and len(line.split(" ")) == 2])
            print("%d packets sent on the path %d" % (len(timestamp_paths), path))
            path += 1

    finally:
        for pid in tcpdump_pids:
            if pid.poll() is None:
                pid.kill()
        net.stop()
        if pid_client is not None and pid_client.poll() is None:
            pid_client.kill()
        if pid_server is not None and pid_server.poll() is None:
            pid_server.kill()
        if pid_conc_client is not None and pid_conc_client.poll() is None:
            pid_conc_client.kill()
        if pid_conc_server is not None and pid_conc_server.poll() is None:
            pid_conc_server.kill()

    start, bw, retransmits = parse_results(results_path)
    return start, bw, retransmits, timestamp_paths


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


def plot(start, bw, retransmits, timestamp_paths, bw_noebpf):

    # Selected path along time

    figure_name = "path_ecn_iperf"
    fig = plt.figure()
    subplot = fig.add_subplot(111)

    timestamps = []
    for path in range(len(timestamp_paths)):
        for t in timestamp_paths[path]:
            timestamps.append([t, path])

    timestamps = sorted(timestamps)
    timestamps = timestamps[20:]  # Ignore control connection
    print(len(timestamps))
    filtered_timestamps = []
    for t, path in timestamps:
        if len(filtered_timestamps) == 0 or filtered_timestamps[-1][1] != path:
            filtered_timestamps.append([t, path])
    if len(filtered_timestamps) >= 1:
        filtered_timestamps.append(timestamps[-1])
    print(filtered_timestamps)

    x_time = []
    y_path = []
    start = filtered_timestamps[0][0]
    for t, path in filtered_timestamps:
        x_time.append((t - start))
        y_path.append(str(path))
    subplot.step(x_time, y_path, color="orangered", marker="o", linewidth=2.0, where="post",
                 markersize=5, zorder=1)

    subplot.set_xlabel("Time (s)", fontsize=FONTSIZE)
    subplot.set_ylabel("Path index", fontsize=FONTSIZE)

    print("Save figure for paths")
    fig.savefig(os.path.join(output_path, "%s.pdf" % figure_name),
                bbox_inches='tight', pad_inches=0, markersize=9)
    fig.clf()
    plt.close()

    # Bandwidth

    figure_name = "bw_ecn_iperf"
    fig = plt.figure()
    subplot = fig.add_subplot(111)
    x = [i * float(INTERVALS) for i in range(len(bw))]
    bw = [float(b) / 10**6 for b in bw]
    bw_noebpf = [float(b) / 10**6 for b in bw_noebpf]

    subplot.step(x, bw, color="#00B0F0", marker="o", linewidth=2.0, where="post",
                 markersize=5, zorder=2, label="with eBPF")
    subplot.step(x, bw_noebpf, color="#009B55", marker="s", linewidth=2.0, where="post",
                 markersize=5, zorder=1, label="without eBPF")
    subplot.legend(loc="best", fontsize=FONTSIZE)

    for i in range(1, len(x_time) - 1):
        subplot.axvline(x=x_time[i], color="orangered", linewidth=2.0, zorder=3)

    subplot.set_xlabel("Time (s)", fontsize=FONTSIZE)
    subplot.set_ylabel("Bandwidth (Mbps)", fontsize=FONTSIZE)
    subplot.set_ylim(bottom=0)
    subplot.set_xlim(left=0, right=30)

    print("Save figure for bandwidth")
    fig.savefig(os.path.join(output_path, "%s.pdf" % figure_name),
                bbox_inches='tight', pad_inches=0, markersize=9)
    fig.clf()
    plt.close()

    figure_name = "bw_no_ebpf_ecn_iperf"
    fig = plt.figure()
    subplot = fig.add_subplot(111)
    subplot.step(x, bw_noebpf, color="#009B55", marker="s", linewidth=2.0, where="post",
                 markersize=5, zorder=1)

    for i in range(1, len(x_time) - 1):
        subplot.axvline(x=x_time[i], color="orangered", linewidth=2.0, zorder=3)

    subplot.set_xlabel("Time (s)", fontsize=FONTSIZE)
    subplot.set_ylabel("Bandwidth (Mbps)", fontsize=FONTSIZE)
    subplot.set_ylim(bottom=0)
    subplot.set_xlim(left=0, right=30)

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
        json.dump({"bw": bw, "retransmits": retransmits, "start": start, "paths": filtered_timestamps},
                  file, indent=4)


# Customize parameters

# Trigger happy ecn
args = {"red_min": 1000, "red_max": 2000, "red_avpkt": 1000, "red_probability": 0.9, "red_burst": 1, "red_limit": 1}
# Mininet configuration of ecn
# args = {"red_min": 30000, "red_max": 35000, "red_avpkt": 1500, "red_probability": 1, "red_burst": 1, "red_limit": 1}
# Custom configuration of ecn
# args = {"red_min": 30000, "red_max": 35000, "red_avpkt": 1500, "red_probability": 1, "red_burst": 1, "red_limit": 1}

print("\n************ Test with ebpf\n")
start_ebpf, bw, retransmits, timestamp_paths = launch(**args)

print("\n************ Test without ebpf\n")
_, no_ebpf_bw, _, _ = launch(ebpf=False, **args)

print("\n************ Plot results\n")
plot(start_ebpf, bw, retransmits, timestamp_paths, no_ebpf_bw)
