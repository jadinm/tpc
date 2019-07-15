import json
import os
import subprocess
import time
from mininet.log import lg
from shlex import split

import matplotlib.pyplot as plt
from ipmininet.clean import cleanup
from ipmininet.utils import realIntfList
from sr6mininet.examples.delay_sr_network import DelaySRNet
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


def debug_tcpdump(node, itf, out_prefix=""):
    processes = []
    cmd = "tcpdump -i %s -w %s ip6" % (itf, os.path.join(output_path, out_prefix + "_" + node.name + "_" + itf + ".pcap"))
    print(cmd)
    processes.append(node.popen(split(cmd)))
    return processes


def launch_iperf(net, ebpf=True):
    try:
        subprocess.check_call(split("pkill iperf3"))
    except subprocess.CalledProcessError:
        pass

    if ebpf:
        pid_server = net["server"].popen(split("iperf3 -J -s"))
    else:
        pid_server = net["r5"].popen(split("iperf3 -J -s"))
    time.sleep(1)
    if pid_server.poll() is not None:
        print("The server exited too early with err=%s" % pid_server.poll())
        return []

    if ebpf:
        pid_conc_server = net["server"].popen(split("iperf3 -J -s -p 8000"))
    else:
        pid_conc_server = net["r8"].popen(split("iperf3 -J -s -p 8000"))
    time.sleep(1)
    if pid_conc_server.poll() is not None:
        print("The concurrent server exited too early with err=%s" % pid_conc_server.poll())
        return [pid_server]

    if ebpf:
        pid_client = run_in_cgroup(net["client"], "iperf3 -J -c fc11::2 -t 1000 -B 2042:16::1")
    else:
        pid_client = net["client"].popen(split("iperf3 -J -c fc11::5 -t 1000 -B fc11::1"))

    time.sleep(1)

    if pid_client.poll() is not None:
        print("The client exited too early with err=%s" % pid_client.poll())
        return [pid_server, pid_conc_server]

    if ebpf:
        pid_conc_client = run_in_cgroup(net["client"], "iperf3 -J -c fc11::2 -t 1000 -p 8000 -B 2042:16::1")
    else:
        pid_conc_client = net["client"].popen(split("iperf3 -J -c fc11::8 -t 1000 -p 8000 -B fc11::1"))

    time.sleep(1)
    if pid_conc_client.poll() is not None:
        print("The concurrent client exited too early with err=%s" % pid_conc_client.poll())
        return [pid_server, pid_conc_server, pid_client]

    return [pid_server, pid_conc_server, pid_client, pid_conc_client]


def launch_apache_benchmark(net, ebpf=True):
    try:
        subprocess.check_call(split("pkill lighttpd"))
    except subprocess.CalledProcessError:
        pass
    try:
        subprocess.check_call(split("pkill ab"))
    except subprocess.CalledProcessError:
        pass

    ab_pid = None
    results_path = None
    try:
        lighttpd_conf = """
server.document-root = "/tmp" 
dir-listing.activate = "enable"
server.pid-file      = "/var/run/lighttpd.pid"
server.port          = 8080
server.bind          = "[::]"
"""
        lighttpd_conf_file = "/tmp/lighttpd.conf"
        with open(lighttpd_conf_file, "w") as fileobj:
            fileobj.write(lighttpd_conf)

        if ebpf:
            http_server = run_in_cgroup(net["client"], "lighttpd -f " + lighttpd_conf_file)
        else:
            http_server = net["client"].popen(split("lighttpd -f " + lighttpd_conf_file))

        time.sleep(1)
        try:
            subprocess.check_call(split("pgrep lighttpd"))
        except subprocess.CalledProcessError:
            print("Lighttpd exited too early with err=%s" % http_server.poll())
            return None

        with open("/tmp/file_1k", "w") as fileobj:
            fileobj.write("0" * 1000)

        results_path = "/tmp/results.csv"
        cmd = "ab -k -n 80 -e {results_path} -B 2042:52::2 http://[2042:13::1]:8080/file_1k"\
              .format(results_path=results_path)
        print(cmd)
        # SR6CLI(net)  # TODO remove
        print(net["server"].cmd(split(cmd)))

    finally:
        try:
            subprocess.check_call(split("pkill lighttpd"))
        except subprocess.CalledProcessError:
            pass
        if ab_pid and ab_pid.poll() is None:
            ab_pid.kill()

    return results_path


def launch(ebpf=True, capture=False, debug=False, **kwargs):
    """
    Setup Mininet network and launch test
    """
    lg.setLogLevel("critical")
    cleanup()
    net = SR6Net(topo=DelaySRNet(**kwargs), static_routing=True, allocate_IPs=False)
    pid_client = None
    pid_server = None
    pid_conc_client = None
    pid_conc_server = None
    tcpdump_pids = []
    tcpdump_debug_pids = []
    timestamp_paths = []
    iperf_pids = []
    try:
        net.start()

        tcpdump_pids = tcpdump(net["client"], *realIntfList(net["client"])) if capture else []
        tcpdump_debug_pids = debug_tcpdump(net["server"], "server-eth0", "ebpf" if ebpf else "no-ebpf") if debug else []
        tcpdump_debug_pids = debug_tcpdump(net["client"], "client-eth0", "ebpf" if ebpf else "no-ebpf") if debug else []

        iperf_pids = launch_iperf(net, ebpf=ebpf)

        time.sleep(5)

        results_path = launch_apache_benchmark(net, ebpf=ebpf)
        if results_path is None:
            return [], [], []

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
        for pid in tcpdump_pids + tcpdump_debug_pids:
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
        for pid in iperf_pids:
            if pid.poll() is None:
                pid.kill()

    print(results_path)
    percentages, delay = parse_results(results_path)
    return percentages, delay, timestamp_paths


def parse_results(results_path):
    percentages = []
    delay = []
    with open(results_path, "r") as results_file:
        next(results_file)
        for line in results_file:
            p, d = line.split(",")
            p = float(p)
            d = float(d[:-1])
            percentages.append(p)
            delay.append(d)
    return ([0.0] + percentages[1:]), ([0.0] + delay[1:])


def plot(percentages, delay, timestamp_paths, delay_noebpf):

    # Delay distribution

    figure_name = "delay_ab"
    fig = plt.figure()
    subplot = fig.add_subplot(111)

    subplot.step(delay, percentages, color="#00B0F0", marker="o", linewidth=2.0, where="post",
                 markersize=5, zorder=2, label="with eBPF")
    subplot.step(delay_noebpf, percentages, color="#009B55", marker="s", linewidth=2.0, where="post",
                 markersize=5, zorder=1, label="without eBPF")
    subplot.legend(loc="best", fontsize=FONTSIZE)

    subplot.set_xlabel("Request completion time (ms)", fontsize=FONTSIZE)
    subplot.set_ylabel("CDF", fontsize=FONTSIZE)
    subplot.set_ylim(bottom=0, top=100)
    subplot.set_xlim(left=0)

    print("Save figure for delay distribution")
    fig.savefig(os.path.join(output_path, "%s.pdf" % figure_name),
                bbox_inches='tight', pad_inches=0, markersize=9)
    fig.clf()
    plt.close()

    print("Saving raw data")
    with open(os.path.join(output_path, "mices.json"), "w") as fileobj:
        json.dump({"delay": delay, "delay no ebpf": delay_noebpf}, fileobj, indent=4)


# Customize parameters

print("\n************ Test with ebpf\n")
p, d, t_paths = launch(debug=False)

print("\n************ Test without ebpf\n")
_, d_noebpf, _ = launch(ebpf=False)

print("\n************ Plot results\n")
plot(p, d, t_paths, d_noebpf)
