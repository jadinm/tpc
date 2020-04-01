import math
import os
import subprocess
import time
from shlex import split

import numpy as np
from ipmininet.utils import realIntfList

DEFAULT_CGROUP = "test.slice"
FONTSIZE = 12
LINE_WIDTH = 2.0
MARKER_SIZE = 5.0
MEASUREMENT_TIME = 30  # Problem if the duration is above 80 seconds for 6 conn
INTERVALS = 1


def run_in_cgroup(node, cmd, cgroup=DEFAULT_CGROUP, **kwargs):
    """
    Run asynchronously the command cmd in a cgroup
    """
    popen = node.popen(split("bash"), stdin=subprocess.PIPE, **kwargs)
    time.sleep(1)

    os.system('echo %d > /sys/fs/cgroup/unified/%s/cgroup.procs' % (popen.pid, cgroup))
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


def debug_tcpdump(node, itf, output_path, out_prefix=""):
    processes = []
    cmd = "tcpdump -i %s -w %s ip6" % (itf, os.path.join(output_path,
                                                         out_prefix + "_" + node.name + "_" + itf + ".pcap"))
    print(cmd)
    processes.append(node.popen(split(cmd)))
    return processes


def get_addr(node):
    try:
        lo_itf = [node.intf('lo')]
    except KeyError:
        lo_itf = []
    for itf in lo_itf + realIntfList(node):
        for ip in itf.ip6s(exclude_lls=True):
            if ip.ip.compressed != "::1":
                return ip.ip.compressed
    return None


def _one_dot_by_instance(bin_edges, cdf, nbr_instances):
    new_bin_edges = []
    new_cdf = []
    i = 0
    for l in np.linspace(0, 1, num=nbr_instances + 1):
        if i == len(cdf):
            break
        new_bin_edges.append(bin_edges[i])
        new_cdf.append(l)
        if math.fabs(cdf[i] - l) <= 10e-6:
            i += 1
    return new_bin_edges, new_cdf


def _histogram_data(bounded_data):
    counts = []
    bin_edges = []
    bounded_data = sorted(bounded_data)
    for i in range(len(bounded_data)):
        if len(bin_edges) != 0 and bin_edges[-1] == bounded_data[i]:
            counts[-1] += 1
        else:
            counts.append(1)
            bin_edges.append(bounded_data[i])
    return counts, bin_edges


def cdf_data(cdf_values, nbr_instances=None):
    data = sorted(cdf_values)

    # Count and filter math.inf
    bounded_data = []
    for value in data:
        if value != math.inf:
            bounded_data.append(value)
    if len(bounded_data) == 0:  # Every demand file was failed
        return None, None

    counts, bin_edges = _histogram_data(bounded_data)
    cdf = np.cumsum(counts)

    cdf = (cdf / cdf[-1]) * (len(bounded_data) / len(data))  # Unsolved instances hurts the cdf
    bin_edges = list(bin_edges)
    bin_edges.insert(0, 0)
    cdf = list(cdf)
    cdf.insert(0, 0)
    if nbr_instances is not None:
        return _one_dot_by_instance(bin_edges, cdf, nbr_instances)
    else:
        return bin_edges, cdf
