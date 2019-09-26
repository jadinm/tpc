import os
import subprocess
import time
from shlex import split

from ipmininet.utils import realIntfList

DEFAULT_CGROUP = "test.slice"


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
