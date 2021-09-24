import math
import os
import subprocess
import time
from shlex import split

import numpy as np
from ipmininet.utils import realIntfList

TEST_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_CGROUP = "test.slice"
FONTSIZE = 12
LINE_WIDTH = 2.0
MARKER_SIZE = 5.0
FLOWBENDER_MEASUREMENT_TIME = 40
MEASUREMENT_TIME = 100  # Problem if the duration is above 80 seconds for 6 conn
AB_MEASUREMENT_TIME = 10
LOAD_BALANCER_MEASUREMENT_TIME = 10
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


def latexify(fig_width=None, fig_height=None, columns=2):
    """Set up matplotlib's RC params for LaTeX plotting.
    Call this before plotting a figure.

    Parameters
    ----------
    fig_width : float, optional, inches
    fig_height : float,  optional, inches
    columns : {1, 2}
    """

    # code adapted from http://www.scipy.org/Cookbook/Matplotlib/LaTeX_Examples
    # also adapted from http://bkanuka.com/posts/native-latex-plots/

    # Width and max height in inches for IEEE journals taken from
    # computer.org/cms/Computer.org/Journal%20templates/transactions_art_guide.pdf

    from math import sqrt
    import matplotlib

    assert(columns in [1,2])

    if fig_width is None:
        fig_width_pt = 505.89                             # Get this from LaTeX using \the\textwidth
        inches_per_pt = 1.0 / 72.27                      # Convert pt to inch
        scale = 3.39 / 6.9 if columns == 1 else 1
        fig_width = fig_width_pt * inches_per_pt * scale # width in inches
        # fig_width = 3.39 if columns==1 else 6.9 # width in inches

    if fig_height is None:
        golden_mean = (sqrt(5)-1.0)/2.0    # Aesthetic ratio
        fig_height = fig_width*golden_mean # height in inches

    MAX_HEIGHT_INCHES = 8.0
    if fig_height > MAX_HEIGHT_INCHES:
        print("WARNING: fig_height too large {}: so will reduce to {} inches.".format(fig_height, MAX_HEIGHT_INCHES))
        fig_height = MAX_HEIGHT_INCHES

    params = {'backend': 'ps',
              'text.latex.preamble': " ".join([r'\usepackage{libertine}', r'\usepackage[libertine]{newtxmath}', r'\usepackage[T1]{fontenc}', r'\usepackage{gensymb}']),
              'axes.labelsize': 10, # fontsize for x and y labels (was 10)
              'axes.titlesize': 10,
              'font.size': 10, # was 10
              'legend.fontsize': 10, # was 10
              'xtick.labelsize': 10,
              'ytick.labelsize': 10,
              'text.usetex': True,
              'figure.figsize': [fig_width,fig_height],
              'pgf.texsystem': 'pdflatex',
              'grid.alpha': 0.25,
              'mathtext.default': 'regular', # Don't italize math text
              # 'font.family': 'serif'
              }

    matplotlib.rcParams.update(params)
