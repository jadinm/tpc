import os

import numpy as np
from matplotlib import pyplot as plt
from mininet.log import lg

from eval.utils import MARKER_SIZE, FONTSIZE, LINE_WIDTH, cdf_data


def plot_cdf(data, colors, markers, labels, xlabel, figure_name, output_path, xlim_min=None, xlim_max=None, grid=False):
    fig = plt.figure()
    subplot = fig.add_subplot(111)

    min_value = np.inf
    max_value = -np.inf
    for zorder, key in enumerate(data.keys()):
        bin_edges, cdf = cdf_data(data[key])
        if bin_edges is None or cdf is None:
            lg.error("bin_edges or cdf data are None... {bin_edges} - {cdf}\n"
                     .format(bin_edges=bin_edges, cdf=cdf))
            return
        min_value = min(bin_edges[1:] + [min_value])
        max_value = max(bin_edges[1:] + [max_value])

        subplot.step(bin_edges + [max_value * 10 ** 7], cdf + [cdf[-1]],
                     color=colors.get(key), marker=markers.get(key),
                     linewidth=LINE_WIDTH, where="post",
                     markersize=MARKER_SIZE, zorder=zorder, label=labels.get(key))

    subplot.set_xlabel(xlabel, fontsize=FONTSIZE)
    subplot.set_ylabel("CDF (%)", fontsize=FONTSIZE)
    if len(labels) > 0:
        subplot.legend(loc="best")

    lg.info("Saving figure for cdf to path {path}\n"
            .format(path=os.path.join(output_path, figure_name + ".pdf")))

    if xlim_min is not None:
        min_value = xlim_min
    if xlim_max is not None:
        max_value = xlim_max

    if max_value <= min_value:
        xdiff = 0.0
    else:
        xdiff = (max_value - min_value) * 0.1

    xlim_min = min(0.0, min_value - xdiff)
    xlim_max = max_value + xdiff
    if xlim_min != xlim_max:  # To avoid being too near of 0
        subplot.set_xlim(left=xlim_min, right=xlim_max)
    subplot.set_ylim(bottom=0, top=1)
    if grid:
        subplot.grid()
    fig.savefig(os.path.join(output_path, figure_name + ".pdf"),
                bbox_inches='tight', pad_inches=0, markersize=9)
    fig.clf()
    plt.close()


def plot_time(data, ylabel, figure_name, output_path, ylim=None, labels=None,
              colors=None):
    fig = plt.figure()
    subplot = fig.add_subplot(111)

    for key, values in data.items():
        times = []
        data_y = []
        for t, y in values:
            times.append(t)
            data_y.append(y)
        subplot.scatter(times, data_y, marker=".", s=MARKER_SIZE,
                        label=labels.get(key) if labels else key,
                        color=colors.get(key) if colors else None)

    subplot.set_xlabel("time (s)", fontsize=FONTSIZE)
    subplot.set_ylabel(ylabel, fontsize=FONTSIZE)
    if labels is not None:
        subplot.legend(loc="best")

    lg.info("Saving figure for plot through time to path {path}\n"
            .format(path=os.path.join(output_path, figure_name + ".pdf")))

    if ylim is not None:
        subplot.set_ylim(**ylim)
    fig.savefig(os.path.join(output_path, figure_name + ".pdf"),
                bbox_inches='tight', pad_inches=0, markersize=9)
    fig.clf()
    plt.close()


def subplot_time(data, ylabel, figure_name, output_path, ylim=None, labels=None,
                 colors=None):
    fig, axes = plt.subplots(len(data), sharex=True, sharey=True)
    prop_cycle = plt.rcParams['axes.prop_cycle']
    default_colors = prop_cycle.by_key()['color']

    i = 0
    for key, values in data.items():
        i += 1
        subplot = axes[i - 1]
        times = []
        data_y = []
        for t, y in values:
            times.append(t)
            data_y.append(y)
        subplot.scatter(times, data_y, marker=".", s=MARKER_SIZE,
                        color=colors.get(key) if colors else default_colors[i - 1])

        if len(data) == i:
            subplot.set_xlabel("time (s)", fontsize=FONTSIZE)
        elif i == 1:
            subplot.set_title(ylabel, fontsize=FONTSIZE)
        if labels and labels.get(key):
            subplot.set_ylabel(labels.get(key), fontsize=FONTSIZE)

        if ylim is not None:
            subplot.set_ylim(**ylim)

    lg.info("Saving figure for plot through time to path {path}\n"
            .format(path=os.path.join(output_path, figure_name + ".pdf")))
    fig.savefig(os.path.join(output_path, figure_name + ".pdf"),
                bbox_inches='tight', pad_inches=0, markersize=9)
    fig.clf()
    plt.close()
