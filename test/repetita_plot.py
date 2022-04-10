import argparse
import datetime
import os

from mininet.log import LEVELS, lg
from sqlalchemy import or_

from eval.db import get_connection, TCPeBPFExperiment, ShortTCPeBPFExperiment
from eval.plot.delay_exp3 import plot_aggregated_ab_cdfs
from eval.plot.flowbender import plot_flowbender_failure
from eval.utils import latexify
from eval.plot.reverse_srh import bw_over_failure, bw_over_load_balancer

script_dir = os.path.dirname(os.path.abspath(__file__))


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('--log', choices=LEVELS.keys(), default='info',
                        help='The level of details in the logs.')
    parser.add_argument('--out-dir', help='Output directory root',
                        default='/root/graphs-ebpf/%s' % datetime.datetime.now().strftime('%Y-%m-%d_%H-%M-%S'))
    parser.add_argument('--srmip-dir',
                        help='Source directory root all sr-mip optimization',
                        default="/root/maxflow-out")
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    lg.setLogLevel(args.log)
    os.mkdir(args.out_dir)

    db = get_connection(readonly=True)

    experiments = []
    for row in db.query(TCPeBPFExperiment) \
            .filter_by(valid=True, failed=False) \
            .filter(or_(TCPeBPFExperiment.random_strategy == "flowbender",
                        TCPeBPFExperiment.random_strategy == "flowbender_timer")) \
            .order_by(TCPeBPFExperiment.timestamp.desc()):
        # Filter out
        if "path_step_6_access_6" in row.topology \
                or "pcc" in row.congestion_control:
            continue
        experiments.append(row)

    delay_experiments = []
    single_path_delay_experiments = []
    ecmp_delay_experiments = []
    for row in db.query(ShortTCPeBPFExperiment) \
            .filter_by(valid=True, failed=False, max_reward_factor=1) \
            .filter(ShortTCPeBPFExperiment.topology.contains("paths.delays.flap")) \
            .filter(or_(ShortTCPeBPFExperiment.gamma_value == 0.01,
                        ShortTCPeBPFExperiment.gamma_value == 0.1,
                        ShortTCPeBPFExperiment.gamma_value == 0.2)) \
            .order_by(ShortTCPeBPFExperiment.timestamp.desc()):
        if "single.path" in row.topology:
            single_path_delay_experiments.append(row)
        else:
            delay_experiments.append(row)

    latexify(columns=1)

    # Plot reverse SRH experiment results
    bw_over_failure(db, output_path=args.out_dir)
    bw_over_load_balancer(db, output_path=args.out_dir)

    # Plot flow bender reaction to failure
    plot_flowbender_failure(experiments, output_path=args.out_dir, timer_based=True, hotnet_paper=True)
    plot_flowbender_failure(experiments, output_path=args.out_dir, timer_based=False, hotnet_paper=True)

    plot_aggregated_ab_cdfs(delay_experiments, output_path=args.out_dir, hotnet_paper=True, use_cache=True)
