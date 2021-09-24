import argparse
import datetime
import os
import shutil

from mininet.log import LEVELS, lg

from eval.db import get_connection, TCPeBPFExperiment, ShortTCPeBPFExperiment
from eval.plot.delay_exp3 import plot_ab_cdfs, plot_aggregated_ab_cdfs
from eval.plot.flowbender import plot_flowbender_failure
from eval.utils import latexify
from eval.plot.reverse_srh import bw_over_failure
from explore_data import explore_maxflow_json_files

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
            .filter_by(valid=True, failed=False) \
            .order_by(ShortTCPeBPFExperiment.timestamp.desc()):
        if "single.path" in row.topology:
            single_path_delay_experiments.append(row)
        else:
            delay_experiments.append(row)

    optim_bw_data = explore_maxflow_json_files(args.srmip_dir)

    # Plot reverse SRH experiment results
    bw_over_failure(db, output_path=args.out_dir)

    # Plot flow bender reaction to failure
    # plot_non_aggregated_flowbender_failure(experiments, output_path=args.out_dir)
    # TODO plot_flowbender_failure(experiments, output_path=args.out_dir, timer_based=True)
    # TODO plot_flowbender_failure(experiments, output_path=args.out_dir, timer_based=False)

    # latexify(fig_height=1.9, columns=1)
    # plot_ab_cdfs(delay_experiments, single_path_delay_experiments,
    #              ecmp_delay_experiments, output_path=args.out_dir, hotnet_paper=True)
    plot_aggregated_ab_cdfs(delay_experiments, output_path=args.out_dir, hotnet_paper=False)
    # Plot comparison between ebpf topo or not
    # bw_ebpf_or_no_ebpf_by_topo(keys, args.out_dir)
    """
    plot_stability_by_connection(delay_experiments[:1],
                                 id={"congestion_control": "cubic",
                                     # "gamma_value": 0.5,
                                     "random_strategy": "exp3"})
    """
    # Parse gamma diffs
    # bw_param_influence_by_topo(keys, param_name="gamma_value")
    """
    bw_param_influence_aggregate(experiments, param_name="gamma_value",
                                 id={"congestion_control": "cubic",
                                     # "gamma_value": 0.5,
                                     "random_strategy": "exp3"},
                                 colors={0.1: "springgreen",
                                         0.5: "orangered",
                                         0.9: "violet",
                                         "ECMP": "#00B0F0"},
                                 markers={0.1: ".", 0.5: "o", 0.9: "^",
                                          "ECMP": "s"},
                                 labels={0.1: "TPC $\\Gamma = 0.1$",
                                         0.5: "TPC $\\Gamma = 0.5$",
                                         0.9: "TPC $\\Gamma = 0.9$",
                                         "ECMP": "ECMP"},
                                 # TODO remove max_history
                                 output_path=args.out_dir, max_history=5)

    bw_param_influence_aggregate(experiments, param_name="random_strategy",
                                 id={"congestion_control": "cubic",
                                     "gamma_value": 0.5,
                                     # "random_strategy": "exp3"
                                     },
                                 colors={"uniform": "springgreen",
                                         "exp3": "orangered",
                                         "ECMP": "#00B0F0"},
                                 markers={"uniform": ".",
                                          "exp3": "o",
                                          "ECMP": "s"},
                                 labels={"uniform": "Uniformly random TPC",
                                         "exp3": "TPC with Exp3",
                                         "ECMP": "ECMP"},
                                 # TODO remove max_history
                                 output_path=args.out_dir, max_history=5)

    bw_param_influence_aggregate(experiments, param_name="congestion_control",
                                 id={#"congestion_control": "cubic",
                                     "gamma_value": 0.5,
                                     "random_strategy": "exp3"
                                     },
                                 colors={"cubic": "orangered",
                                         "bbr": "springgreen",
                                         "ECMP": "#00B0F0"},
                                 markers={"cubic": "o",
                                          "bbr": ".",
                                          "ECMP": "s"},
                                 labels={"cubic": "TPC cubic",
                                         "bbr": "TPC bbr",
                                         "ECMP": "ECMP cubic"},
                                 output_path=args.out_dir)

    bw_param_influence_aggregate(experiments, param_name="ebpf",
                                 id={"congestion_control": "cubic",
                                     "gamma_value": 0.5,
                                     "random_strategy": "exp3"
                                     },
                                 colors={True: "orangered",
                                         "ECMP": "#00B0F0"},
                                 markers={True: "o",
                                          "ECMP": "s"},
                                 labels={True: "TPC",
                                         "ECMP": "ECMP"},
                                 output_path=args.out_dir)
    """
    # Parse CC diffs
    # bw_param_influence_by_topo(keys, param_name="congestion_control")

    # Parse rand diffs
    # bw_param_influence_by_topo(keys, param_name="random_strategy")

    # Plot aggregates
    # keys = []
    # for row in db.query(TCPeBPFExperiment.topology,
    #  TCPeBPFExperiment.demands) \
    #         .filter_by(valid=True, failed=False).distinct():
    #     keys.append((row.topology, row.demands))
    # bw_ebpf_or_no_ebpf_aggregate(keys, args.out_dir)
