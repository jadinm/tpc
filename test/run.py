import argparse
import datetime
import json
import os

from ipmininet.cli import IPCLI
from mininet.log import LEVELS
from mininet.log import lg as log

from eval.repetita_eval import eval_repetita, short_flows, \
    short_flows_completion
from examples.repetita_network import RepetitaTopo
from reroutemininet.clean import cleanup
from reroutemininet.config import SRLocalCtrl
from reroutemininet.net import ReroutingNet
from test import launch_all_tests

project_dir = os.path.dirname(os.path.abspath(__file__))


def mininet_cli(lg, args, ovsschema):
    with open(os.path.join(project_dir, "examples/fake_albilene/FakeAlbilene.evensplit.flows")) as fileobj:
        json_demands = json.load(fileobj)

    cleanup()
    topo_args = {"schema_tables": ovsschema["tables"], "cwd": args.log_dir,
                 "repetita_graph": os.path.join(project_dir, "examples/fake_albilene/FakeAlbilene.graph"),
                 "ebpf": args.ebpf, "json_demands": json_demands,
                 "localctrl_opts": {"short_ebpf_program": SRLocalCtrl.SHORT_EBPF_PROGRAM_COMPLETION}}
    net = ReroutingNet(topo=RepetitaTopo(**topo_args), static_routing=True)
    try:
        net.start()
        IPCLI(net)
    finally:
        net.stop()
        cleanup()


tests = {
    "mininet-cli": mininet_cli,
    # TODO This requires the custom version of scapy on segment-routing organisation
    #  until scapy reaches 2.4.3 (still unstable)
    "unit": launch_all_tests,
    "eval-repetita": eval_repetita,
    "short-flows": short_flows,
    "short-flows-completion": short_flows_completion
}

script_dir = os.path.dirname(os.path.abspath(__file__))


# Argument parsing

def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('--log', choices=LEVELS.keys(), default='info',
                        help='The level of details in the logs.')
    parser.add_argument('--log-dir', help='Logging directory root',
                        default='/root/experiences/logs-%s' % datetime.datetime.now().strftime('%Y-%m-%d_%H-%M-%S'))
    parser.add_argument('--src-dir', help='Source directory root of SRN components',
                        default=os.path.join(os.path.dirname(script_dir), 'srn-dev'))
    parser.add_argument('--test', help='Test name to perform', choices=tests,
                        default='mininet-cli')
    parser.add_argument('--repetita-topo', help='Gives the path to a Repetita topology (only for repetita tests)',
                        default=None)
    parser.add_argument('--repetita-dir', help='Gives the path to a Repetita directory (only for repetita tests)',
                        default=None)
    parser.add_argument('--ebpf', action="store_true", help='Use ebpf in the evaluation')
    parser.add_argument('--tcpdump', action="store_true",
                        help='Use tcpdump on each host in the evaluation (only for repetita tests)')
    parser.add_argument('--with-interactive', action="store_true",
                        help='Send interactive following a Zipf law in volume '
                             'while sending iperf traffic in the evaluation.')
    parser.add_argument('--number-tests',
                        help='Repeat test a given number of times',
                        default=1)
    return parser.parse_args()


args = parse_args()

with open(os.path.join(args.src_dir, "sr.ovsschema"), "r") as fileobj:
    ovsschema = json.load(fileobj)

log.setLogLevel(args.log)
sr_testdns = os.path.join(os.path.abspath(args.src_dir), "bin", "sr-testdns")

# Add SR components to PATH
os.environ["PATH"] = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "bin") + os.pathsep + \
                     os.path.join(os.path.abspath(args.src_dir), "bin") + os.pathsep + os.environ["PATH"]

args.number_tests = int(args.number_tests)
log_dir = args.log_dir
for i in range(args.number_tests):
    if args.number_tests > 1:
        args.log_dir = log_dir + "-iter-%d" % i
    tests[args.test](log, args, ovsschema)
