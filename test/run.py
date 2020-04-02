import argparse
import datetime
import json
import os

import ipmininet
from mininet.log import LEVELS
import mininet.log
from sr6mininet.cli import SR6CLI

from eval.repetita_eval import eval_repetita
from examples.albilene import Albilene
from reroutemininet.net import ReroutingNet
from test import launch_all_tests


def mininet_cli(lg, args, ovsschema):
    topo_args = {"schema_tables": ovsschema["tables"], "cwd": args.log_dir}
    net = ReroutingNet(topo=Albilene(**topo_args), static_routing=True)
    try:
        net.start()
        SR6CLI(net)
    finally:
        net.stop()


tests = {
    "mininet-cli": mininet_cli,
    # TODO This requires the custom version of scapy on segment-routing organisation
    #  until scapy reaches 2.4.3 (still unstable)
    "unit": launch_all_tests,
    "eval-repetita": eval_repetita
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

mininet.log.lg.setLogLevel(args.log)
if args.log == 'debug':
    ipmininet.DEBUG_FLAG = True
sr_testdns = os.path.join(os.path.abspath(args.src_dir), "bin", "sr-testdns")

# Add SR components to PATH
os.environ["PATH"] = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "bin") + os.pathsep +\
                     os.path.join(os.path.abspath(args.src_dir), "bin") + os.pathsep + os.environ["PATH"]

args.number_tests = int(args.number_tests)
for i in range(args.number_tests):
    if args.number_tests > 1:
        args.log_dir = args.log_dir + "-iter-%d" % i
    tests[args.test](mininet.log.lg, args, ovsschema)
