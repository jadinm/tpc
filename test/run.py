import argparse
import datetime
import json
import os
from mininet.log import LEVELS, lg

import ipmininet
from sr6mininet.cli import SR6CLI

from examples.albilene import Albilene
from reroutemininet.net import ReroutingNet
from test import launch_all_tests
from eval import launch_eval, launch_repetita_eval


def mininet_cli(args, ovsschema):
    topo_args = {"schema_tables": ovsschema["tables"], "cwd": args.log_dir}
    net = ReroutingNet(topo=Albilene(**topo_args), static_routing=True)
    try:
        net.start()
        SR6CLI(net)
    finally:
        net.stop()


tests = {
    "mininet-cli": mininet_cli,
    "unit": launch_all_tests,
    "eval": launch_eval,
    "repetita": launch_repetita_eval
}


# Argument parsing

def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('--log', choices=LEVELS.keys(), default='info',
                        help='The level of details in the logs.')
    parser.add_argument('--log-dir', help='Logging directory root',
                        default='/tmp/logs-%s' % datetime.datetime.now().strftime('%Y-%m-%d_%H-%M-%S'))
    parser.add_argument('--src-dir', help='Source directory root of SRN components',
                        default='../srn-dev')
    parser.add_argument('--test', help='Test name to perform', choices=tests,
                        default='mininet-cli')
    parser.add_argument('--repetita-topo', help='Gives the path to a Repetita topology (only for repetita tests)',
                        default=os.path.join(os.path.dirname(os.path.abspath(__file__)), "examples",
                                             "data", "Arpanet_low_latency.graph"))
    return parser.parse_args()


args = parse_args()

with open(os.path.join(args.src_dir, "sr.ovsschema"), "r") as fileobj:
    ovsschema = json.load(fileobj)

lg.setLogLevel(args.log)
if args.log == 'debug':
    ipmininet.DEBUG_FLAG = True
sr_testdns = os.path.join(os.path.abspath(args.src_dir), "bin", "sr-testdns")

# Add SR components to PATH
os.environ["PATH"] = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "bin") + os.pathsep +\
                     os.path.join(os.path.abspath(args.src_dir), "bin") + os.pathsep + os.environ["PATH"]

tests[args.test](args, ovsschema)
