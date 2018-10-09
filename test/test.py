import argparse
import json
import os
from mininet.log import LEVELS, lg

import ipmininet
from sr6mininet.cli import SR6CLI
from srnmininet.albilene import Albilene

from net import ReroutingNet

components = ["sr-ctrl", "sr-routed", "sr-dnsproxy", "sr-nsd"]


# Argument parsing

def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('--log', choices=LEVELS.keys(), default='info',
                        help='The level of details in the logs.')
    parser.add_argument('--log-dir', help='Logging directory root',
                        default='logs')
    parser.add_argument('--src-dir', help='Source directory root of SR components',
                        default='../srn-dev')
    return parser.parse_args()


args = parse_args()

with open(os.path.join(args.src_dir, "sr.ovsschema"), "r") as fileobj:
    full_schema = json.load(fileobj)

lg.setLogLevel(args.log)
if args.log == 'debug':
    ipmininet.DEBUG_FLAG = True
sr_testdns = os.path.join(os.path.abspath(args.src_dir), "bin", "sr-testdns")

# Add SR components to PATH
os.environ["PATH"] = os.path.join(os.path.abspath(args.src_dir), "bin") + os.pathsep + os.environ["PATH"]

# Flapping link
topo_args = {"schema_tables": full_schema["tables"], "cwd": args.log_dir}
net = ReroutingNet(topo=Albilene(**topo_args), static_routing=True)
try:
    net.start()
    SR6CLI(net)
finally:
    net.stop()
