import os

from sr6mininet.cli import SR6CLI

from examples.albilene import Albilene
from reroutemininet.net import ReroutingNet


def launch_eval(args, ovsschema):
    topo_args = {"schema_tables": ovsschema["tables"],
                 "cwd": os.path.join(args.log_dir, "eval"),
                 "clients": 2}
    net = ReroutingNet(topo=Albilene(**topo_args), static_routing=True, clients=["client"], servers=["server"])
    try:
        net.start()
        SR6CLI(net)
    finally:
        net.stop()
