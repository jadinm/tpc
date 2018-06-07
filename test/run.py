#!/usr/bin/python

import argparse
from mininet.log import lg, LEVELS

import ipmininet
from sr6mininet.cli import SR6CLI
from sr6mininet.sr6net import SR6Net
import os
from simple_network import SimpleNet

TOPOS = {
    'simple_network': SimpleNet,
    'simple_static_network': SimpleNet,
}

NET_ARGS = {'simple_static_sr_network': {'static_routing': True}}


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('--topo', choices=TOPOS.keys(),
                        default='simple_static_network',
                        help='The topology that you want to start.')
    parser.add_argument('--log', choices=LEVELS.keys(), default='info',
                        help='The level of details in the logs.')
    parser.add_argument('--args', help='Additional arguments to give'
                                       'to the topology constructor (key=val, key=val, ...)',
                        default='')
    return parser.parse_args()


if __name__ == '__main__':
    args = parse_args()
    lg.setLogLevel(args.log)
    if args.log == 'debug':
        ipmininet.DEBUG_FLAG = True
    kwargs = {}
    for arg in args.args.strip(' \r\t\n').split(','):
        arg = arg.strip(' \r\t\n')
        if not arg:
            continue
        try:
            k, v = arg.split('=')
            kwargs[k] = v
        except ValueError:
            lg.error('Ignoring args:', arg)

    os.environ["PATH"] += os.pathsep + os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "bin")
    print(os.environ["PATH"])
    net = SR6Net(topo=TOPOS[args.topo](**kwargs), **NET_ARGS.get(args.topo, {}))
    try:
        net.start()
        SR6CLI(net)
    finally:
        net.stop()
