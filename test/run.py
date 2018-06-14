#!/usr/bin/python

import argparse
import json
import matplotlib.pyplot as plt
import mininet.clean
import os
import sys
import time
from mininet.log import lg, LEVELS

import ipmininet
from sr6mininet.sr6link import SR6TCIntf
from sr6mininet.sr6net import SR6Net
from sr6mininet.sr6router import SR6Router

from repetita_network import RepetitaNet
from simple_network import SimpleNet

TOPOS = {
    'simple_network': SimpleNet,
    'simple_static_network': SimpleNet,
    'repetita_network': RepetitaNet,
    'repetita_static_network': RepetitaNet
}

NET_ARGS = {'simple_static_network': {'static_routing': True},
            'repetita_static_network': {'static_routing': True}}

iperf_time_limit = 60
iperf_start_limit = 10


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


class NoLogRouter(SR6Router):
    def start(self):
        """Start the router: Configure the daemons, set the relevant sysctls,
        and fire up all needed processes"""
        # Build the config
        self.config.build()
        # Check them
        err_code = False
        for d in self.config.daemons:
            out, err, code = self._processes.pexec(*d.dry_run.split(' '))
            err_code = err_code or code
            if code:
                lg.error(d.NAME, 'configuration check failed [rcode:', str(code),
                         ']\nstdout:', str(out), '\nstderr:', str(err))
        if err_code:
            lg.error('Config checks failed, aborting!')
            mininet.clean.cleanup()
            sys.exit(1)
        # Set relevant sysctls
        for opt, val in self.config.sysctl:
            self._old_sysctl[opt] = self._set_sysctl(opt, val)
        # Fire up all daemons
        for d in self.config.daemons:
            kwargs = {"stdout": d.options.logobj, "stderr": d.options.logobj} if d.options.logobj else {}
            self._processes.popen(*d.startup_line.split(' '), **kwargs)
            # Busy-wait if the daemon needs some time before being started
            while not d.has_started():
                time.sleep(.001)


class SRReroutedNet(SR6Net):

    def __init__(self,
                 router=NoLogRouter,
                 intf=SR6TCIntf,  # TODO Might be needed to change for the red parameters
                 *args, **kwargs):
        self.iperf_clients = []
        super(SRReroutedNet, self).__init__(*args, router=router, intf=intf, **kwargs)

    def launch_iperf_clients(self):
        for i in range(0, len(self.routers), 2):
            if i == len(self.routers) - 1:
                pass
            router_src = self.routers[i]
            router_dst = self.routers[i+1]
            ip6_addr = [ip6.ip.compressed for ip6 in router_dst.intf('lo').ip6s(exclude_lls=True)
                        if ip6.ip.compressed != "::1"][0]
            self.iperf_clients.append(router_src.popen(("iperf3 -6 --get-server-out -V -J"
                                                        " -t {iperf_time_limit} -O {iperf_start_limit} -c {addr}"
                                                        .format(iperf_time_limit=iperf_time_limit,
                                                                iperf_start_limit=iperf_start_limit,
                                                                addr=ip6_addr))
                                                       .split(" ")))

    def parse_iperf_outputs(self):
        iperf_jsons = [json.loads(iperf.communicate()[0].decode("utf-8")) for iperf in self.iperf_clients]
        iperf_intervals = [[(interval["sum"]["bytes"] / (float(10**6)))
                            for interval in iperf_json["intervals"] if not interval["sum"]["omitted"]]
                           for iperf_json in iperf_jsons]
        x = range(len(iperf_intervals[0]))
        y = []
        for i in x:
            network_mb = 0.0
            for interval in iperf_intervals:
                network_mb += interval[i]
            y.append(network_mb)
        # TODO If maxflow is known, the percentage of usage would be better to set in 'y'

        fig1 = plt.figure()
        subplot = fig1.add_subplot(111)
        subplot.plot(x, y, 'go--', linewidth=2, markersize=12)
        subplot.set_xlim((0, x[-1] + 5))
        subplot.set_xlabel("Time (sec)")
        subplot.set_ylim((0, max(y) + 2))
        subplot.set_ylabel("Network traffic (MB)")
        subplot.set_title("%s traffic usage" % (str(self.topo)))
        fig1.savefig(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                  "network_usage_%s.png" % os.path.basename(str(self.topo))))
        fig1.clf()

    def remove_iperf_clients(self):
        for iperf_client in self.iperf_clients:
            try:
                iperf_client.kill()
            except OSError:  # Already finished
                pass
        self.iperf_clients = []

    def stop(self):
        self.remove_iperf_clients()
        super(SRReroutedNet, self).stop()


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
    net = SRReroutedNet(topo=TOPOS[args.topo](**kwargs), **NET_ARGS.get(args.topo, {}))
    try:
        net.start()
        time.sleep(5)
        lg.info("*** Starting IPerf clients\n")
        net.launch_iperf_clients()
        time.sleep(iperf_time_limit)
        lg.info("*** Collecting IPerf results\n")
        net.parse_iperf_outputs()
    finally:
        net.stop()
