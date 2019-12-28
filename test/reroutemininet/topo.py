import os
import shlex
import subprocess

from srnmininet.config.config import SRCtrlDomain

from .config import SRLocalCtrl
from .host import ReroutingHostConfig
from .router import ReroutingConfig


class SRReroutedCtrlDomain(SRCtrlDomain):

    def __init__(self, access_routers, sr_controller, schema_tables, rerouting_routers, hosts,
                 rerouted_opts=None, maxseg=-1, localctrl_opts=None):
        super(SRReroutedCtrlDomain, self).__init__(access_routers, sr_controller, schema_tables)

        self.nodes.extend(rerouting_routers)
        for n in rerouting_routers:
            self.set_node_property(n, "sr_controller", sr_controller)

        self.nodes.extend(hosts)
        for n in hosts:
            self.set_node_property(n, "sr_controller", sr_controller)

        self.set_node_property(sr_controller, "maxseg", maxseg)

        self.hosts = list(hosts)
        self.rerouting_routers = list(rerouting_routers)
        for node in access_routers:
            if node not in self.rerouting_routers:
                self.rerouting_routers.append(node)

        self.sr_controller = sr_controller
        self.rerouted_opts = rerouted_opts if rerouted_opts is not None else {}
        self.localctrl_opts = localctrl_opts if localctrl_opts is not None else {}

    def load_bpf_programs(self):
        processes = []
        for h in self.hosts:
            # Load eBPF program
            cmd = "{bpftool} prog load {ebpf_program} {ebpf_load_path}" \
                  " type sockops"\
                  .format(bpftool=SRLocalCtrl.BPFTOOL,
                          ebpf_program=SRLocalCtrl.EBPF_PROGRAM,
                          ebpf_load_path=SRLocalCtrl.ebpf_load_path(h))
            print(h + " " + cmd)
            processes.append(subprocess.Popen(shlex.split(cmd),
                                              stdout=subprocess.PIPE,
                                              stderr=subprocess.PIPE))

        failed = False
        for p in processes:
            stdout, stderr = p.communicate()
            p.poll()
            if stdout is not None:
                print(stdout.decode("utf-8"))
            if stderr is not None:
                print(stderr.decode("utf-8"))
            if p.returncode != 0:
                print("ERROR %d while loading the eBPF program" % p.returncode)
                failed = True
                break

        subprocess.call(shlex.split("pkill -9 bpftool"))
        return not failed

    def apply(self, topo):
        """Apply the Overlay properties to the given topology"""
        super(SRReroutedCtrlDomain, self).apply(topo)

        for n in self.rerouting_routers:
            config = topo.nodeInfo(n).get("config", None)
            if not config:
                config = (ReroutingConfig, {})
            if 'additional_daemons' not in config[1]:
                config[1]['additional_daemons'] = []
            if 'rerouting_enabled' not in self.rerouted_opts:
                self.rerouted_opts['rerouting_enabled'] = getattr(topo, 'rerouting_enabled', True)
            # config[1]['additional_daemons'].append((SRRerouted,
            # self.rerouted_opts))
            topo.nodeInfo(n)["config"] = config

        # Load the program concurrently as many times as needed
        # because the verification is a slow process
        if not self.load_bpf_programs():
            raise ValueError("eBPF programs are not loading")

        for h in self.hosts:
            config = topo.nodeInfo(h).get("config", None)
            if not config:
                config = (ReroutingHostConfig, {})
            if 'daemons' not in config[1]:
                config[1]['daemons'] = []
            config[1]['daemons'].append((SRLocalCtrl, self.localctrl_opts))
            topo.nodeInfo(h)["config"] = config
