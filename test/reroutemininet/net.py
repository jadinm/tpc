import mininet.clean
import os
import sys
import time
from mininet.log import lg

from ipmininet.router.config.utils import ConfigDict
from srnmininet.srnnet import SRNNet

from config import SREndhostd, SRServerd


class ReroutingNet(SRNNet):

    def __init__(self, clients=None, servers=None, *args, **kwargs):
        super(ReroutingNet, self).__init__(*args, **kwargs)
        self.clients = clients if clients is not None else []
        self.servers = servers if servers is not None else []
        self._additional_daemons = []

    def ovsdb_node_entry(self, r, ospfv3_id, prefix):
        table, entry = super(ReroutingNet, self).ovsdb_node_entry(r, ospfv3_id, prefix)

        # If this is an access router, the controller has to know
        entry["accessRouter"] = 1 if r.access_router else 0

        return table, entry

    def start_additional_daemon(self, d, node, **kwargs):
        cfg = ConfigDict()
        daemon = d(node, **kwargs)
        cfg[d.NAME] = daemon.build()
        cfg_content = daemon.render(cfg)
        daemon.write(cfg_content)

        out, err, code = node.pexec(*daemon.dry_run.split(' '))
        if code:
            lg.error(d.NAME, 'configuration check failed ['
                             'rcode:', str(code), ']\nstdout:',
                     str(out), '\nstderr:', str(err))
        if code:
            lg.error('Config checks failed, aborting!')
            mininet.clean.cleanup()
            sys.exit(1)

        p = node.popen(*daemon.startup_line.split(' '))
        while not daemon.has_started():
            time.sleep(.001)
        self._additional_daemons.append((daemon, p))

    def activate_ecn(self):
        cmd = "sysctl -w net.ipv4.tcp_ecn=1"
        cmd = cmd.split(" ")
        cmd2 = "sysctl -w net.ipv4.tcp_ecn_fallback=0"
        cmd2 = cmd2.split(" ")
        for host in self.hosts:
            host.cmd(cmd)
            host.cmd(cmd2)
        for router in self.routers:
            router.cmd(cmd)
            router.cmd(cmd2)

    def start(self):
        super(ReroutingNet, self).start()
        self.activate_ecn()

        time.sleep(10)

        port = 50000
        for client in self.clients:
            for server in self.servers:
                path = os.path.join(self.topo.cwd, client, str(port))
                os.makedirs(path)
                self.start_additional_daemon(SREndhostd, self[client], server_port=port, cwd=path)
                path = os.path.join(self.topo.cwd, server, str(port))
                os.makedirs(path)
                self.start_additional_daemon(SRServerd, self[server], server_port=port, cwd=path)
                port += 1

    def eval_files(self):
        return [daemon.evalfile() for daemon, _ in self._additional_daemons if daemon.NAME == SRServerd.NAME]

    def stop(self):
        for d, p in self._additional_daemons:
            d.cleanup()
            try:
                p.terminate()
            except OSError:
                pass  # Process is already dead
        super(ReroutingNet, self).stop()
