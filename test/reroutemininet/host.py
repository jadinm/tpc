import os
import subprocess

from ipmininet.host.config import HostConfig
from ipmininet.router import ProcessHelper
from ipmininet.utils import realIntfList
from sr6mininet.sr6host import SR6Host

from .config import SRLocalCtrl


class SR6HostConfig(HostConfig):

    def build(self):
        self.sysctl = "net.ipv6.conf.all.seg6_enabled=1"
        self.sysctl = "net.ipv6.conf.default.seg6_enabled=1"
        for intf in realIntfList(self._node):
            self.sysctl = "net.ipv6.conf.%s.seg6_enabled=1" % intf.name
        super(SR6HostConfig, self).build()


class ReroutingHostConfig(SR6HostConfig):

    def build(self):
        self.sysctl = "net.ipv4.tcp_ecn=1"
        self.sysctl = "net.ipv4.tcp_ecn_fallback=0"
        super(ReroutingHostConfig, self).build()


class CGroupProcessHelper(ProcessHelper):
    pass


class ReroutingHost(SR6Host):

    def __init__(self, name, *args, **kwargs):

        super(ReroutingHost, self)\
            .__init__(name, process_manager=CGroupProcessHelper, *args,
                      **kwargs)
        os.makedirs(self.cwd, exist_ok=True)

    @property
    def sr_controller(self):
        return self.get('sr_controller', None)

    def run_cgroup(self, cmd, **kwargs):
        """
        Run asynchronously the command cmd in a cgroup
        """
        if isinstance(cmd, list):
            cmd = " ".join(cmd)
        print("Running '%s' in eBPF" % cmd)
        popen = self.popen(["bash"], stdin=subprocess.PIPE, **kwargs)
        # time.sleep(1)

        cgroup = self.nconfig.daemon(SRLocalCtrl).cgroup
        os.system('echo %d > %s/cgroup.procs' % (popen.pid, cgroup))
        # time.sleep(1)

        popen.stdin.write(cmd.encode("utf-8"))
        popen.stdin.close()
        return popen
