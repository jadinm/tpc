import os
import subprocess

from ipmininet.host.config import HostConfig
from ipmininet.router import ProcessHelper
from srnmininet.srnhost import SRNHost

from .config import SRLocalCtrl


class ReroutingHostConfig(HostConfig):

    def build(self):
        self.sysctl = "net.ipv4.tcp_ecn=1"
        self.sysctl = "net.ipv4.tcp_ecn_fallback=0"
        super().build()


class CGroupProcessHelper(ProcessHelper):

    def popen(self, *args, **kwargs):
        """Call a command and return a Popen handle to it.
           If ebpf is the first word of the command, run it in the cgroup in
           the second argument

        :param args: the command + arguments
        :param kwargs: key-val arguments, as used in subprocess.Popen
        :return: a process index in this family"""

        self._pid_gen += 1
        if args[0][0] == "ebpf":
            cgroup = self.node.nconfig.daemon(SRLocalCtrl).cgroup(args[0][1])
            print(cgroup)
            self._processes[self._pid_gen] = self.node \
                .run_cgroup(args[0][2:], cgroup=cgroup, **kwargs)

        self._processes[self._pid_gen] = self.node.popen(*args, **kwargs)
        return self._pid_gen


class ReroutingHost(SRNHost):

    def __init__(self, name, *args, **kwargs):

        super() \
            .__init__(name, process_manager=CGroupProcessHelper, *args,
                      **kwargs)
        os.makedirs(self.cwd, exist_ok=True)

    @property
    def sr_controller(self):
        return self.get('sr_controller', None)

    def run_cgroup(self, cmd, cgroup=None, **kwargs):
        """
        Run asynchronously the command cmd in a cgroup
        """
        if isinstance(cmd, list):
            cmd = " ".join(cmd)
        print("Running '%s' in eBPF" % cmd)
        popen = self.popen(["bash"], stdin=subprocess.PIPE, **kwargs)
        # time.sleep(1)

        if cgroup is None:
            cgroup = self.nconfig.daemon(SRLocalCtrl) \
                .cgroup(SRLocalCtrl.EBPF_PROGRAM)
        os.system('echo %d > %s/cgroup.procs' % (popen.pid, cgroup))
        # time.sleep(1)

        popen.stdin.write(cmd.encode("utf-8"))
        popen.stdin.close()
        return popen
