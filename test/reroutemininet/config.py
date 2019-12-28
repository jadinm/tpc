
import heapq
import os
import shlex
import subprocess
import time

from ipmininet.host.config.base import HostDaemon
from ipmininet.utils import realIntfList
from srnmininet.config.config import SRNDaemon, ZlogDaemon, srn_template_lookup
from srnmininet.srnrouter import mkdir_p


__TEMPLATES_DIR = os.path.join(os.path.dirname(__file__), 'templates')
srn_template_lookup.directories.append(__TEMPLATES_DIR)


class SRLocalCtrl(SRNDaemon):
    """The class representing the sr-localctrl daemon
    used on the host to fill eBPF map and reading the database"""

    NAME = 'sr-localctrl'
    KILL_PATTERNS = (NAME,)

    def __init__(self, *args, template_lookup=srn_template_lookup, **kwargs):
        super(SRLocalCtrl, self).__init__(*args,
                                          template_lookup=template_lookup,
                                          **kwargs)
        self.prog_id = -1
        self.files.append(self.ebpf_load_path)
        self.files.append(self.map_path("dest_map_fd"))
        os.makedirs(self._node.cwd, exist_ok=True)

    def set_defaults(self, defaults):
        super(SRLocalCtrl, self).set_defaults(defaults)
        defaults.loglevel = self.DEBUG  # TODO Remove
        defaults.bpftool = os.path.expanduser("~/ebpf_hhf/bpftool")
        defaults.ebpf_program = os.path.expanduser("~/ebpf_hhf/ebpf_socks_ecn.o")  # TODO Change

    @property
    def cgroup(self):
        return "/sys/fs/cgroup/unified/{node}_{daemon}.slice/".format(node=self._node.name, daemon=self.NAME)

    @property
    def ebpf_load_path(self):
        return "/sys/fs/bpf/{node}_{daemon}".format(node=self._node.name, daemon=self.NAME)

    def map_path(self, map_name):
        return self.ebpf_load_path + "_" + map_name

    def render(self, cfg, **kwargs):

        # Load eBPF program

        cmd = "{bpftool} prog load {ebpf_program} {ebpf_load_path} type sockops"\
              .format(bpftool=self.options.bpftool, ebpf_program=self.options.ebpf_program,
                      ebpf_load_path=self.ebpf_load_path)
        print(cmd)
        print(self._node.name)
        subprocess.check_call(shlex.split(cmd))

        # Extract IDs

        time.sleep(1)

        cmd = "{bpftool} prog".format(bpftool=self.options.bpftool)
        print(cmd)
        out = subprocess.check_output(shlex.split(cmd)).decode("utf-8")
        prog_id = -1
        for line in out.split("\n"):
            if "sock_ops" in line:
                prog_id = int(line.split(":")[0])

        cmd = "{bpftool} map".format(bpftool=self.options.bpftool)
        print(cmd)
        out = subprocess.check_output(shlex.split(cmd)).decode("utf-8")
        dest_map_id = -1
        for line in out.split("\n"):
            if "dest_map" in line:
                dest_map_id = int(line.split(":")[0])
        print(dest_map_id)

        # Pin maps to fds

        cmd = "{bpftool} map pin id {dest_map_id} {map_path}".format(bpftool=self.options.bpftool,
                                                                     dest_map_id=dest_map_id,
                                                                     map_path=self.map_path("dest_map"))
        print(cmd)
        subprocess.check_call(shlex.split(cmd))

        # Create cgroup

        mkdir_p(self.cgroup)

        cmd = "{bpftool} cgroup attach {cgroup} sock_ops id {prog_id} multi"\
              .format(bpftool=self.options.bpftool, cgroup=self.cgroup, prog_id=prog_id)
        print(cmd)
        subprocess.check_call(shlex.split(cmd))
        self.prog_id = prog_id

        # Fill config template

        cfg[self.NAME].dest_map_id = dest_map_id
        cfg_content = super(SRLocalCtrl, self).render(cfg, **kwargs)

        return cfg_content

    def cleanup(self):
        if self.prog_id >= 0:
            cmd = "{bpftool} cgroup detach {cgroup} sock_ops id {prog_id} multi".format(bpftool=self.options.bpftool,
                                                                                        cgroup=self.cgroup,
                                                                                        prog_id=self.prog_id)
            print(cmd)
            subprocess.check_call(shlex.split(cmd))
            os.unlink(self.map_path("dest_map"))

        super(SRLocalCtrl, self).cleanup()


class SRRerouted(SRNDaemon):
    """The class representing the sr-rerouted daemon,
    used for redirection via ICMPv6"""

    NAME = 'sr-rerouted'
    KILL_PATTERNS = (NAME,)

    def __init__(self, *args, template_lookup=srn_template_lookup, **kwargs):
        super(SRRerouted, self).__init__(*args,
                                         template_lookup=template_lookup,
                                         **kwargs)

    def build(self):
        cfg = super(SRRerouted, self).build()
        self._node.sysctl = "net.ipv4.tcp_ecn=1"
        self._node.sysctl = "tcp_ecn_fallback=0"

        cfg.red_limit = self.options.red_limit
        cfg.red_avpkt = self.options.red_avpkt
        cfg.red_probability = self.options.red_probability
        cfg.red_min = self.options.red_min
        cfg.red_max = self.options.red_max
        cfg.red_burst = self.options.red_burst
        return cfg

    @property
    def dry_run(self):
        if self.options.rerouting_enabled:
            return super(SRRerouted, self).dry_run
        else:
            return "echo 'Rerouting disabled on node %s'" % self._node.name

    @property
    def startup_line(self):
        if self.options.rerouting_enabled:
            return super(SRRerouted, self).startup_line
        else:
            return "echo 'Rerouting disabled on node %s'" % self._node.name

    def set_defaults(self, defaults):
        """:param red_limit: Limit for red (see tc-red(1)) expressed as a multiplier of the link bandwidth
                             (or 10M if there is no link bandwidth)
           :param red_avpkt: avpkt for red (see tc-red(1))
           :param red_probability: probability for red (see tc-red(1))
           :param red_min: min for red (see tc-red(1)) expressed as a multiplier of red_limit (multiplied by link bandwidth)
                           This value must be '> 0'
           :param red_max: max for red (see tc-red(1)) expressed as a multiplier of red_limit (multiplied by link bandwidth)
           :param red_burst: function computing the burst for red (see tc-red(1))
           :param rerouting_enabled: whether the daemon is actually launched or only the tc and iptable tules are set"""

        defaults.red_limit = 1
        defaults.red_avpkt = 1000
        defaults.red_probability = 0.9
        defaults.red_min = 1/20.
        defaults.red_max = 1/4.
        defaults.red_burst = self.red_burst
        defaults.rerouting_enabled = True
        super(SRRerouted, self).set_defaults(defaults)
        defaults.loglevel = self.DEBUG  # TODO Remove

    @staticmethod
    def red_burst(itf_bw, red_limit, red_avpkt, red_probability, red_min, red_max):
        """Compute the value of the burst as advised by tc-red(1) man page
           :param itf_bw: Bandwidth of the interface (in bytes)
           All the other parameters are the same as those of set_defaults()
        """
        # Man pages say ((2. * red_min + 1. * red_max) / (3. * red_avpkt)) * red_limit * itf_bw + 1
        # but it seems new version of iproute prefers
        # return red_min * red_limit * itf_bw / float(red_avpkt) + 1
        return 1  # TODO Replace by red_min * red_limit * itf_bw / float(red_avpkt) + 1

    def cleanup(self):
        # Clean firewall
        self._node.pexec('ip6tables -D FORWARD -m ecn --ecn-ip-ect 3 -j NFQUEUE --queue-num 0')

        try:
            with open(self._file('pid'), 'r') as f:
                pid = int(f.read())
                self._node._processes.call('kill -9 %d ' % pid)
        except (IOError, OSError):
            pass
        super(SRRerouted, self).cleanup()

    def render(self, cfg, **kwargs):
        cfg_content = super(SRRerouted, self).render(cfg, **kwargs)

        # Firewall rule for netfilter queues
        cmd = 'ip6tables -A FORWARD -m ecn --ecn-ip-ect 3 -j NFQUEUE --queue-num 0'
        _, err, exitcode = self._node.pexec(cmd)
        if exitcode != 0:
            raise ValueError('%s: Cannot set firewall rule in %s - cmd "%s" exited with %s' %
                             (self._node.name, self.NAME, cmd, err))

        # Warning ECN marking should be enabled !

        return cfg_content


class SREndhostd(ZlogDaemon):
    NAME = "sr-endhostd"
    KILL_PATTERNS = (NAME,)

    def __init__(self, *args, template_lookup=srn_template_lookup, **kwargs):
        self.cwd = kwargs.pop("cwd", os.curdir)
        super(SREndhostd, self).__init__(*args,
                                         template_lookup=template_lookup,
                                         **kwargs)

    @property
    def startup_line(self):
        return '{name} {cfg}' \
            .format(name=self.NAME,
                    cfg=self.cfg_filename)

    @property
    def dry_run(self):
        return '{name} -d {cfg}' \
            .format(name=self.NAME,
                    cfg=self.cfg_filename)

    def build(self):
        cfg = super(SREndhostd, self).build()

        cfg.server_addr = "::1"
        server, server_itf = find_node(self._node, self.options.server, lambda x: 1)
        ip6s = server_itf.ip6s(exclude_lls=True)
        for ip6 in ip6s:
            if ip6.ip.compressed != "::1":
                cfg.server_addr = ip6.ip.compressed

        cfg.server_port = self.options.server_port
        cfg.evalfile = self.evalfile()
        return cfg

    def evalfile(self):
        return self._filepath(self._filename("%s.%s.%s" % (self.options.server, self.options.server_port, "eval")))

    def set_defaults(self, defaults):
        """:param server: Server node name
           :param server_port: Server port"""
        defaults.server = "server"
        defaults.server_port = 80
        defaults.routerid = 1
        super(SREndhostd, self).set_defaults(defaults)
        defaults.loglevel = self.DEBUG  # TODO Remove

    def _filepath(self, f):
        return os.path.join(self.cwd, f)


class SRServerd(ZlogDaemon):
    NAME = "sr-serverd"
    KILL_PATTERNS = (NAME,)

    def __init__(self, *args, template_lookup=srn_template_lookup, **kwargs):
        self.cwd = kwargs.pop("cwd", os.curdir)
        super(SRServerd, self).__init__(*args,
                                        template_lookup=template_lookup,
                                        **kwargs)

    @property
    def startup_line(self):
        return '{name} {cfg}' \
            .format(name=self.NAME,
                    cfg=self.cfg_filename)

    @property
    def dry_run(self):
        return '{name} -d {cfg}' \
            .format(name=self.NAME,
                    cfg=self.cfg_filename)

    def build(self):
        cfg = super(SRServerd, self).build()
        cfg.server_port = self.options.server_port
        cfg.evalfile = self.evalfile()
        return cfg

    def evalfile(self):
        return self._filepath(self._filename("%s.%s" % (self.options.server_port, "eval")))

    def set_defaults(self, defaults):
        """:param server_port: Listening port"""
        defaults.server_port = 80
        defaults.cwd = os.curdir
        defaults.routerid = 1
        super(SRServerd, self).set_defaults(defaults)
        defaults.loglevel = self.DEBUG  # TODO Remove

    def _filepath(self, f):
        return os.path.join(self.cwd, f)


class Lighttpd(HostDaemon):
    NAME = 'lighttpd'
    DEPENDS = (SRLocalCtrl,)  # Need to have eBPF loaded before starting
    KILL_PATTERNS = (NAME,)

    def __init__(self, *args, template_lookup=srn_template_lookup, **kwargs):
        super(Lighttpd, self).__init__(*args,
                                       template_lookup=template_lookup,
                                       **kwargs)

    @property
    def startup_line(self):
        return "{name} -D -f {conf}".format(name=self.NAME,
                                            conf=self.cfg_filename)

    @property
    def dry_run(self):
        return "{name} -tt -f {conf}".format(name=self.NAME,
                                             conf=self.cfg_filename)

    def build(self):
        cfg = super(Lighttpd, self).build()
        cfg.web_dir = self.options.web_dir
        cfg.pid_file = self._file(suffix='pid')
        cfg.port = self.options.port
        return cfg

    def render(self, cfg, **kwargs):
        cfg_content = super(Lighttpd, self).render(cfg, **kwargs)
        # Create the big file
        path = os.path.join(self._node.cwd, "mock_file")
        os.makedirs(self._node.cwd, exist_ok=True)
        if not os.path.exists(path):
            with open(path, "w") as fileobj:
                fileobj.write("0" * 10**7)
            self.files.append(path)

        return cfg_content

    def set_defaults(self, defaults):
        """
        :param port: The port on which the daemon listens for HTTP requests
        :param web_dir: The directory of files that can be queried
        """
        defaults.port = 8080
        defaults.web_dir = self._node.cwd
        super(Lighttpd, self).set_defaults(defaults)

    def has_started(self):
        # Try to connect to the server
        _, _, ret = self._node.pexec("nc -z ::1 {port}"
                                     .format(port=self.options.port))
        print(ret)
        return ret == 0


def find_node(start, to_find, cost_intf):
    """
    Find a node by name

    :param start: the start node
    :type start: mininet.node.Node
    :param to_find: the name of the node to find
    :type to_find: str
    :param cost_intf: a function giving the cost of an interface
    :type cost_intf: (mininet.node.IPIntf) -> int

    :return: The node that was found
    :rtype: (mininet.node.Node, mininet.node.IPIntf)
    """
    if start.name == to_find:
        return start, realIntfList(start)[0]

    visited = set()
    to_visit = [(cost_intf(intf), intf) for intf in realIntfList(start)]
    heapq.heapify(to_visit)

    # Explore all interfaces recursively, until we find one
    # connected to the to_find node.
    while to_visit:
        cost, intf = heapq.heappop(to_visit)
        if intf in visited:
            continue
        visited.add(intf)
        for peer_intf in intf.broadcast_domain.interfaces:
            if peer_intf.node.name == to_find:
                return peer_intf.node, peer_intf
            else:
                for x in realIntfList(peer_intf.node):
                    heapq.heappush(to_visit, (cost + cost_intf(x), x))
    return None, None
