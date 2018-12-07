
import heapq
import os
from mininet.log import lg

from ipmininet.router.config.base import Daemon
from ipmininet.router.config.utils import template_lookup
from ipmininet.utils import realIntfList
from srnmininet.config.config import SRNDaemon, ZlogDaemon

template_lookup.directories.append(os.path.join(os.path.dirname(__file__), 'templates'))


class SRRerouted(SRNDaemon):
    """The class representing the sr-rerouted daemon,
    used for redirection via ICMPv6"""

    NAME = 'sr-rerouted'

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

    def reconfigure_itf(self, itf, cfg, bw=None, delay=None, jitter=None, loss=None,
                        speedup=0, use_hfsc=False, use_tbf=False,
                        latency_ms=None, enable_ecn=False, enable_red=False,
                        max_queue_size=None, **params):
        """
        This ugly function is needed because Mininet does not store the last tc handle used
        """
        # Clear existing configuration
        tcoutput = itf.tc('%s qdisc show dev %s')
        if "priomap" not in tcoutput and "noqueue" not in tcoutput:
            cmds = ['%s qdisc del dev %s root']
        else:
            cmds = []

        parent = " root "

        # ECN
        bw = itf.bw if itf.bw > 0 else 10
        bw *= 10 ** 6
        red_limit = cfg[self.NAME].red_limit * bw
        burst = int(cfg[self.NAME].red_burst(bw, cfg[self.NAME].red_limit, cfg[self.NAME].red_avpkt,
                                             cfg[self.NAME].red_probability, cfg[self.NAME].red_min,
                                             cfg[self.NAME].red_max))

        # Shaping
        cmds += ['%s qdisc add dev %s {parent} handle 5:0 htb default 1'.format(parent=parent),
                 '%s class add dev %s parent 5:0 classid 5:1 htb ' +
                 'rate %fMbit burst 15k' % (bw / 10**6)]
        parent = ' parent 5:1 '

        cmd = '%s qdisc add dev %s {parent} handle 1: red limit {limit} burst {burst} ' \
              'avpkt {avpkt} probability {probability} min {min} max {max} bandwidth {bandwidth} {ecn}' \
            .format(itf=itf.name, limit=int(red_limit), burst=burst, avpkt=cfg[self.NAME].red_avpkt,
                    probability=cfg[self.NAME].red_probability, min=1000, # TODO replace int(red_limit * cfg[self.NAME].red_min)
                    max=2000, bandwidth=bw, parent=parent, ecn='ecn') # TODO int(red_limit * cfg[self.NAME].red_max)
        parent = " parent 1:1 "
        cmds += [cmd]
        # Delay
        netemargs = '%s%s%s%s' % (
            'delay %s ' % delay if delay is not None else '',
            '%s ' % jitter if jitter is not None else '',
            'loss %d ' % loss if loss is not None else '',
            'limit %d' % max_queue_size if max_queue_size is not None else 'limit 10000000')
        if netemargs:
            cmds += ['%s qdisc add dev %s ' + parent +
                     ' handle 10: netem ' +
                     netemargs]
            parent = ' parent 10:1 '

        # Execute all the commands in our node
        lg.debug("at map stage w/cmds: %s\n" % cmds)
        tcoutputs = [itf.tc(cmd) for cmd in cmds]
        for output in tcoutputs:
            if output != '':
                lg.error("*** Error: %s" % output)
        lg.debug("cmds:", cmds, '\n')
        lg.debug("outputs:", tcoutputs, '\n')

        return parent

    def render(self, cfg, **kwargs):
        cfg_content = super(SRRerouted, self).render(cfg, **kwargs)

        # Firewall rule for netfilter queues
        cmd = 'ip6tables -A FORWARD -m ecn --ecn-ip-ect 3 -j NFQUEUE --queue-num 0'
        _, err, exitcode = self._node.pexec(cmd)
        if exitcode != 0:
            raise ValueError('%s: Cannot set firewall rule in %s - cmd "%s" exited with %s' %
                             (self._node.name, self.NAME, cmd, err))

        # ECN marking through red
        for itf in realIntfList(self._node):
            self.reconfigure_itf(itf, cfg, **itf.params)

        return cfg_content


class IPerf(Daemon):
    """Class to laucnh iperf in daemon mode"""

    NAME = "iperf"

    def render(self, cfg, **kwargs):
        return None

    def write(self, cfg):
        return None

    def build(self):
        cfg = super(IPerf, self).build()

        if not self.options.logobj:
            self.options.logobj = open(self.options.logfile, "a+")

        return cfg

    def set_defaults(self, defaults):
        """:param duration: Length of the iperf3
           :param server: Name of the server node (or None if this is the server-side iperf)"""
        defaults.duration = 300
        defaults.server = None
        super(IPerf, self).set_defaults(defaults)

    @property
    def startup_line(self):
        return 'iperf3 -s  -V -J'

    @property
    def dry_run(self):
        return 'true'

    def cleanup(self):
        if self.options.logobj:
            self.options.logobj.close()
        super(IPerf, self).cleanup()


class SREndhostd(ZlogDaemon):
    NAME = "sr-endhostd"

    def __init__(self, *args, **kwargs):
        self.cwd = kwargs.pop("cwd", os.curdir)
        super(SREndhostd, self).__init__(*args, **kwargs)

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

    def _filepath(self, f):
        return os.path.join(self.cwd, f)


class SRServerd(ZlogDaemon):
    NAME = "sr-serverd"

    def __init__(self, *args, **kwargs):
        self.cwd = kwargs.pop("cwd", os.curdir)
        super(SRServerd, self).__init__(*args, **kwargs)

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

    def _filepath(self, f):
        return os.path.join(self.cwd, f)


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
