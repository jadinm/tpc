
import heapq
import os
from mininet.log import lg

from ipmininet.router.config.base import Daemon
from ipmininet.router.config.utils import template_lookup
from ipmininet.utils import realIntfList
from mako import exceptions as mako_exceptions

template_lookup.directories.append(os.path.join(os.path.dirname(__file__), 'templates'))


class SRRerouted(Daemon):
    """The class representing the sr-rerouted daemon,
    used for redirection via ICMPv6"""

    NAME = 'sr-rerouted'

    def build(self):
        cfg = super(SRRerouted, self).build()
        self._node.sysctl = "net.ipv4.tcp_ecn=1"
        cfg.zlog_cfg_filename = self.zlog_cfg_filename

        cfg.red_limit = self.options.red_limit
        cfg.red_avpkt = self.options.red_avpkt
        cfg.red_probability = self.options.red_probability
        cfg.red_min = self.options.red_min
        cfg.red_max = self.options.red_max
        return cfg

    def set_defaults(self, defaults):
        """:param red_limit: Limit for red (see tc-red(1))
           :param red_avpkt: avpkt for red (see tc-red(1))
           :param red_probability: probability for red (see tc-red(1))
           :param min: min for red (see tc-red(1))
           :param max: max for red (see tc-red(1))"""
        defaults.red_limit = '1000kB'
        defaults.red_avpkt = 100
        defaults.red_probability = 0.1
        defaults.red_min = 500
        defaults.red_max = '2kB'
        super(SRRerouted, self).set_defaults(defaults)

    @property
    def startup_line(self):
        return 'sr-rerouted {cfg}'.format(cfg=self.cfg_filename)

    @property
    def dry_run(self):
        return 'sr-rerouted -d {cfg}'.format(cfg=self.cfg_filename)

    def cleanup(self):
        # Clean firewall and tc rules
        for itf in realIntfList(self._node):
            cmd = 'tc qdisc del dev {itf} root handle 4:'.format(itf=itf.name)
            self._node.pexec(cmd)
        self._node.pexec('ip6tables -D INPUT -m ecn --ecn-ip-ect 3 -j NFQUEUE --queue-num 0')

        try:
            with open(self._file('pid'), 'r') as f:
                pid = int(f.read())
                self._node._processes.call('kill -9 %d ' % pid)
        except (IOError, OSError):
            pass
        super(SRRerouted, self).cleanup()

    @property
    def zlog_cfg_filename(self):
        """Return the filename in which this daemon log rules should be stored"""
        return self._filepath("%s-zlog.cfg" % self.NAME)

    @property
    def zlog_template_filename(self):
        return "zlog.mako"

    def render(self, cfg, **kwargs):

        cfg_content = [super(SRRerouted, self).render(cfg, **kwargs)]

        self.files.append(self.zlog_cfg_filename)
        lg.debug('Generating %s\n' % self.zlog_cfg_filename)
        try:
            cfg["zlog"] = cfg[self.NAME]
            cfg_content.append(template_lookup.get_template(self.zlog_template_filename).render(node=cfg, **kwargs))
        except:
            # Display template errors in a less cryptic way
            lg.error('Couldn''t render a config file(',
                     self.zlog_template_filename, ')')
            lg.error(mako_exceptions.text_error_template().render())
            raise ValueError('Cannot render the rules configuration [%s: %s]' % (
                self._node.name, self.NAME))

        # Firewall rule for netfilter queues
        cmd = 'ip6tables -A INPUT -m ecn --ecn-ip-ect 3 -j NFQUEUE --queue-num 0'
        _, err, exitcode = self._node.pexec(cmd)
        if exitcode != 0:
            raise ValueError('%s: Cannot set firewall rule in %s - cmd "%s" exited with %s' %
                             (self._node.name, self.NAME, cmd, err))

        # ECN marking through red
        for itf in realIntfList(self._node):
            print("Test - " + self._node.cmd('tc qdisc show dev {itf}'.format(itf=itf.name)))  # TODO Remove !! tc must be parent or chile of the other
            cmd = 'tc qdisc add dev {itf} root handle 4: red limit {limit} ' \
                  'avpkt {avpkt} probability {probability} min {min} max {max} ecn'\
                .format(itf=itf.name, limit=cfg[self.NAME].red_limit, avpkt=cfg[self.NAME].red_avpkt,
                        probability=cfg[self.NAME].red_probability, min=cfg[self.NAME].red_min,
                        max=cfg[self.NAME].red_max)
            _, err, exitcode = self._node.pexec(cmd)
            if exitcode != 0:
                raise ValueError('%s: Cannot set the ECN marking in %s - cmd "%s" exited with %s' %
                                 (self._node.name, self.NAME, cmd, err))

        return cfg_content

    def write(self, cfg):

        super(SRRerouted, self).write(cfg[0])
        with open(self.zlog_cfg_filename, 'w') as f:
            f.write(cfg[1])


class IPerf(Daemon):
    """Class to laucnh iperf in daemon mode"""

    NAME = "iperf"

    def render(self, cfg, **kwargs):
        return None

    def write(self, cfg):
        return None

    def build(self):
        cfg = super(IPerf, self).build()

        self.options.mode = "-s" if not self.options.server else "-c"
        self.options.server = "" if not self.options.server else self.get_addr(self._node, self.options.server)

    def set_defaults(self, defaults):
        """:param duration: Length of the iperf3
           :param server: Name of the server node (or None if this is the server-side iperf)"""
        defaults.duration = 300
        defaults.server = None
        super(IPerf, self).set_defaults(defaults)

    @property
    def startup_line(self):
        return 'iperf3 -6 {mode} {server}'.format(duration=self.options.duration,
                                                  mode=self.options.mode,
                                                  server=self.options.server)

    @property
    def dry_run(self):
        return 'true'

    @staticmethod
    def get_addr(base, node_name):
        if base.name == node_name:
            return (base.intf("lo").ip6 or "::1")

        visited = set()
        to_visit = [(1, intf) for intf in realIntfList(base)]
        heapq.heapify(to_visit)

        # Explore all interfaces in base ASN recursively, until we find one
        # connected to the SRN controller.
        while to_visit:
            cost, intf = heapq.heappop(to_visit)
            if intf in visited:
                continue
            visited.add(intf)
            for peer_intf in intf.broadcast_domain.routers:
                if peer_intf.node.name == node_name:
                    ip6s = peer_intf.node.intf("lo").ip6s(exclude_lls=True)
                    for ip6 in ip6s:
                        if ip6.ip.compressed != "::1":
                            return ip6.ip
                    return peer_intf.ip6
                elif peer_intf.node.asn == base.asn or not peer_intf.node.asn:
                    for x in realIntfList(peer_intf.node):
                        heapq.heappush(to_visit, (cost + 1, x))
        return None
