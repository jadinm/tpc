
import os
from mininet.log import lg

from ipmininet.router.config.base import Daemon
from ipmininet.router.config.utils import template_lookup
from ipmininet.utils import realIntfList
from mako import exceptions as mako_exceptions
from srnmininet.config.config import SRNDaemon

template_lookup.directories.append(os.path.join(os.path.dirname(__file__), 'templates'))


class SRRerouted(SRNDaemon):
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
        cfg.red_burst = self.options.red_burst
        return cfg

    def set_defaults(self, defaults):
        """:param red_limit: Limit for red (see tc-red(1)) expressed as a multiplier of the link bandwidth
                             (or 10M if there is no link bandwidth)
           :param red_avpkt: avpkt for red (see tc-red(1))
           :param red_probability: probability for red (see tc-red(1))
           :param red_min: min for red (see tc-red(1)) expressed as a multiplier of red_limit
           :param red_max: max for red (see tc-red(1)) expressed as a multiplier of red_limit
           :param red_burst: function computing the burst for red (see tc-red(1))"""

        defaults.red_limit = 1
        defaults.red_avpkt = 1000
        defaults.red_probability = 0.1
        defaults.red_min = 1/12.
        defaults.red_max = 1/4.
        defaults.red_burst = self.red_burst
        super(SRRerouted, self).set_defaults(defaults)

    @staticmethod
    def red_burst(itf_bw, red_limit, red_avpkt, red_probability, red_min, red_max):
        """Compute the value of the burst as advised by tc-red(1) man page
           :param itf_bw: Bandwidth of the interface (in bytes)
           All the other parameters are the same as those of set_defaults()
        """
        return ((2. * red_min + 1. * red_max) / (3. * red_avpkt)) * red_limit * itf_bw + 1

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

    @property
    def zlog_cfg_filename(self):
        """Return the filename in which this daemon log rules should be stored"""
        return self._filepath("%s-zlog.cfg" % self.NAME)

    @property
    def zlog_template_filename(self):
        return "zlog.mako"

    @staticmethod
    def reconfigure_itf(itf, bw=None, delay=None, jitter=None, loss=None,
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

        # Bandwidth limits via various methods
        bwcmds, parent = itf.bwCmds(bw=bw, speedup=speedup, use_hfsc=use_hfsc, use_tbf=use_tbf,
                                    latency_ms=latency_ms, enable_ecn=enable_ecn, enable_red=enable_red)
        cmds += bwcmds

        # Delay/jitter/loss/max_queue_size using netem
        delaycmds, parent = itf.delayCmds(delay=delay, jitter=jitter, loss=loss, max_queue_size=max_queue_size,
                                          parent=parent)
        cmds += delaycmds

        # Ugly but functional: display configuration info
        stuff = ((['%.2fMbit' % bw] if bw is not None else []) +
                 (['%s delay' % delay] if delay is not None else []) +
                 (['%s jitter' % jitter] if jitter is not None else []) +
                 (['%d%% loss' % loss] if loss is not None else []) +
                 (['ECN'] if enable_ecn else ['RED']
                 if enable_red else []))
        lg.info('(' + ' '.join(stuff) + ') ')

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

        cfg_content = [super(SRRerouted, self).render(cfg, **kwargs)]

        self.files.append(self.zlog_cfg_filename)
        lg.debug('Generating %s\n' % self.zlog_cfg_filename)
        try:
            cfg["zlog"] = cfg[self.NAME]
            cfg_content.append(template_lookup.get_template(self.zlog_template_filename).render(node=cfg, **kwargs))
        except:
            # Display template errors in a less cryptic way
            lg.error('Couldn''t render a reroutemininet file(',
                     self.zlog_template_filename, ')')
            lg.error(mako_exceptions.text_error_template().render())
            raise ValueError('Cannot render the rules configuration [%s: %s]' % (
                self._node.name, self.NAME))

        # Firewall rule for netfilter queues
        cmd = 'ip6tables -A FORWARD -m ecn --ecn-ip-ect 3 -j NFQUEUE --queue-num 0'
        _, err, exitcode = self._node.pexec(cmd)
        if exitcode != 0:
            raise ValueError('%s: Cannot set firewall rule in %s - cmd "%s" exited with %s' %
                             (self._node.name, self.NAME, cmd, err))

        # ECN marking through red
        for itf in realIntfList(self._node):
            parent = self.reconfigure_itf(itf, **itf.params)

            bw = itf.bw if itf.bw > 0 else 10
            bw *= 10**6
            red_limit = cfg[self.NAME].red_limit * bw
            burst = int(cfg[self.NAME].red_burst(bw, cfg[self.NAME].red_limit, cfg[self.NAME].red_avpkt,
                                                 cfg[self.NAME].red_probability, cfg[self.NAME].red_min,
                                                 cfg[self.NAME].red_max))

            cmd = 'tc qdisc add dev {itf} {parent} handle 20: red limit {limit} burst {burst} ' \
                  'avpkt {avpkt} probability {probability} min {min} max {max} bandwidth {bandwidth} ecn'\
                .format(itf=itf.name, limit=red_limit, burst=burst, avpkt=cfg[self.NAME].red_avpkt,
                        probability=cfg[self.NAME].red_probability, min=int(red_limit * cfg[self.NAME].red_min),
                        max=int(red_limit * cfg[self.NAME].red_max), bandwidth=bw, parent=parent)
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
