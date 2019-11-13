import os
import subprocess
import sys
import time
from operator import attrgetter

import mininet.clean
from ipmininet import DEBUG_FLAG
from ipmininet.router.__router import ProcessHelper
from ipmininet.router.config.base import Daemon
from ipmininet.router.config.utils import ConfigDict
from ipmininet.utils import require_cmd, realIntfList
from mininet.log import lg
from sr6mininet.sr6host import SR6Host
from srnmininet.srnrouter import mkdir_p

from .config import SRLocalCtrl


class HostConfig(object):
    """This class manages a set of daemons, and generates the global
    configuration for a host"""

    def __init__(self, node, daemons=(), sysctl=None,
                 *args, **kwargs):
        """Initialize our config builder

        :param node: The node for which this object will build configurations
        :param daemons: an iterable of active routing daemons for this node
        :param sysctl: A dictionary of sysctl to set for this node.
                       By default, it enables IPv4/IPv6 forwarding on all
                       interfaces."""
        self._node = node  # The node for which we will build the configuration
        self._daemons = {}  # Active daemons
        self.routerid = None
        map(self.register_daemon, daemons)
        self._cfg = ConfigDict()  # Our root config object
        self._sysctl = {}
        if sysctl:
            self._sysctl.update(sysctl)
        super(HostConfig, self).__init__(*args, **kwargs)

    def build(self):
        """Build the configuration for each daemon, then write the
        configuration files"""
        self._cfg.clear()
        self._cfg.name = self._node.name
        # Check that all daemons have their dependencies satisfied
        map(self.register_daemon,
            (c for cls in self._daemons.values()
             for c in cls.DEPENDS if c.NAME not in self._daemons))
        # Build their config
        for name, d in self._daemons.iteritems():
            self._cfg[name] = d.build()
        # Write their config, using the global ConfigDict to handle
        # dependencies
        for d in self._daemons.itervalues():
            cfg = d.render(self._cfg)
            d.write(cfg)

    def cleanup(self):
        """Cleanup all temporary files for the daemons"""
        for d in self._daemons.itervalues():
            d.cleanup()

    def register_daemon(self, cls, **daemon_opts):
        """Add a new daemon to this configuration

        :param cls: Daemon class or object, or a 2-tuple (Daemon, dict)
        :param daemon_opts: Options to set on the daemons"""
        try:
            cls, kw = cls
            daemon_opts.update(kw)
        except TypeError:
            pass
        if cls.NAME in self._daemons:
            return
        if not isinstance(cls, Daemon):
            if issubclass(cls, Daemon):
                cls = cls(self._node, **daemon_opts)
            else:
                raise TypeError('Expected an object or a subclass of '
                                'Daemon, got %s instead' % cls)
        else:
            cls.options.update(daemon_opts)
        self._daemons[cls.NAME] = cls
        require_cmd(cls.NAME, 'Could not find an executable for a daemon!')

    @property
    def sysctl(self):
        """Return an iterator over all sysctl to set on this node"""
        return self._sysctl.iteritems()

    @sysctl.setter
    def sysctl(self, *values):
        """Sets sysctl to particular value.
        :param values: sysctl strings, as `key=val`"""
        for value in values:
            try:
                key, val = value.split('=')
                self._sysctl[key] = val
            except ValueError:
                raise ValueError('sysctl must be specified using `key=val` '
                                 'format. Ignoring %s' % value)

    @property
    def daemons(self):
        return sorted(self._daemons.itervalues(), key=attrgetter('PRIO'))

    def daemon(self, key):
        """Return the Daemon object in this config for the given key
        :param key: the daemon name or a daemon class or instance
        :return the Daemon object
        :raise KeyError: if not found"""
        if not isinstance(key, basestring):
            key = key.NAME
        return self._daemons[key]


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


class ReroutingHost(SR6Host):
    def __init__(self, name, config=ReroutingHostConfig, cwd='/tmp',
                 process_manager=ProcessHelper, *args, **kwargs):
        super(ReroutingHost, self).__init__(name, *args, **kwargs)
        self.cwd = cwd
        mkdir_p(cwd)
        self._old_sysctl = {}
        try:
            self.config = config[0](self, **config[1])
        except (TypeError, IndexError):
            self.config = config(self)
        self._processes = process_manager(self)

    @property
    def sr_controller(self):
        return self.get('sr_controller', None)

    def configDefault(self, **moreParams):
        self.params.update(moreParams)
        r = {}
        self.setParam(r, 'setMAC', mac=self.params.get("mac"))
        self.setParam(r, 'setIP', ip=self.params.get("ip"))
        self.setParam(r, 'setDefaultRoute', defaultRoute=self.params.get("defaultRoute"))
        self.cmd('ifconfig lo ' + self.params.get("lo", "up"))

    def start(self):
        """Start the host: Configure the daemons, set the relevant sysctls,
        and fire up all needed processes"""
        self.cmd('ip', 'link', 'set', 'dev', 'lo', 'up')
        # Build the config
        self.config.build()
        # Check them
        err_code = False
        for d in self.config.daemons:
            out, err, code = self._processes.pexec(*d.dry_run.split(' '))
            err_code = err_code or code
            if code:
                lg.error(d.NAME, 'configuration check failed ['
                                 'rcode:', str(code), ']\n'
                                                      'stdout:', str(out), '\n'
                                                                           'stderr:', str(err))
        if err_code:
            lg.error('Config checks failed, aborting!')
            mininet.clean.cleanup()
            sys.exit(1)
        # Set relevant sysctls
        for opt, val in self.config.sysctl:
            self._old_sysctl[opt] = self._set_sysctl(opt, val)
        # Fire up all daemons
        for d in self.config.daemons:
            self._processes.popen(*d.startup_line.split(' '))
            # Busy-wait if the daemon needs some time before being started
            while not d.has_started():
                time.sleep(.001)

    def terminate(self):
        """Stops this router and sets back all sysctls to their old values"""
        self._processes.terminate()
        if not DEBUG_FLAG:
            self.config.cleanup()
        for opt, val in self._old_sysctl.iteritems():
            self._set_sysctl(opt, val)
        super(ReroutingHost, self).terminate()

    def _set_sysctl(self, key, val):
        """Change a sysctl value, and return the previous set value"""
        val = str(val)
        try:
            v = self._processes.call('sysctl', key) \
                .split('=')[1] \
                .strip(' \n\t\r')
        except IndexError:
            v = None
        if v != val:
            self._processes.call('sysctl', '-w', '%s=%s' % (key, val))
        return v

    def get(self, key, val=None):
        """Check for a given key in the router parameters"""
        return self.params.get(key, val)

    @property
    def asn(self):
        return self.get('asn')

    def run_cgroup(self, cmd, **kwargs):
        """
        Run asynchronously the command cmd in a cgroup
        """
        popen = self.popen(["bash"], stdin=subprocess.PIPE, **kwargs)
        # time.sleep(1)

        cgroup = self.config.daemon(SRLocalCtrl).cgroup
        os.system('echo %d > %s/cgroup.procs' % (popen.pid, cgroup))
        # time.sleep(1)

        popen.stdin.write(bytes(cmd))
        popen.stdin.close()
        return popen
