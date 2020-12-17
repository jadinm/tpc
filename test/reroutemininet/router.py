from ipmininet.router.config import RouterConfig
from ipmininet.router.config.ospf6 import OSPF6RedistributedRoute
from srnmininet.srnrouter import SRNRouter


class ReroutingConfig(RouterConfig):

    def __init__(self, node: 'ReroutingRouter', additional_daemons=(), *args, **kwargs):
        """A simple router made of at least an OSPF daemon

        :param additional_daemons: Other daemons that should be used"""
        # Importing here to avoid circular import
        from ipmininet.router.config.ospf import OSPF
        from srnmininet.config.config import SRNOSPF6, SRCtrl, SRRouted
        # We don't want any zebra-specific settings, so we rely on the OSPF/OSPF6
        # DEPENDS list for that daemon to run it with default settings
        # We also don't want specific settings beside the defaults, so we don't
        # provide an instance but the class instead
        d = []
        if node.use_v4 and not node.static_routing:
            d.append(OSPF)
        if node.use_v6:
            if node.controller:
                if not node.static_routing:
                    d.append((SRNOSPF6, {'ovsdb_adv': True,
                                         'redistribute': [OSPF6RedistributedRoute("connected")]}))
                d.append((SRCtrl, {'extras': {'maxseg': node.maxseg}}))
            elif not node.static_routing:
                d.append((SRNOSPF6, {'redistribute': [OSPF6RedistributedRoute("connected")]}))
            if node.access_router:
                d.append(SRRouted)
        d.extend(additional_daemons)
        super().__init__(node, daemons=d, *args, **kwargs)

    def build(self):
        self.sysctl = "net.ipv4.tcp_ecn=1"
        self.sysctl = "net.ipv4.tcp_ecn_fallback=0"
        # Hash with port numbers as well
        self.sysctl = "fib_multipath_hash_policy=1"
        super().build()


class ReroutingRouter(SRNRouter):

    def __init__(self, name, config=ReroutingConfig, *args, **kwargs):
        super().__init__(name, config=config, *args, **kwargs)

    @property
    def maxseg(self):
        return self.get('maxseg', -1)
