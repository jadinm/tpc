from srnmininet.srntopo import SRNTopo
from reroutemininet.topo import SRReroutedCtrlDomain


class Albilene(SRNTopo):
    """
                                     +---+
                       +-------------+ B +-------------+
                       |             +---+             |
                       |                               |
        +--------+   +-+-+   +---+   +---+   +---+   +-+-+   +--------+
        | client +---+ A +---+ C +---+ D +---+ E +---+ F +---+ server |
        +--------+   +---+   +-+-+   +---+   +-+-+   +---+   +--------+
                             | |               |
                             | |      5ms      |
                             | +---------------+
                             |
                       +-----+------+
                       | controller |
                       +------------+

    Client and server represents two hosts, the other are routers.
    All the links have an IGP weight of 1.
    Link latencies are set at 1ms except for the latency of (C, E) which has a latency of 5ms.
    """

    def __init__(self, schema_tables=None, link_bandwidth=100, always_redirect=False, red_limit=1.0, *args, **kwargs):
        """:param schema_tables: The schema table of ovsdb
           :param link_delay: The link delay
           :param link_bandwidth: The link bandwidth
           :param always_redirect: Tune tc parameters such that SRRerouted daemon always chooses to reroute (for debugging)
           :param red_limit: Portion of the link bandwidth that is the limit for RED on SRRerouted daemon"""
        self.link_delay = "1ms"
        self.link_bandwidth = link_bandwidth
        self.schema_tables = schema_tables if schema_tables else {}
        self.always_redirect = always_redirect
        self.red_limit = red_limit

        super(Albilene, self).__init__("controller", *args, **kwargs)

    def build(self, *args, **kwargs):

        # Controllers
        controller = self.addRouter(self.controllers[0], controller=True)

        # Routers
        a = self.addRouter("A")
        b = self.addRouter("B")
        c = self.addRouter("C")
        d = self.addRouter("D")
        e = self.addRouter("E")
        f = self.addRouter("F")

        # Hosts
        clientA = self.addHost("client")
        clientB = self.addHost("clientB")
        serverF = self.addHost("server")

        # Links
        self.addLink(a, b)
        self.addLink(clientB, b)
        self.addLink(c, controller)
        self.addLink(clientA, a)
        self.addLink(a, c)
        self.addLink(c, d)
        self.addLink(d, e)
        self.addLink(c, e)
        self.addLink(e, f)
        self.addLink(f, serverF)
        self.addLink(b, f)

        # SRN overlay
        opts = {}
        if self.always_redirect:  # Force marking of all packets
            opts = {"red_min": 1.0 / self.link_bandwidth, "red_max": 1., "red_probability": 1.}
        else:
            opts = {"red_limit": self.red_limit}
        self.addOverlay(SRReroutedCtrlDomain(access_routers=(a, f, b), sr_controller=controller,
                                             schema_tables=self.schema_tables, rerouting_routers=(c, d, e),
                                             rerouted_opts=opts))

        super(Albilene, self).build(*args, **kwargs)

    def addRouter(self, name, controller=False, **params):
        return super(Albilene, self).addRouter(name, controller, **params)

    def addLink(self, node1, node2, link_delay=None, link_bandwidth=None, **opts):
        link_delay = self.link_delay if link_delay is None else link_delay
        link_bandwidth = self.link_bandwidth if link_bandwidth is None else link_bandwidth

        if self.isRouter(node1) and self.isRouter(node2):
            # Because of strange behavior between tc and mininet on the sending-side
            # we remove tc on these links
            # source: https://progmp.net/mininetPitfalls.html
            default_params1 = {"bw": link_bandwidth, "delay": link_delay}
            default_params1.update(opts.get("params1", {}))
            opts["params1"] = default_params1

            default_params2 = {"bw": link_bandwidth, "delay": link_delay}
            default_params2.update(opts.get("params2", {}))
            opts["params2"] = default_params2

        return super(SRNTopo, self).addLink(node1, node2, **opts)
