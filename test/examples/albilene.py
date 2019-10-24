import os

from srnmininet.srntopo import SRNTopo

from reroutemininet.topo import SRReroutedCtrlDomain


class Albilene(SRNTopo):
    """
                                     +---+
                       +-------------+ B +-------------+
                       |  2ms        +---+             |
                       |                               |
        +--------+   +-+-+   +---+   +---+   +---+   +-+-+   +--------+
        | client +---+ A +---+ C +---+ D +---+ E +---+ F +---+ server |
        +--------+   +---+   +-+-+   +---+   +-+-+   +---+   +--------+
                             | |               |
                             | |               |
                             | +---------------+
                             |
                       +-----+------+
                       | controller |
                       +------------+

    Client and server represents two hosts, the other are routers.
    All the links have an IGP weight of 1.
    Link latencies are set at 1ms except for the latency of (C, E) which has a latency of 5ms.
    """

    def __init__(self, schema_tables=None, link_bandwidth=100, always_redirect=False, rerouting_enabled=True,
                 red_limit=1.0, maxseg=-1, ebpf_program=None, *args, **kwargs):
        """:param schema_tables: The schema table of ovsdb
           :param link_delay: The link delay
           :param link_bandwidth: The link bandwidth
           :param always_redirect: Tune tc parameters such that SRRerouted daemon always chooses to reroute (for debugging)
           :param red_limit: Portion of the link bandwidth that is the limit for RED on SRRerouted daemon
           :param maxseg: Maximum number of segment allowed (-1 or 0 means no limit)
           :param ebpf_program: path to the ebpf program"""
        self.link_delay = "1ms"
        self.link_bandwidth = link_bandwidth
        self.schema_tables = schema_tables if schema_tables else {}
        self.always_redirect = always_redirect
        self.red_limit = red_limit
        self.rerouting_enabled = rerouting_enabled
        self.maxseg = maxseg
        self.ebpf_program = ebpf_program
        self.switch_count = 0
        super(Albilene, self).__init__("controller", *args, **kwargs)

    def build(self, *args, **kwargs):

        # Controllers
        controller = self.addRouter(self.controllers[0])

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
        self.addLink(a, b, link_delay="2ms")
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
                                             rerouted_opts=opts, maxseg=self.maxseg, hosts=[clientA, clientB, serverF],
                                             localctrl_opts={"ebpf_program": self.ebpf_program} if self.ebpf_program else None))

        super(Albilene, self).build(*args, **kwargs)

    def addLink(self, node1, node2, link_delay=None, link_bandwidth=None, **opts):
        link_delay = self.link_delay if link_delay is None else link_delay
        link_bandwidth = self.link_bandwidth if link_bandwidth is None else link_bandwidth

        opts1 = dict(opts)
        try:
            opts1.pop("params2")
        except KeyError:
            pass
        opts2 = dict(opts)
        try:
            opts2.pop("params1")
        except KeyError:
            pass

        if self.isRouter(node1) and self.isRouter(node2):
            # Because of strange behavior between tc and mininet on the sending-side
            # we remove tc on these links
            # source: https://progmp.net/mininetPitfalls.html
            default_params1 = {"bw": link_bandwidth, "enable_ecn": True}
            default_params1.update(opts.get("params1", {}))
            opts1["params1"] = default_params1

            default_params2 = {"bw": link_bandwidth, "enable_ecn": True}
            default_params2.update(opts.get("params2", {}))
            opts2["params2"] = default_params2

            opts1["params2"] = {"delay": link_delay, "max_queue_size": 1000000}
            opts2["params1"] = {"delay": link_delay, "max_queue_size": 1000000}

        # Netem queues might disturb shaping and ecn marking
        # Therefore, we put them on an intermediary switch
        self.switch_count += 1
        s = "s%d" % self.switch_count
        self.addSwitch(s)
        return super(SRNTopo, self).addLink(node1, s, **opts1), super(SRNTopo, self).addLink(s, node2, **opts2)

    def addHost(self, name, **params):
        if self.cwd is not None and "cwd" not in params:
            params["cwd"] = os.path.join(self.cwd, name)
        return super(SRNTopo, self).addHost(name, **params)
