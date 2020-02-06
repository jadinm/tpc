
import os
import string

from srnmininet.srntopo import SRNTopo

from reroutemininet.config import Lighttpd
from reroutemininet.host import ReroutingHostConfig
from reroutemininet.topo import SRReroutedCtrlDomain

MAX_QUEUE = 1000000000


class RepetitaEdge:

    def __init__(self, label, src, dest, weight, bw, delay):
        self.label = label
        self.src = int(src)
        self.dest = int(dest)

        self.weight_src = int(weight)
        self.bw_src = int(int(bw) / 10**3)  # Mbps
        self.delay_src = int(delay)

        self.weight_dst = -1
        self.bw_dst = -1
        self.delay_dst = -1

    # This enables merging edges in the same direction
    def __eq__(self, other):
        return (self.src == other.src or self.src == other.dest) and (self.dest == other.dest or self.dest == other.src)

    def __hash__(self):
        return self.src + self.dest

    def merge_directed_edge(self, other):
        if self.src == other.src and self.dest == other.dest:
            self.weight_src = min(other.weight_src, self.weight_src)
            self.bw_src = other.bw_src + self.bw_src
            self.delay_src = min(other.delay_src, self.delay_src)

        elif self.dest == other.src and self.src == other.dest:
            self.weight_dst = other.weight_src
            self.bw_dst = other.bw_src
            self.delay_dst = other.delay_src

    def complete_edge(self):
        return self.weight_src > 0 and self.bw_src > 0 and self.delay_src > 0 and self.weight_dst > 0 and \
               self.bw_dst > 0 and self.delay_dst > 0

    def add_to_topo(self, topo, node_index):
        if not self.complete_edge():
            raise Exception("Only partial information: " + str(self))
        bw_src = self.bw_src if topo.bw is None else topo.bw
        bw_dst = self.bw_dst if topo.bw is None else topo.bw
        print("Link between %s and %s" % (node_index[self.src], node_index[self.dest]))
        return topo.addLink(node_index[self.src], node_index[self.dest],
                            params1={"bw": bw_src,
                                     "delay": str(self.delay_src) + "ms",
                                     "igp_weight": self.weight_src},
                            params2={"bw": bw_dst,
                                     "delay": str(self.delay_dst) + "ms",
                                     "igp_weight": self.weight_dst})

    def __str__(self):
        return "<Edge %s (%s to %s) params_src (%s %s %s) params_dest (%s %s %s)>" %\
               (self.label, self.src, self.dest,
                self.weight_src, self.bw_src, self.delay_src,
                self.weight_dst, self.bw_dst, self.delay_dst)


class RepetitaTopo(SRNTopo):

    def __init__(self, repetita_graph=None, schema_tables=None,
                 rerouting_enabled=True, bw=None, ebpf=True, json_demands=(),
                 *args, **kwargs):
        self.repetita_graph = repetita_graph
        self.schema_tables = schema_tables
        self.rerouting_enabled = rerouting_enabled
        self.bw = bw
        self.switch_count = 1
        self.router_indices = []
        self.ebpf = ebpf
        self.json_demands = json_demands
        super(RepetitaTopo, self).__init__("controller", *args, **kwargs)

    def getFromIndex(self, idx):
        """
        Get Node name that was at index idx
        :param idx: The index of the node in the Repetita file
        :return: The string name of the router
        """
        return self.router_indices[idx] if idx < len(self.router_indices) else None

    def label2node(self, label):
        node_name = ""
        for i in range(len(label)):
            if len(node_name) == 9:
                break
            if label[i] in string.ascii_letters or label[i] in "-_" or label[i] in string.digits:
                node_name = node_name + label[i]
        return node_name

    def build(self, *args, **kwargs):
        """
        The network is generated from the graphs in the file at path 'repetita_graph'
        The input format is described at https://github.com/svissicchio/Repetita/wiki/Adding-Problem-Instances#topology-format
        """
        node_index = []
        edge_dict = {}
        access_routers = []
        with open(self.repetita_graph) as fileobj:
            nbr_nodes = int(fileobj.readline().split(" ")[1]) # NODES XXX
            fileobj.readline()  # label x y
            for i in range(nbr_nodes):
                label, _, _ = fileobj.readline().split(" ")  # Node line
                router = self.addRouter(self.label2node(label))  # Interface names are at max 15 characters (NULL not included)
                self.router_indices.append(self.label2node(label))  # Interface names are at max 15 characters (NULL not included)
                for d in self.json_demands:  # Access routers only for flows
                    if (d["src"] == i or d["dest"] == i) \
                            and router not in access_routers:
                        access_routers.append(router)
                        break
                node_index.append(router)
            print(self.router_indices)

            fileobj.readline()  # Empty line
            nbr_edges = int(fileobj.readline().split(" ")[1])  # EDGES XXX
            fileobj.readline()  # label src dest weight bw delay
            for i in range(nbr_edges):
                label, src, dest, weight, bw, delay = fileobj.readline().split(" ")  # Edge line
                edge = RepetitaEdge(label, src, dest, weight, bw, delay)
                if edge in edge_dict:
                    edge_dict[edge].merge_directed_edge(edge)
                else:
                    edge_dict[edge] = edge

            for edge in edge_dict.keys():
                edge.add_to_topo(self, node_index)

        # We consider that access routers have minimum two links
        print(access_routers)
        for access_router in access_routers:
            h = self.addHost("h%s" % self.label2node(access_router))  # Interface names are at max 15 characters (NULL not included)
            self.addLink(h, access_router)

        # Add controller
        routers = self.routers()
        controller = self.addRouter("controller")
        # Be sure that this is not the bottleneck link (i.e, 100Gbps, 1ms)
        self.addLink(routers[0], controller, delay="1ms", bw=10**5)

        # Configure SRN with rerouting
        if self.ebpf:
            self.addOverlay(SRReroutedCtrlDomain(access_routers=[router for router in access_routers],
                                                 sr_controller=controller, schema_tables=self.schema_tables,
                                                 rerouting_routers=routers, hosts=self.hosts()))

        super(RepetitaTopo, self).build(*args, **kwargs)

    def __str__(self):
        return "RepetitaNetwork %s" % os.path.basename(self.repetita_graph)

    def addLink(self, node1, node2, delay="1ms", bw=None, **opts):
        src_delay = None
        dst_delay = None
        opts1 = dict(opts)
        try:
            opts1.pop("params2")
            src_delay = opts.get("params1", {}).pop("delay")
        except KeyError:
            pass
        opts2 = dict(opts)
        try:
            opts2.pop("params1")
            dst_delay = opts.get("params2", {}).pop("delay")
        except KeyError:
            pass

        src_delay = src_delay if src_delay else delay
        dst_delay = dst_delay if dst_delay else delay

        if self.isRouter(node1) and self.isRouter(node2):
            # Because of strange behavior between tc and mininet on the sending-side
            # we remove tc on these links
            # source: https://progmp.net/mininetPitfalls.html
            print(opts)
            default_params1 = {"bw": bw, "enable_ecn": True}
            default_params1.update(opts.get("params1", {}))
            opts1["params1"] = default_params1
            # opts1["params1"]["delay"] = "5ms"
            # opts1["params1"]["max_queue_size"] = MAX_QUEUE

            default_params2 = {"bw": bw, "enable_ecn": True}
            default_params2.update(opts.get("params2", {}))
            opts2["params2"] = default_params2
            # opts2["params2"]["delay"] = "5ms"
            # opts2["params2"]["max_queue_size"] = MAX_QUEUE

            opts1["params2"] = {"delay": dst_delay, "max_queue_size": MAX_QUEUE}
            opts2["params1"] = {"delay": src_delay, "max_queue_size": MAX_QUEUE}

        # Netem queues might disturb shaping and ecn marking
        # Therefore, we put them on an intermediary switch
        self.switch_count += 1
        s = "s%d" % self.switch_count
        self.addSwitch(s)
        return super(SRNTopo, self).addLink(node1, s, **opts1), super(SRNTopo, self).addLink(s, node2, **opts2)

    def addHost(self, name, **params):
        if self.cwd is not None and "cwd" not in params:
            params["cwd"] = os.path.join(self.cwd, name)
        h = super(SRNTopo, self).addHost(name, config=ReroutingHostConfig, **params)
        h.addDaemon(Lighttpd)  # Launch an HTTP server on each node
        return h
