
import os

from srnmininet.srntopo import SRNTopo

from reroutemininet.topo import SRReroutedCtrlDomain


class RepetitaEdge:

    def __init__(self, label, src, dest, weight, bw, delay):
        self.label = label
        self.src = int(src)
        self.dest = int(dest)

        self.weight_src = int(weight)
        self.bw_src = int(min(int(bw)/10**6, 10))  # Mbps
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
        return topo.addLink(node_index[self.src], node_index[self.dest],
                            params1={"bw": self.bw_src,
                                     "delay": str(self.delay_src) + "ms",
                                     "igp_weight": self.weight_src},
                            params2={"bw": self.bw_dst,
                                     "delay": str(self.delay_dst) + "ms",
                                     "igp_weight": self.weight_dst})

    def __str__(self):
        return "<Edge %s (%s to %s) params_src (%s %s %s) params_dest (%s %s %s)>" %\
               (self.label, self.src, self.dest,
                self.weight_src, self.bw_src, self.delay_src,
                self.weight_dst, self.bw_dst, self.delay_dst)


class RepetitaTopo(SRNTopo):

    def __init__(self, repetita_graph=None, schema_tables=None, *args, **kwargs):
        self.repetita_graph = repetita_graph
        self.schema_tables = schema_tables
        super(RepetitaTopo, self).__init__("controller", *args, **kwargs)

    def build(self, *args, **kwargs):
        """
        The network is generated from the graphs in the file at path 'repetita_graph'
        The input format is described at https://github.com/svissicchio/Repetita/wiki/Adding-Problem-Instances#topology-format
        """
        node_index = []
        edge_dict = {}
        access_routers = {}
        with open(self.repetita_graph) as fileobj:
            nbr_nodes = int(fileobj.readline().split(" ")[1]) # NODES XXX
            fileobj.readline()  # label x y
            for i in range(nbr_nodes):
                label, _, _ = fileobj.readline().split(" ")  # Node line
                router = self.addRouter(label)
                access_routers[router] = (0, float("inf"))
                node_index.append(router)

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
                access_src = node_index[edge.src]
                access_dst = node_index[edge.dest]

                access_routers[access_src] = (access_routers[access_src][0] + 1,
                                              min(access_routers[access_src][1], edge.bw_src))
                access_routers[access_dst] = (access_routers[access_dst][0] + 1,
                                              min(access_routers[access_dst][1], edge.bw_dst))
                edge.add_to_topo(self, node_index)

        # We consider that access routers have maximum two links
        access_routers = [(x, bw) for x, (e, bw) in access_routers.iteritems() if e <= 2]
        for access_router, bw in access_routers:
            h = self.addHost("h%s" % access_router)
            s = self.addSwitch("s%s" % access_router)
            self.addLink(h, s)
            self.addLink(s, access_router,
                         params1={"bw": bw,  # Minimum bandwidth of all outgoing links of the access router
                                  "delay": "1ms"},
                         params2={"bw": bw,
                                  "delay": "1ms"})

        # Add controller
        routers = self.routers()
        controller = self.addRouter("controller")
        self.addLink(routers[0], controller)

        # Configure SRN with rerouting
        self.addOverlay(SRReroutedCtrlDomain(access_routers=[router for router, _ in access_routers],
                                             sr_controller=controller, schema_tables=self.schema_tables,
                                             rerouting_routers=routers))

        super(RepetitaTopo, self).build(*args, **kwargs)

    def __str__(self):
        return "RepetitaNetwork %s" % os.path.basename(self.repetita_graph)
