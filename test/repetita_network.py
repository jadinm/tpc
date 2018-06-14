
from ipmininet.iptopo import IPTopo
from ipmininet.iptopo import Overlay
from networkx import topological_sort, DiGraph
from sr6mininet.sr6router import SR6Config

from config import SRRerouted, IPerf


class RepetitaEdge:

    def __init__(self, label, src, dest, weight, bw, delay):
        self.label = label
        self.src = int(src)
        self.dest = int(dest)

        self.weight_src = int(weight)
        self.bw_src = int(bw)/10**6  # MB
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
                            params1={"bw": self.bw_src, "delay": self.delay_src, "igp_weight": self.weight_src},
                            params2={"bw": self.bw_dst, "delay": self.delay_dst, "igp_weight": self.weight_dst})

    def __str__(self):
        return "<Edge %s (%s to %s) params_src (%s %s %s) params_dest (%s %s %s)>" %\
               (self.label, self.src, self.dest,
                self.weight_src, self.bw_src, self.delay_src,
                self.weight_dst, self.bw_dst, self.delay_dst)


class IPerfOverlay(Overlay):

    def __init__(self, client, server, server_port):  # TODO Add marker for access router

        super(IPerfOverlay, self).__init__(nodes=[client, server])
        self.client = client
        self.server = server
        self.server_port = server_port

    # TODO This is not working !!!!!
    def append_to_daemon_list(self, topo, host, params):
        attrs = topo.nodeInfo(host)
        config = attrs.get("config", None)
        if not config:
            config = (SR6Config, {})
        if 'additional_daemons' not in config[1]:
            config[1]['additional_daemons'] = []
        daemon_list = config[1]['additional_daemons']

        daemon_list.append(params)
        self.set_node_property(host, "config", config)

    def apply(self, topo):
        self.append_to_daemon_list(topo, self.client, (IPerf, {"server_port": self.server_port, "server": self.server}))
        self.append_to_daemon_list(topo, self.server, (IPerf, {"server_port": self.server_port, "server": None}))
        super(IPerfOverlay, self).apply(topo)


class RepetitaNet(IPTopo):

    def __init__(self, *args, **kwargs):
        self.icmp_rerouting = True
        self.routers_order = None
        super(RepetitaNet, self).__init__(*args, **kwargs)

    def build(self, repetita_graph, icmp_rerouting=True, *args, **kwargs):
        """
        The network is generated from the graphs in the file at path 'repetita_graph'
        The input format is described at https://github.com/svissicchio/Repetita/wiki/Adding-Problem-Instances#topology-format
        """
        self.icmp_rerouting = icmp_rerouting
        node_index = []
        edge_dict = {}
        with open(repetita_graph) as fileobj:
            nbr_nodes = int(fileobj.readline().split(" ")[1]) # NODES XXX
            fileobj.readline()  # label x y
            for i in range(nbr_nodes):
                label, _, _ = fileobj.readline().split(" ")  # Node line
                node_index.append(self.addRouter(label))

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

        # TODO Pair nodes linked to the next one
        dependency_graph = DiGraph()
        start_port = 5000
        for i in range(0, nbr_nodes, 2):
            dependency_graph.add_node(node_index[i])
            dependency_graph.add_node(node_index[i+1])
            if i + 1 < nbr_nodes:
                self.addOverlay(IPerfOverlay(client=node_index[i], server=node_index[i+1], server_port=start_port+i))
                dependency_graph.add_edge(node_index[i+1], node_index[i])  # Server must be started before client

        self.routers_order = list(topological_sort(dependency_graph))

        super(RepetitaNet, self).build(*args, **kwargs)

    def addRouter(self, name, config=None, **kwargs):
        if not config:
            config = (SR6Config, {})
        if 'additional_daemons' not in config[1]:
            config[1]['additional_daemons'] = []
        daemon_list = config[1]['additional_daemons']
        if self.icmp_rerouting:
            daemon_list.append(SRRerouted)

        return super(RepetitaNet, self).addRouter(name, config=config, **kwargs)
