import os
import string
import subprocess
import time
from shlex import split
from typing import Union, Optional, Tuple, List

from ipmininet.cli import IPCLI
from ipmininet.router import IPNode
from pyroute2 import IPRoute
from srnmininet.srntopo import SRNTopo

from eval.utils import MEASUREMENT_TIME
from reroutemininet.config import Lighttpd
from reroutemininet.host import ReroutingHostConfig
from reroutemininet.link import RerouteIntf
from reroutemininet.net import ReroutingNet
from reroutemininet.topo import SRReroutedCtrlDomain

MAX_QUEUE = 1000000000


class RepetitaEdge:

    def __init__(self, label, src, dest, weight, bw, delay):
        self.label = label
        self.src = int(src)
        self.dest = int(dest)

        self.weight_src = int(weight)
        self.bw_src = int(int(bw) / 10 ** 3)  # Mbps
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
                                     "igp_metric": self.weight_src},
                            params2={"bw": bw_dst,
                                     "delay": str(self.delay_dst) + "ms",
                                     "igp_metric": self.weight_dst})

    def __str__(self):
        return "<Edge %s (%s to %s) params_src (%s %s %s) params_dest (%s %s %s)>" % \
               (self.label, self.src, self.dest,
                self.weight_src, self.bw_src, self.delay_src,
                self.weight_dst, self.bw_dst, self.delay_dst)


class LinkChange:

    def __init__(self, topo: 'RepetitaTopo', time: Union[int, str], src: str, switch: str, dest: str,
                 weight: int, bw: float, delay: int, ddos: Optional[str] = None):
        self.time = int(time)
        self.src = src
        self.switch = switch
        self.dest = dest
        self.weight = int(weight)
        self.bw = int(int(bw) / 10 ** 3)  # Mbps
        self.delay = int(delay)
        self.applied_cmd = ""
        self.applied_time = -1  # The time right before applying the TC
        self.ddos = ddos and bool(int(ddos))
        self.pid_to_clean: List[subprocess.Popen] = []
        self.file = open(f"test_{self.src}.json", "w")  # TODO remove

        if self.ddos:
            if "h" + self.dest not in topo.hosts():
                topo.addHost("h" + self.dest)
                topo.addLink("h" + self.dest, self.dest)
            if "h" + self.src not in topo.hosts():
                topo.addHost("h" + self.src)
                topo.addLink("h" + self.src, self.src)

    def link_params(self, net: ReroutingNet) -> Tuple[IPNode, RerouteIntf, RerouteIntf]:
        switch = net[self.switch]
        dest = net[self.dest]
        link = net.linksBetween(switch, dest)[0]
        if link.intf1.node == switch:
            intf = link.intf1
            dest_itf = link.intf2
        else:
            intf = link.intf2
            dest_itf = link.intf1
        return dest, intf, dest_itf

    def apply(self, net: ReroutingNet):

        if self.ddos:  # Start a iperf3 in UDP to emulate a DDoS on the link
            dest = net["h" + self.dest]
            self.pid_to_clean.append(dest.popen("iperf3 -s --one-off", stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                                universal_newlines=True))
            time.sleep(0.5)
            cmd = f"iperf3 -u -c {dest.intf().ip6} -t {MEASUREMENT_TIME} -b {self.bw}M"
            self.pid_to_clean.append(net["h" + self.src].popen(cmd, stdout=self.file,
                                                               stderr=subprocess.STDOUT, universal_newlines=True))
            self.applied_time = time.monotonic()
            print("UDDDDDDDDDDDDDDDDDDDPPPPPPPPPPPPPPPPPPPPPPPPP")
        else:
            dest, intf, dest_itf = self.link_params(net)
            ipr = IPRoute()
            if self.bw == 0:  # Loss of 100% if no bandwidth can pass => also blocks ICMPs
                dev = ipr.link_lookup(ifname=intf.name)[0]
                ipr.link("set", index=dev, state="down")  # TODO temporary
                # ipr.tc("add", "netem", dev, parent="10:", handle="20:", delay=str(self.delay), loss=100, limit=1)
                self.applied_time = time.monotonic()
                print("KKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKK")
                print(self.applied_time)
                print("KKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKK")
            else:
                # Change netem
                dev = ipr.link_lookup(ifname=intf.name)[0]
                ipr.tc("change", "netem", dev, handle="10:", delay=str(self.delay), loss=0, limit=MAX_QUEUE)  # TODO Too large queue
                ipr.tc("delete", "netem", dev, parent="10:", handle="20:")  # TODO Will fail if no loss before...
                self.applied_time = time.monotonic()

    def revert(self, net: ReroutingNet):
        print("GGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGG")
        dest, intf, dest_itf = self.link_params(net)
        if self.ddos:
            self.clean()
        else:
            ipr = IPRoute()
            dev = ipr.link_lookup(ifname=intf.name)[0]
            if self.bw == 0:
                ipr.link("set", index=dev, state="up")  # TODO temporary
                # TODO print(ipr.tc("delete", "netem", dev, parent="10:", handle="20:"))
            else:
                print(ipr.tc("delete", "netem", dev, handle="10:"))
        print("GGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGG")

    def clean(self):
        self.file.close()  # TODO remove
        for pid in self.pid_to_clean:
            if pid.poll() is None:
                pid.kill()
            print("ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ")
            print(pid.args)
            # print(pid.stdout.readlines())
            # print(pid.stderr.readlines())
            print("ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ")

    def serialize(self):
        return {
            "time": self.time,
            "src": self.src,
            "dest": self.dest,
            "weight": self.weight,
            "bw": self.bw,
            "delay": self.delay,
            "applied_time": self.applied_time
        }

    def __lt__(self, other):
        return (self.time < other.time or
                (self.time == other.time and
                 (self.src < other.src or
                  (self.src == other.src and self.dest < other.dest))))

    def __eq__(self, other):
        return (self.time == other.time and self.src == other.src and
                self.dest == other.dest)

    def __str__(self):
        return "LinkChange<cmd='{}'>".format(self.serialize())


class RepetitaTopo(SRNTopo):

    def __init__(self, repetita_graph=None, schema_tables=None,
                 rerouting_enabled=True, bw=None, ebpf=True, json_demands=(),
                 localctrl_opts=None, enable_ecn=True, *args, **kwargs):
        self.repetita_graph = repetita_graph
        self.schema_tables = schema_tables
        self.rerouting_enabled = rerouting_enabled
        self.bw = bw
        self.switch_count = 1
        self.router_indices = []
        self.ebpf = ebpf
        self.json_demands = json_demands
        self.localctrl_opts = localctrl_opts if localctrl_opts else {}
        self.inter_switches = {}
        self.pending_changes = []
        self.applied_changes = []
        self.enable_ecn = enable_ecn
        super().__init__("controller", *args, **kwargs)

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
            nbr_nodes = int(fileobj.readline().split(" ")[1])  # NODES XXX
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

            try:
                fileobj.readline()  # Empty line
                # CHANGES XXX
                nbr_changes = int(fileobj.readline().split(" ")[1])
                fileobj.readline()  # time src dest weight bw delay
                for i in range(nbr_changes):
                    time, src, dest, weight, bw, delay, *other = \
                        fileobj.readline().split(" ")  # Change line
                    src = int(src)
                    dest = int(dest)
                    intermediate_switch = self.inter_switches[
                        node_index[src]][node_index[dest]]
                    change = LinkChange(self, time, node_index[src],
                                        intermediate_switch,
                                        node_index[dest], weight, bw, delay, *other)
                    self.pending_changes.append(change)
            except IndexError:  # If the end of the file, there isn't any change
                pass
            except IOError:  # If the end of the file, there isn't any change
                pass

        self.pending_changes.sort()

        # We consider that access routers have minimum two links
        print(access_routers)
        for access_router in access_routers:
            h = self.addHost("h%s" % self.label2node(access_router))  # Interface names are at max 15 characters (NULL not included)
            self.addLink(h, access_router)

        # Add controller
        routers = self.routers()
        controller = self.addRouter("controller")
        # Be sure that this is not the bottleneck link (i.e, 100Gbps, 1ms)
        self.addLink(routers[0], controller, delay="1ms", bw=10 ** 5)

        # Configure SRN with rerouting
        if self.ebpf:
            self.addOverlay(SRReroutedCtrlDomain(access_routers=[router for router in access_routers],
                                                 sr_controller=controller, schema_tables=self.schema_tables,
                                                 rerouting_routers=routers,
                                                 hosts=self.hosts(),
                                                 localctrl_opts=self.localctrl_opts))

        super().build(*args, **kwargs)

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
            default_params1 = {"bw": bw, "enable_ecn": self.enable_ecn}
            default_params1.update(opts.get("params1", {}))
            opts1["params1"] = default_params1
            # opts1["params1"]["delay"] = "5ms"
            # opts1["params1"]["max_queue_size"] = MAX_QUEUE

            default_params2 = {"bw": bw, "enable_ecn": self.enable_ecn}
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
        self.inter_switches.setdefault(node1, {})[node2] = s
        self.inter_switches.setdefault(node2, {})[node1] = s
        return super(SRNTopo, self).addLink(node1, s, **opts1), super(SRNTopo, self).addLink(s, node2, **opts2)

    def addHost(self, name, **params):
        if self.cwd is not None and "cwd" not in params:
            params["cwd"] = os.path.join(self.cwd, name)
        h = super().addHost(name, config=ReroutingHostConfig, **params)
        h.addDaemon(Lighttpd, ebpf=self.ebpf)  # Launch an HTTP server on each node
        return h
