
from srnmininet.srnrouter import SRNConfig
from srnmininet.config.config import SRCtrlDomain

from config import SRRerouted


class SRReroutedCtrlDomain(SRCtrlDomain):

    def __init__(self, access_routers, sr_controller, schema_tables, rerouting_routers, rerouted_opts=None):
        super(SRReroutedCtrlDomain, self).__init__(access_routers, sr_controller, schema_tables)

        self.nodes.extend(rerouting_routers)
        for n in rerouting_routers:
            self.set_node_property(n, "sr_controller", sr_controller)

        self.rerouting_routers = list(rerouting_routers)
        for node in access_routers:
            if node not in self.rerouting_routers:
                self.rerouting_routers.append(node)

        self.sr_controller = sr_controller
        self.rerouted_opts = rerouted_opts if rerouted_opts is not None else {}

    def apply(self, topo):
        """Apply the Overlay properties to the given topology"""
        super(SRReroutedCtrlDomain, self).apply(topo)

        for n in self.rerouting_routers:
            config = topo.nodeInfo(n).get("reroutemininet", None)
            if not config:
                config = (SRNConfig, {})
            if 'additional_daemons' not in config[1]:
                config[1]['additional_daemons'] = []
            if 'rerouting_enabled' not in self.rerouted_opts:
                self.rerouted_opts['rerouting_enabled'] = getattr(topo, 'rerouting_enabled', True)
            config[1]['additional_daemons'].append((SRRerouted, self.rerouted_opts))
            topo.nodeInfo(n)["config"] = config
