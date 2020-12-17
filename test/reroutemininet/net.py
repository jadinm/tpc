from ipmininet.utils import realIntfList
from srnmininet.srnnet import SRNNet

from .host import ReroutingHost
from .link import RerouteIntf
from .router import ReroutingRouter, ReroutingConfig


class ReroutingNet(SRNNet):

    def __init__(self, config=ReroutingConfig, intf=RerouteIntf, router=ReroutingRouter,
                 host=ReroutingHost, *args, **kwargs):
        super().__init__(config=config, router=router, intf=intf,
                                           host=host, *args, **kwargs)

    def ovsdb_node_entry(self, r, ospfv3_id, prefix):
        table, entry = super().ovsdb_node_entry(r, ospfv3_id, prefix)

        # If this is an access router, the controller has to know
        entry["accessRouter"] = 1 if r.access_router else 0

        return table, entry

    def start(self):
        super().start()

        # TODO Reduce MSS for eBPF SRv6 tests, fix in the future !
        for h in self.hosts:
            if 'defaultRoute' in h.params:
                continue  # Skipping hosts with explicit default route
            default = False
            # The first router we find will become the default gateway
            for itf in realIntfList(h):
                for r in itf.broadcast_domain.routers:
                    if (self.use_v6 and h.use_v6 and len(r.addresses[6]) > 0 and
                            len(r.ra_prefixes)) == 0:
                        # We define a default route only if router xi
                        # advertisement are not activated. If we call the same
                        # function, the route created above might be deleted
                        h.cmd('ip route del default dev %s via %s' % (
                            h.defaultIntf(), r.ip6))
                        h.cmd('ip route add default dev %s via %s advmss %s' % (
                            h.defaultIntf(), r.ip6, 1280))
                        default = True
                    break
                if default:
                    break
