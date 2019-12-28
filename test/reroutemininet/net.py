from srnmininet.srnnet import SRNNet

from .host import ReroutingHost
from .link import RerouteIntf
from .router import ReroutingRouter, ReroutingConfig


class ReroutingNet(SRNNet):

    def __init__(self, config=ReroutingConfig, intf=RerouteIntf, router=ReroutingRouter,
                 host=ReroutingHost, *args, **kwargs):
        super(ReroutingNet, self).__init__(config=config, router=router, intf=intf,
                                           host=host, *args, **kwargs)

    def ovsdb_node_entry(self, r, ospfv3_id, prefix):
        table, entry = super(ReroutingNet, self).ovsdb_node_entry(r, ospfv3_id, prefix)

        # If this is an access router, the controller has to know
        entry["accessRouter"] = 1 if r.access_router else 0

        return table, entry
