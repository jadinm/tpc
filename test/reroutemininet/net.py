from mininet.log import lg

from srnmininet.srnnet import SRNNet

from host import ReroutingHost
from router import ReroutingRouter, ReroutingConfig


class ReroutingNet(SRNNet):

    def __init__(self, config=ReroutingConfig, router=ReroutingRouter,
                 host=ReroutingHost, *args, **kwargs):
        super(ReroutingNet, self).__init__(config=config, router=router,
                                           host=host, *args, **kwargs)

    def ovsdb_node_entry(self, r, ospfv3_id, prefix):
        table, entry = super(ReroutingNet, self).ovsdb_node_entry(r, ospfv3_id, prefix)

        # If this is an access router, the controller has to know
        entry["accessRouter"] = 1 if r.access_router else 0

        return table, entry

    def start(self):
        super(ReroutingNet, self).start()
        lg.info('*** Starting', len(self.hosts), 'hosts\n')
        for host in self.hosts:
            lg.info(host.name + ' ')
            host.start()
        lg.info('\n')
