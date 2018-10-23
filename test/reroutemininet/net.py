from srnmininet.srnnet import SRNNet


class ReroutingNet(SRNNet):

    def ovsdb_node_entry(self, r, ospfv3_id, prefix):
        table, entry = super(ReroutingNet, self).ovsdb_node_entry(r, ospfv3_id, prefix)

        # If this is an access router, the controller has to know
        entry["accessRouter"] = 1 if r.access_router else 0

        return table, entry
