
from ipmininet.iptopo import IPTopo
from sr6mininet.sr6router import SR6Config

from config import SRRerouted


class SimpleNet(IPTopo):

    def build(self, *args, **kwargs):
        """
        +--------+      +----+      +----+      +----+
        | client +------+ R1 +------+ R2 +------+ R3 |
        +--------+      +--+-+      +----+      +--+-+
                           |                       |
                           |                       |
                        +--+-+                  +--+-+      +--------+
                        | R4 +------------------+ R5 +------+ server +
                        +----+                  +----+      +--------+

        This network runs SR-Retouted daemons to redirect traffic in case of congestion
        """
        client = self.addHost('client')
        server = self.addHost('server')

        r1 = self.addRouter('r1')
        r2 = self.addRouter('r2')
        r3 = self.addRouter('r3')
        r4 = self.addRouter('r4')
        r5 = self.addRouter('r5')

        self.addLink(client, r1)
        self.addLink(r1, r2)
        self.addLink(r1, r4)
        self.addLink(r2, r3)
        self.addLink(r3, r5)
        self.addLink(r5, server)

        super(SimpleNet, self).build(*args, **kwargs)

    def addRouter(self, name, config=None, **kwargs):
        if not config:
            config = (SR6Config, {})
        if 'additional_daemons' not in config[1]:
            config[1]['additional_daemons'] = []
        daemon_list = config[1]['additional_daemons']
        daemon_list.append(SRRerouted)

        return super(SimpleNet, self).addRouter(name, config=config, **kwargs)
