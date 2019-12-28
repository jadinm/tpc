from mininet.log import lg
from sr6mininet.sr6link import SR6TCIntf


class RerouteIntf(SR6TCIntf):

    def bwCmds(self, bw=None, speedup=0, use_hfsc=False, use_tbf=False,
               latency_ms=None, enable_ecn=False, enable_red=False,
               red_limit=1000000, red_avpkt=1500, red_probability=1,
               red_min=30000, red_max=35000, red_burst=20):
        "Return tc commands to set bandwidth"

        cmds, parent = [], ' root '

        if bw and bw <= 0:
            lg.error('Bandwidth limit', bw, 'is outside supported range ]0,inf[ - ignoring\n')
        elif bw is not None:
            # BL: this seems a bit brittle...
            if speedup > 0 and self.node.name[0:1] == 's':
                bw = speedup

            cmds += ['%s qdisc add dev %s {parent} handle 5:0 htb default 1'.format(parent=parent),
                     '%s class add dev %s parent 5:0 classid 5:1 htb ' +
                     'rate %dMbit burst 15k' % (int(bw))]
            parent = ' parent 5:1 '

            # FQCodel # TODO Parametrize
            if enable_ecn:
                cmds += ['%s qdisc add dev %s {parent} handle 4: fq_codel '
                         # 'interval 10ms target 5ms '  # limit 1000
                         'ecn'.format(parent=parent)]
                parent = ' parent 4: '

        return cmds, parent
