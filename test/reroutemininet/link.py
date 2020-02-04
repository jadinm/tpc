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
            lg.error('Bandwidth limit', bw,
                     'is outside supported range ]0,inf[ - ignoring\n')
        elif bw is not None:
            # BL: this seems a bit brittle...
            if speedup > 0 and self.node.name[0:1] == 's':
                bw = speedup

            cmds += ['%s qdisc add dev %s {parent} handle 5:0 htb default 1'.format(parent=parent),
                     '%s class add dev %s parent 5:0 classid 5:1 htb ' +
                     'rate %dMbit burst %s' % (int(bw), 394365)]
            parent = ' parent 5:1 '

            # FQCodel # TODO Parametrize
            if enable_ecn:
                cmds += ['%s qdisc add dev %s {parent} handle 4: fq_codel '
                         # 'interval 10ms target 5ms '  # limit 1000
                         'ecn'.format(parent=parent)]
                parent = ' parent 4: '

        if self.params.get("policing", False):
            if self.params.get("policing_delay", None) is None:
                lg.error('Cannot compute burst without delay info\n')
            elif self.params.get("policing_bw", None) is None:
                lg.error('Cannot compute policing without bw info\n')
            else:
                cmds.append("%s qdisc add dev %s handle ffff: ingress")
                delay_pol = int(self.params["policing_delay"].split("ms")[0])\
                            / 1000 * 2 * 1000000
                bw_pol = self.params["policing_bw"]
                bw_pol_bytes = (bw_pol * 10**6) / 8
                # We set the burst to the BDP (Bandwidth Delay Product) in Bytes
                cmd = "%s filter add dev %s parent ffff: u32 match u32 0" \
                      " 0 police rate {bw}mbit burst {mqs} drop"\
                    .format(bw=bw_pol, mqs=394365)
                print(cmd % ("tc", self.name))
                cmds.append(cmd)

        return cmds, parent
