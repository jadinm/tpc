from scapy.all import *


class SRICMPIPerror6(IPerror6):
    """
    This new class purpose is to implement an IPerror6 packet without counting on an underlayer.
    It can thus be used in a PacketField.
    """

    def answers(self, other):
        if not isinstance(other, IPv6):
            return False
        sd = inet_pton(socket.AF_INET6, self.dst)
        ss = inet_pton(socket.AF_INET6, self.src)
        od = inet_pton(socket.AF_INET6, other.dst)
        os = inet_pton(socket.AF_INET6, other.src)

        # find upper layer for self (possible citation)
        selfup = self.payload
        while selfup is not None and isinstance(selfup, _IPv6ExtHdr):
            selfup = selfup.payload

        # find upper layer for other (initial packet). Also look for RH
        otherup = other.payload
        request_has_rh = False
        while otherup is not None and isinstance(otherup, _IPv6ExtHdr):
            if isinstance(otherup, IPv6ExtHdrRouting):
                request_has_rh = True
            otherup = otherup.payload

        if ((ss == os and sd == od) or  # <- Basic case
                (ss == os and request_has_rh)):  # <- Request has a RH :
            #    don't check dst address

            # Let's deal with possible MSS Clamping
            if (isinstance(selfup, TCP) and
                    isinstance(otherup, TCP) and
                    selfup.options != otherup.options):  # seems clamped

                # Save fields modified by MSS clamping
                old_otherup_opts = otherup.options
                old_otherup_cksum = otherup.chksum
                old_otherup_dataofs = otherup.dataofs
                old_selfup_opts = selfup.options
                old_selfup_cksum = selfup.chksum
                old_selfup_dataofs = selfup.dataofs

                # Nullify them
                otherup.options = []
                otherup.chksum = 0
                otherup.dataofs = 0
                selfup.options = []
                selfup.chksum = 0
                selfup.dataofs = 0

                # Test it and save result
                s1 = str(selfup)
                s2 = str(otherup)
                l = min(len(s1), len(s2))
                res = s1[:l] == s2[:l]

                # recall saved values
                otherup.options = old_otherup_opts
                otherup.chksum = old_otherup_cksum
                otherup.dataofs = old_otherup_dataofs
                selfup.options = old_selfup_opts
                selfup.chksum = old_selfup_cksum
                selfup.dataofs = old_selfup_dataofs

                return res

            s1 = str(selfup)
            s2 = str(otherup)
            l = min(len(s1), len(s2))
            return s1[:l] == s2[:l]

        return False


class SRICMPv6(ICMPv6Unknown):
    TYPE = 5
    TYPE_STR = "Redirection with SRH"
    CODE = 0
    CONNECTION_INFO_LEN = 48

    name = "IPv6 Segment Routing ICMP"

    fields_desc = [ByteEnumField("type", TYPE, {TYPE: TYPE_STR}),
                   ByteField("code", CODE),
                   XShortField("cksum", None),
                   ShortField("srhidx", None),
                   XShortField("reserved", 0),
                   PacketLenField("trigger", SRICMPIPerror6() / TCPerror(), SRICMPIPerror6,
                                  length_from=lambda pkt: pkt.srhidx)]

    def post_build(self, p, pay):
        if self.srhidx is None:
            l = len(p) - 8
            p = p[:4] + struct.pack("!H", l) + p[6:]

        # Checksum computation
        p = super(SRICMPv6, self).post_build(p, pay)
        return p

    def guess_payload_class(self, p):
        return IPv6ExtHdrSegmentRouting

    def is_valid_checksum(self):
        """Checks the Checksum computation for built packets"""
        return in6_chksum(58, self.underlayer, str(self)) == 0


# Binding IPv6 and SRICMPv6
scapy.layers.inet6.icmp6typescls[SRICMPv6.TYPE] = SRICMPv6
scapy.layers.inet6.icmp6typesminhdrlen[SRICMPv6.TYPE] = 8 + 48 + 8  # ICMP Header + Trigger packet + SRH
scapy.layers.inet6.icmp6types[SRICMPv6.TYPE] = SRICMPv6.TYPE_STR
